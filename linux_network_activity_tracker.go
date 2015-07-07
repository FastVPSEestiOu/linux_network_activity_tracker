package main

/*

Based on
	https://github.com/FastVPSEestiOu/Antidoto - linux_network_activity_tracker.pl

*/
import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
)

const proc_tcp = "/proc/net/tcp"
const proc_tcp6 = "/proc/net/tcp6"
const proc_udp = "/proc/net/udp"
const proc_udp6 = "/proc/net/udp6"

var out io.Writer = ioutil.Discard

var blacklist_listen_ports map[uint64]BlackListItem
var SocketInodeMap map[uint64]uint64
var work_mux sync.Mutex
var json_output bool

type PidInfo struct {
	Pid     uint64 `json:"pid"`
	Name    string `json:"pid_name"`
	Ctid    uint32 `json:"ctid"`
	Uid     uint64 `json:"uid"`
	Gid     uint64 `json:"gid"`
	CmdLine string `json:"cmd_line"`
}

type InetConnection struct {
	IpLocal    string  `json:"ip_local"`
	IpRemote   string  `json:"ip_remote"`
	PortLocal  uint64  `json:"port_local"`
	PortRemote uint64  `json:"port_remote"`
	Inode      uint64  `json:"inode"`
	Type       string  `json:"type"`
	BadLocal   bool    `json:"bad_local"`
	Reason     string  `json:"reason"`
	Process    PidInfo `json:"process"`
}

type BlackListItem struct {
	// tcp/udp/all
	Type string `json:"type"`
	// local/remote/all
	PortType string `json:"port_type"`
	Reason   string `json:"reason"`
}

var BlacklistedConnections []InetConnection

func init() {
	configPathFlag := flag.String("c", "", "Config file path")
	jsonFlag := flag.Bool("j", false, "Output in json")
	flag.Parse()

	default_blacklist_listen_ports := map[uint64]BlackListItem{
		6666:  {"tcp", "all", "irc"},
		6667:  {"tcp", "all", "irc alternative"},
		9050:  {"tcp", "local", "tor"},
		36008: {"tcp", "remote", "botnet melinda & bill gates"},
		4443:  {"tcp", "local", "/tmp/.estbuild/lib/ld-linux.so.2 rooted"},
	}

	// Not config - load build in config
	if len(*configPathFlag) > 0 {
		var err error
		blacklist_listen_ports, err = LoadConfig(*configPathFlag)
		if err != nil {
			fmt.Println("We cannot open and parse config file! Error - ", err)
			os.Exit(1)
		}
		if len(blacklist_listen_ports) == 0 {
			fmt.Println("Warning - we get zero ports from config file - load default build in rules")
			blacklist_listen_ports = default_blacklist_listen_ports
		}
	} else {
		blacklist_listen_ports = default_blacklist_listen_ports
	}

	json_output = *jsonFlag
	if json_output {
		out = ioutil.Discard
	} else {
		out = os.Stdout
	}

}

func main() {
	/*

		Get all tcp/tcp6/upd/upd6  connections from /proc/net via 4 thread

	*/

	runtime.GOMAXPROCS(4)
	runtime.UnlockOSThread()
	var waitReadNetProc sync.WaitGroup
	waitReadNetProc.Add(4)
	go func() {
		defer waitReadNetProc.Done()
		err := GetAndParseNetFile(proc_tcp, "tcp")
		if err != nil {
			fmt.Fprintln(out, "Cannot read proc net tcp file")
			fmt.Fprintln(out, err)
			os.Exit(1)
		}
	}()
	go func() {
		defer waitReadNetProc.Done()
		err := GetAndParseNetFile(proc_udp, "udp")
		if err != nil {
			fmt.Fprintln(out, "Cannot read proc net tcp file")
			fmt.Fprintln(out, err)
			os.Exit(1)
		}
	}()
	go func() {
		defer waitReadNetProc.Done()
		err := GetAndParseNetFile(proc_tcp6, "tcp6")
		if err != nil {
			fmt.Fprintln(out, "Cannot read proc net tcp file")
			fmt.Fprintln(out, err)
			os.Exit(1)
		}
	}()
	go func() {
		defer waitReadNetProc.Done()
		err := GetAndParseNetFile(proc_udp6, "udp6")
		if err != nil {
			fmt.Fprintln(out, "Cannot read proc net tcp file")
			fmt.Fprintln(out, err)
			os.Exit(1)
		}
	}()
	waitReadNetProc.Wait()

	/*
		End get all connections
	*/

	// Not found suspicious connections - exit
	if len(BlacklistedConnections) == 0 {
		fmt.Fprintln(out, "We not find suspicious connections")
		os.Exit(0)
	}
	fmt.Fprintln(out, "We found ", len(BlacklistedConnections), " suspicious connetions")
	fmt.Fprintln(out, "Found they process, please be patient")

	// Get all pids
	pidList := GetPidList()

	SocketInodeMap = make(map[uint64]uint64)
	forOneThread := len(pidList) / 4
	forOneThread++

	/*
		Build inode -> pid map
	*/

	var waitGetSockMap sync.WaitGroup
	waitGetSockMap.Add(4)
	go func() {
		defer waitGetSockMap.Done()
		for _, pid := range pidList[:forOneThread] {
			GetLinksForPidToMap(pid)
		}
	}()
	go func() {
		defer waitGetSockMap.Done()
		for _, pid := range pidList[forOneThread : forOneThread*2] {
			GetLinksForPidToMap(pid)
		}
	}()
	go func() {
		defer waitGetSockMap.Done()
		for _, pid := range pidList[forOneThread*2 : forOneThread*3] {
			GetLinksForPidToMap(pid)
		}
	}()
	go func() {
		defer waitGetSockMap.Done()
		for _, pid := range pidList[forOneThread*3:] {
			GetLinksForPidToMap(pid)
		}
	}()
	waitGetSockMap.Wait()
	/*
		End build inode->pid map
	*/

	// Get info about pid
	for i := range BlacklistedConnections {
		//fmt.Println(connection)
		if SocketInodeMap[BlacklistedConnections[i].Inode] > 0 {
			BlacklistedConnections[i].Process = GetInfoAboutPid(SocketInodeMap[BlacklistedConnections[i].Inode])
		} else {
			//fmt.Fprintln(out, "Warning - cannot find pid for ", BlacklistedConnections[i])
		}
	}

	if json_output {
		json_data, _ := json.Marshal(BlacklistedConnections)
		fmt.Print(string(json_data))
	} else {
		fmt.Fprintf(out, "\n\n")
		for _, conn := range BlacklistedConnections {
			var output string
			output = output + fmt.Sprintf("Conn: %s:%v - %s:%v\n", conn.IpLocal, conn.PortLocal, conn.IpRemote, conn.PortRemote)
			output = output + fmt.Sprintf("\t\tType: %s\n", conn.Type)
			output = output + fmt.Sprintf("\t\tLocalPortDetect: %t\n", conn.BadLocal)
			output = output + fmt.Sprintf("\t\tReason: \"%s\"\n", conn.Reason)
			output = output + fmt.Sprintf("\t\tCTID: %v  Pid: %v\n", conn.Process.Ctid, conn.Process.Pid)
			output = output + fmt.Sprintf("\t\tProcess Name: %s\n", conn.Process.Name)
			output = output + fmt.Sprintf("\t\tUid: %v  Gid: %v\n", conn.Process.Uid, conn.Process.Gid)
			output = output + fmt.Sprintf("\t\tCmdLine: %s\n\n", conn.Process.CmdLine)
			fmt.Fprintln(out, output)
		}
	}

}

func GetAndParseNetFile(fileName string, Type string) error {
	proc_file_content, err := ioutil.ReadFile(fileName)
	if err != nil {
		fmt.Fprintln(out, err)
		return err
	}
	proc_file_data := strings.Split(string(proc_file_content), "\n")
	regexp_for_split_params := regexp.MustCompile(`\s+`)
	regexp_for_cut_first_spaces := regexp.MustCompile(`^\s+`)
	for _, line := range proc_file_data[1:] {
		splitedLine := regexp_for_split_params.Split(regexp_for_cut_first_spaces.ReplaceAllString(line, ""), -1)
		if len(splitedLine) >= 13 {
			var inetConnect InetConnection
			inetConnect.IpLocal, inetConnect.PortLocal, _ = ParseIpPort(splitedLine[1])
			inetConnect.IpRemote, inetConnect.PortRemote, _ = ParseIpPort(splitedLine[2])
			inetConnect.Inode, _ = strconv.ParseUint(splitedLine[9], 10, 64)
			inetConnect.Type = Type
			if CheckConnetToBlackListed(&inetConnect) {
				work_mux.Lock()
				BlacklistedConnections = append(BlacklistedConnections, inetConnect)
				work_mux.Unlock()
			}
		}
	}
	return err
}

func ParseIpPort(ip_port_raw string) (ip string, port uint64, err error) {
	ip_port_array := strings.Split(ip_port_raw, ":")
	if len(ip_port_array) == 2 {
		ip, _ = HexStringToIp(ip_port_array[0])
		port, _ = strconv.ParseUint(ip_port_array[1], 16, 64)
	} else {
		err = errors.New("Parse error - not p:port format")
	}
	return
}

func HexStringToIpv4(ip_raw string) (ip string, err error) {
	for len(ip_raw) > 1 {
		octet, _ := strconv.ParseInt(ip_raw[0:2], 16, 32)
		ip = fmt.Sprintf("%v.", octet) + ip
		ip_raw = ip_raw[2:]
	}
	ip = ip[0 : len(ip)-1]
	return
}

func HexStringToIp(ip_raw string) (ip string, err error) {
	if len(ip_raw) > 8 {
		if ip_raw[:23] == "0000000000000000FFFF000" {
			// it is ipv4 in fact
			ip, err = HexStringToIpv4(ip_raw[24:])
			ip = "::ffff:" + ip
		} else {
			var byte_befor []uint8
			for len(ip_raw) > 1 {
				ui, _ := strconv.ParseUint(ip_raw[0:2], 16, 8)
				ui8 := uint8(ui)
				byte_befor = append(byte_befor, ui8)
				ip_raw = ip_raw[2:]
			}

			byte_after := []uint8{
				byte_befor[3], byte_befor[2], byte_befor[1], byte_befor[0],
				byte_befor[7], byte_befor[6], byte_befor[5], byte_befor[4],
				byte_befor[11], byte_befor[10], byte_befor[9], byte_befor[8],
				byte_befor[15], byte_befor[14], byte_befor[13], byte_befor[12],
			}
			var ipv6 net.IP
			ipv6 = byte_after
			ip = ipv6.String()
		}
	} else {
		ip, err = HexStringToIpv4(ip_raw)
	}

	return
}

func CheckConnetToBlackListed(inetConnect *InetConnection) (blacklisted bool) {
	blacklisted = false
	var blackListItem BlackListItem

	blackListItem = blacklist_listen_ports[inetConnect.PortLocal]
	if len(blackListItem.Reason) > 0 {
		if blackListItem.Type == inetConnect.Type[0:3] || blackListItem.Type == "all" {
			if blackListItem.PortType == "local" || blackListItem.PortType == "all" {
				inetConnect.BadLocal = true
				inetConnect.Reason = blackListItem.Reason
				blacklisted = true
				return
			}
		}
	}

	blackListItem = blacklist_listen_ports[inetConnect.PortRemote]
	if len(blackListItem.Reason) > 0 {
		if blackListItem.Type == inetConnect.Type[0:3] || blackListItem.Type == "all" {
			if blackListItem.PortType == "remote" || blackListItem.PortType == "all" {
				inetConnect.BadLocal = false
				inetConnect.Reason = blackListItem.Reason
				blacklisted = true
				return
			}
		}
	}

	return
}

func GetPidList() (pidList []uint64) {
	dirHandle, err := os.Open("/proc/")
	if err != nil {
		panic(err)
	}
	fileList, err := dirHandle.Readdir(-1)
	if err != nil {
		panic(err)
	}

	for _, file := range fileList {
		if file.Mode().IsDir() {
			pidNumber, err := strconv.ParseUint(file.Name(), 10, 64)
			if err != nil {
				continue
			}
			pidList = append(pidList, pidNumber)
		}

	}
	return
}

func GetLinksForPidToMap(pid uint64) {
	dirHandle, err := os.Open("/proc/" + fmt.Sprintf("%v", pid) + "/fd/")
	if err != nil {
		return
	}
	fileList, err := dirHandle.Readdir(-1)
	if err != nil {
		return
	}
	socketRegexp := regexp.MustCompile(`^socket\:\[(\d+)\]$`)

	for _, fdFile := range fileList {
		fileName := fmt.Sprintf("/proc/%v/fd/%s", pid, fdFile.Name())
		fileStat, err := os.Lstat(fileName)
		if err != nil {
			continue
		}
		if fileStat.Mode()&os.ModeSymlink != 0 {
			linkName, err := os.Readlink(fileName)
			if err != nil {
				continue
			}
			result := socketRegexp.FindAllStringSubmatch(linkName, -1)
			if result != nil {
				inode, _ := strconv.ParseUint(result[0][1], 10, 64)
				work_mux.Lock()
				SocketInodeMap[inode] = pid
				work_mux.Unlock()
			}
		}
	}
}

func GetInfoAboutPid(pid uint64) (pidInfo PidInfo) {
	statusFile_content, err := ioutil.ReadFile(fmt.Sprintf("/proc/%v/status", pid))
	if err != nil {
		return
	}
	pidInfo.Pid = pid
	statusFile_data := strings.Split(string(statusFile_content), "\n")
	regexpForSplit := regexp.MustCompile(`\s+`)
	regexpForName := regexp.MustCompile(`^Name:`)
	regexpForCtid := regexp.MustCompile(`^envID:`)
	regexpForUid := regexp.MustCompile(`^Uid:`)
	regexpForGid := regexp.MustCompile(`^Gid:`)
	for _, line := range statusFile_data {
		splitedLine := regexpForSplit.Split(line, -1)
		if regexpForName.MatchString(line) && len(splitedLine) == 2 {
			pidInfo.Name = splitedLine[1]
		}

		if regexpForCtid.MatchString(line) && len(splitedLine) == 2 {
			i, _ := strconv.ParseUint(splitedLine[1], 10, 32)
			pidInfo.Ctid = uint32(i)
		}

		if regexpForUid.MatchString(line) && len(splitedLine) > 1 {
			pidInfo.Uid, _ = strconv.ParseUint(splitedLine[1], 10, 64)
		}
		if regexpForGid.MatchString(line) && len(splitedLine) > 1 {
			pidInfo.Gid, _ = strconv.ParseUint(splitedLine[1], 10, 64)
		}

	}
	cmdLine_content, err := ioutil.ReadFile(fmt.Sprintf("/proc/%v/cmdline", pid))
	if err != nil {
		return
	}
	cmdLine_data := string(cmdLine_content)
	regexpTr := regexp.MustCompile(`\000`)
	pidInfo.CmdLine = regexpTr.ReplaceAllString(cmdLine_data, " ")

	return
}

// only add port to BlackListItem type
type ConfigItem struct {
	Port uint64 `json:"port"`
	// tcp/udp/all
	Type string `json:"type"`
	// local/remote/all
	PortType string `json:"port_type"`
	Reason   string `json:"reason"`
}

func LoadConfig(configPath string) (blacklist_listen_ports map[uint64]BlackListItem, err error) {
	blacklist_listen_ports = make(map[uint64]BlackListItem)
	var mapFromConfigFile []ConfigItem

	config_content, err := ioutil.ReadFile(configPath)
	if err != nil {
		return
	}
	err = json.Unmarshal(config_content, &mapFromConfigFile)
	if err != nil {
		return
	}

	checkType := regexp.MustCompile(`^(all|tcp|udp)$`)
	checkPortType := regexp.MustCompile(`^(all|local|remote)$`)
	for _, value := range mapFromConfigFile {
		var item BlackListItem
		item.Reason = value.Reason
		if checkType.MatchString(value.Type) {
			item.Type = value.Type
		} else {
			item.Type = "all"
			fmt.Fprintln(os.Stderr, "Warning! Wrong type \""+value.Type+"\" in config for "+fmt.Sprintf("%v", value.Port)+" port. Set it in \"all\"")
		}
		if checkPortType.MatchString(value.PortType) {
			item.PortType = value.PortType
		} else {
			item.PortType = "all"
			fmt.Fprintln(os.Stderr, "Warning! Wrong port_type \""+value.PortType+"\" in config for "+fmt.Sprintf("%v", value.Port)+" port. Set it in \"all\"")
		}

		blacklist_listen_ports[value.Port] = item
	}

	return
}

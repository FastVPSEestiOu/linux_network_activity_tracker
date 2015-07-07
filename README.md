linux_network_activity_tracker
==============================

**linux_network_activity_tracker** - little software for detecting connections to the suspicious ports (first of all, we support OpenVZ).

It is re-implementattion (by performance reasons) on golang **linux_network_activity_tracker.pl** from [Antidoto](https://github.com/FastVPSEestiOu/Antidoto)

Install
-------
```
git pull https://github.com/FastVPSEestiOu/linux_network_activity_tracker.git
cd linux_network_activity_tracker
export GOPATH=$(pwd)
go build
```

And copy binary file to directory in $PATH if it needed.

Usage
-------
```
linux_network_activity_tracker [-j] [ -c config_file ]
```

Options
-------
- --help

Print usage message (build in from flag library)

- -j

Enable json output

- -c PATH

Path to config file with json content about ports and reasons(see lnat_config.json as example)

Description
-----------

We get connections from /proc/net/ files(tcp,tcp6,udp,udp6).
Buid /proc/?/fd/ map if we have connections with interested ports.
Get info about process, who start this connections.
And output this info to OUTPUT in human readable fromat or in json format.

Config file must be in json, with format

```
[
{"port":$PORT,"type":"$TYPE","port_type":"$PORT_TYPE","reason":"$REASON"},
{"port":$PORT,"type":"$TYPE","port_type":"$PORT_TYPE","reason":"$REASON"},
...
{"port":$PORT,"type":"$TYPE","port_type":"$PORT_TYPE","reason":"$REASON"}
]
```

Where 
- $PORT - detected port

- $TYPE - detect only **tcp**, **udp** or **all** for both(IPv6 included without add 6 to tcp/udp)

- $PORT_TYPE - detect only if port on **local**, **remote** side or **all** for both

- $REASON - little description why we detect this port

If config not set we use built in rules - they in default_blacklist_listen_ports in init().
Built in have same format, except port - it directly use by key for list rules for blacklist.

Contributors
------------
- [Sergei Mamonov](https://github.com/mrqwer88)

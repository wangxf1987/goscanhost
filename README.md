# goscan
 
**Features:**
 * Scan the whole IPv4 address space
 * Scan your local network with ARP packets
 * Display the IP address, MAC address, hostname and vendor associated
 * Using SMB(Windows devices) and mDNS(Apple devices) to detect hostname
 
 
### Usage: ###

```sh
# install dependencies
$ go get github.com/Sirupsen/logrus
$ go get github.com/timest/gomanuf
$ go get github.com/google/gopacket

# build
$ go build

# execute
$ sudo ./main  
# or
$ sudo ./main -I en0
```

Goscan must run as **root**.

Goscan work in Linux/Mac using [libpcap](http://www.tcpdump.org/) and on Windows with [WinPcap](https://www.winpcap.org/install/). 

If you need English comments, check this fork: https://github.com/skoky/goscan/tree/english 


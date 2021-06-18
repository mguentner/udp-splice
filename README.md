# udp-splice

an userspace udp splicer written in Go. Receive packets and forward them to multiple
destinations.

Keywords: UDP, Multiplexer, Multiplicator, Networking

## Why / Problem

In case a UDP client sends to a server (receiver) there are many ways to send the same
data to another / multiple destinations.

* use the broadcast address
* use IPv4 multicast
* `iptables` with `mangle` + `-j tee` and some `nat` rules
* `socat` + `tee`
* if the second receiver is running on the same host, `libpcap` could be used to intercept (not recommended)
* patch the client

## How / Solution

```
[ peer0 (tx/rx) ] <-------> [ udp-splice ] <--------> [ peer1 (tx/rx) ]
                                   |
                                   | \
                                   |  \
                                   V   V
                          [ peer2 rx ] .. [ peerN (rx) ]
```

Here is another one, implemented in userspace with go that does exactly what is described above.
The main advantage is that you don't need to mess with your machines setup (iptables) or touch
the client itself. If your connection between `peerA` and `peerB` already works, you just
need to point `peerA` to the address `udp-splice` is listening on which inturn then
forwards the traffic to `peerB`. `peer1` can also send traffic back to `udp-slice` which
will forward it to `peer0` - this is basically NAT.
If configured, the traffic will also be forwarded to `peer2` through `peerN`. This connection
however is transmit-only from the perspective of `udp-splice`.
Obviously the major downside of this setup is that `udp-splice` presents a single point of failure
for the connection.

## What / Usage

Start `udp-splice`:
```
./udp-splice --listen localhost:10000 --destination localhost:10001,localhost:10002
```

Start `peer1`
```
socat - UDP4-RECVFROM:10001,fork
```

Start `peer2`
```
socat - UDP4-RECVFROM:10002,fork
```

Send some traffic to `udp-splice`
```
echo  "udp-splice" | socat - UDP4-SENDTO:localhost:10000
```

## Toggle forwarding

To further optimize resources it is possible to disable forwarding to `peer2` through `peerN` if
this is not needed.

Simply send `SIGUSR1` to the running instance using `kill -SIGUSR1 $PID_OF_UDP_SPLICE`.
To re-enable it, repeat the same command.

## Copyright & License

MIT (see LICENSE)

2021 Maximilian Güntner <code@mguentner.de>

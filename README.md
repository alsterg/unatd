unatd
=======

REQUIREMENTS: libev, kernel tproxy

This program can serve two purposes:
  1. A fast general purpose transparent proxy.
  2. A lightweight user-space SNAT daemon.

In either case, you have to configure your box to intercept the
desired traffic and redirect it to your local proxy. 
Assuming you want to proxy (or snat) the 80 port, and your proxy is
listening on port 2002, execute:

    # sysctl net.ipv4.ip_forward=0
    # iptables -t mangle -A PREROUTING -p tcp --dport 80 -j TPROXY --tproxy-mark 0x1/0x1 --on-port 2002
    # iptables -t mangle -N DIVERT
    # iptables -t mangle -A PREROUTING -p tcp -m socket -j DIVERT
    # iptables -t mangle -A DIVERT -j MARK --set-mark 1
    # iptables -t mangle -A DIVERT -j ACCEPT
    # ip rule add fwmark 1 lookup 100
    # ip route add local 0.0.0.0/0 dev lo table 100
    # ulimit -n 999999

Now invoke the unatd. 

For case 1:

    # unatd -p 2002

where 2002 is the local port to bind to.

For case 2:

    # unatd -p 2002 -o eth0

where eth0 is the interface from which the SNATed traffic will leave,
using the primary IP address of the interface for IP tranlation.

If you want to allow non-http traffic to pass through, then you have
to enable forwarding, and populate the routing table accordingly.

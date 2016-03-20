weewx-interceptor

This is a driver for weewx that intercepts and parses network traffic.  It can
be used with a variety of "internet bridge" devices such as the Acurite
Internet Bridge, the Oregon Scientific WS301/302, or the Fine Offset
ObserverIP.

How it works

The driver runs a web server on a separate thread.  Data posted to that server
are parsed then processed as sensor inputs.

There are a few options for getting the data from the network to the driver.

1) Hijack DNS

Change the DNS entry so that the internet bridge device sends directly to the
driver.  If you control DNS on the network, you can make the internet bridge
send to a different destination by creating a DNS entry for the host to which
the internet bridge tries to send its data.

Some router software such as OpenWrt or pfSense include a graphic interface
for adding DNS entries.

Here is a sample configuration for doing it using bind9 for the acurite
internet bridge:

In the file /etc/bind/named.conf.local:
```
zone "www.acu-link.com" {
    type master;
    file "/etc/bind/acu-link.com";
};
```

In the file /etc/bind/acu-link.com:
```
$TTL    604800
@       IN      SOA     dns.www.acu-link.com. root.www.acu-link.com. (
2016032001 ; Serial
    604800 ; Refresh
     86400 ; Retry
   2419200 ; Expire
    604800 ) ; Negative Cache TTL
;
@       IN      NS      dns.www.acu-link.com.
@       IN      A       Y.Y.Y.Y
*       IN      A       Y.Y.Y.Y
*       IN      AAAA    ::1
```

```Y.Y.Y.Y``` is the address of the machine on which weewx is running the
driver.

This will redirect any requests to www.acu-link.com, but it will not redirect
any requests to acu-link.com.

2) Man-in-the-middle

Use a proxy to capture HTTP traffic and redirect it to the driver.

TODO: apache configuration

3) Network tap configurations

There are many ways to intercept network traffic from the internet bridge.  In
each case, traffic is intercepted then sent to the driver.  The traffic may
also be sent to its original destination.

There are many ways to intercept and redirect network traffic.  Here are two
examples:

```
#!/bin/sh
tcpdump -i eth0 src X.X.X.X and port 80 | nc Y.Y.Y.Y PPPP
```

```
#!/bin/sh
ngrep -l -q -d eth0 'ether src host X.X.X.X && dst port 80'
```

```X.X.X.X``` is the address of the internet bridge
```Y.Y.Y.Y``` is the address of the computer on which weewx is running
```PPPP``` is the port on which the driver is listening

Here are four different configurations that use this strategy.

a) Tap-on-Router

Capture traffic on the network's edge router.  Run a script on the router that
captures traffic from the internet bridge and sends it to the driver.

b) Tap-on-Bridge

Configure a computer with two network interfaces to bridge between the
internet bridge and the regular network.  The bridge captures traffic and
sends it to the driver, and optionally sends it along to its original
destination.

c) Tap-on-Hub

Configure a device connected to the same hub as the internet bridge.  Since
any device on a hub can see the network traffic from any other device on the
hub, simply intercept any traffic from the internet bridge then send it to
the driver.

d) Tap-on-Switch

Configure a device on a managed switch.  Unmanaged switches will not work.
Configure the switch to mirror the traffic from one port to a second port.
Configure a device on the second port to capture traffic from the internet
bridge then send it to the driver.

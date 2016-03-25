weewx-interceptor

This is a driver for weewx that intercepts and parses network traffic.  It can
be used with a variety of "internet bridge" devices such as the Acurite
Internet Bridge, the Oregon Scientific WS301/302, or the Fine Offset
ObserverIP.


Installation

0) install weewx (see the weewx user guide)

1) download the driver

wget -O weewx-interceptor.zip https://github.com/matthewwall/weewx-interceptor/archive/master.zip

2) install the driver

wee_extension --install weewx-interceptor.zip

3) configure the driver

wee_config --reconfigure

4) start weewx

sudo /etc/init.d/weewx start

5) direct network traffic from the bridge or weather station to weewx


How it works

The driver runs a web server on its own thread.  Data posted to that server
are parsed then processed as sensor inputs.

There are a few options for getting the data from the network to the driver,
including the following:

  1) Hijack DNS
     internet_bridge -> driver ( -> web_service )

  2) Man-in-the-middle with HTTP proxy
     internet_bridge -> proxy -> driver ( -> web_service )

  3) Network tap
     internet_bridge -> web_service

  4) DNS hijack plus HTTP redirect
     internet_bridge -> web_server --> driver
                                   \-> web_service

Which one you choose depends on your network configuration, network hardware,
and your ability to add and configure devices on the network.


1) Hijack DNS

Change the DNS entry so that the internet bridge device sends directly to the
driver.  If you control DNS on the network, you can make the internet bridge
send to a the driver by creating a DNS entry for the host to which the
internet bridge tries to send its data.

Some router software such as OpenWrt or pfSense include a graphic interface
for adding DNS entries.  If you use either of these, simply create a DNS entry
for the name to which the bridge normally sends (e.g., www.acu-link.com) and
enter the address for the host on which the driver is running.

If you run your own nameserver, add an entry to your DNS configuration.  Here
is a sample configuration for bind9 to hijack traffic from the acurite
internet bridge:

In the file /etc/bind/named.conf.local:

zone "www.acu-link.com" {
    type master;
    file "/etc/bind/acu-link.com";
};

In the file /etc/bind/acu-link.com:

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


Y.Y.Y.Y is the address of the machine on which weewx is running the
driver.

This will redirect any requests to www.acu-link.com, but it will not redirect
any requests to acu-link.com.

2) Man-in-the-middle

Use a proxy to capture HTTP traffic and redirect it to the driver.

Here is an example of an Apache 'reverse proxy' configuration for the Acurite
internet bridge.  The Apache server sends any requests from the internet bridge
to the driver, and relays any responses from the driver back to the internet
bridge.  It applies only to traffic destined for www.acu-link.com.

In the file /etc/apache2/conf.d/aculink.conf:

RewriteEngine on
RewriteCond %{HTTP_POST} www.acu-link.com
RewriteRule ^/messages(.*)$ http://Y.Y.Y.Y/messages$1


3) Network tap configurations

There are many ways to capture traffic using a 'tap'.  In each case, traffic is
intercepted then sent to the driver.  The capture and the driver might run on
the same device, or they can run on separate devices.  The traffic may also be
sent to its original destination.

Here are three examples of direct capture.  Some use tcpdump to capture, others
use ngrep to capture.  The tool 'nc' is used to direct captured traffic to the
host on which the driver is running.


#!/bin/sh
tcpdump -i eth0 src X.X.X.X and port 80 | nc Y.Y.Y.Y PPPP


#!/bin/sh
tcpdump -i eth0 dst www.acu-link.com and port 80 | nc Y.Y.Y.Y PPPP


#!/bin/sh
ngrep -l -q -d eth0 'ether src host X.X.X.X && dst port 80' | nc Y.Y.Y.Y PPPP


X.X.X.X is the address of the internet bridge
Y.Y.Y.Y is the address of the computer on which weewx is running
PPPP is the port on which the driver is listening

Here are four different configurations that use this strategy.

a) Tap-in-Router

Capture traffic on the network's edge router.  Run a script on the router that
captures traffic from the internet bridge and sends it to the driver.

b) Tap-as-Bridge

Configure a computer with two network interfaces to bridge between the
internet bridge and the regular network.  Plug the internet bridge into one
port, and plug the other port into the local network.  The bridge captures
traffic and sends it to the driver, and optionally sends it along to its
original destination.

c) Tap-on-Hub

Configure a device connected to the same hub as the internet bridge.  Since
any device on a hub can see the network traffic from any other device on the
hub, simply intercept any traffic from the internet bridge then send it to
the driver.

d) Tap-on-Switch

Configure a device that is connected to a managed switch.  Unmanaged switches
will not work.  Configure the switch to mirror the traffic from one port to a
second port.  Configure a device on the second port to capture traffic from
the internet bridge then send it to the driver.


4) DNS hijack plus HTTP redirect

First hijack the DNS so that traffic goes to a local web server.  Then
configure the web server so that it relays the requests to the driver and
optionally to the web service.

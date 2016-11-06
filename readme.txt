weewx-interceptor

This is a driver for weewx that receives and parses network traffic.  It can
be used with a variety of "internet bridge" devices such as the Acurite
Internet Bridge, the Oregon Scientific LW301/302, the Fine Offset
HP1000/WH2600, or the LaCrosse GW1000U.

Warning!  This driver is experimental.  It is fully tested with the Acurite
bridge, mostly functional with the Fine Offset HP1000 and WH2600, mostly
functional with the Oregon Scientific LW stations, and mostly functional with
the GW1000U.  Feedback from anyone with the untested hardware would be greatly
appreciated.  My intent is to push these components into weewx once all of the
different configurations are working properly.


===============================================================================
Prerequisites

The 'listen' mode (default) has no pre-requisites.

The 'sniff' mode requires installation of the python pcap module:

  sudo pip install pypcap

  OR

  sudo apt-get install libpcap python-libpcap


===============================================================================
Installation

0) install weewx, select 'Simulator' driver (see the weewx user guide)

dpkg -i weewx_x.y.z-r.deb

1) download the driver

wget -O weewx-interceptor.zip https://github.com/matthewwall/weewx-interceptor/archive/master.zip

2) install the driver

wee_extension --install weewx-interceptor.zip

3) configure the driver

wee_config --reconfigure

4) start weewx

sudo /etc/init.d/weewx start

5) direct network traffic from the bridge or weather station to weewx


===============================================================================
Driver options

To configure the driver beyond the default values, set parameters in the
[Interceptor] section of the weewx configuration file.

For example, to listen on port 80 instead of the default port 9999,

[Interceptor]
    driver = user.interceptor
    device_type = observer
    port = 80

To listen on port 8080 on the network interface with address 192.168.0.14:

[Interceptor]
    driver = user.interceptor
    device_type = lw30x
    port = 8080
    address = 192.168.0.14

To sniff packets from 192.168.0.14 on network interface eth1:

[Interceptor]
    driver = user.interceptor
    device_type = acurite-bridge
    mode = sniff
    iface = eth1
    filter = src 192.168.0.14 and dst port 80


===============================================================================
How it works

There are two modes of operation: listen and sniff.

In listen mode, the driver runs a socket server on a dedicated thread.  Data
posted to that server are parsed then processed as sensor inputs.

In sniff mode, the driver runs a packet sniffer on a dedicated thread.  Data
captured by sniffing are parsed then processed as sensor inputs.

There are many options for getting data to the driver.  Here are some examples,
from simplest to most complicated.

Example 1: weewx is running on host 'pi' and nothing is listening on port 80.
Configure the driver to listen on port 80 and configure the internet bridge to
send to the host 'pi' instead of the cloud.

Example 2: weewx is running on host 'pi' with two bridged network interfaces,
eth0 and eth1.  Plug the internet bridge into one interface and the network
into the other interface.  Configure the driver to sniff traffic from the
internet bridge.

Example 3: weewx is running on host 'pi', nothing is listening on port 80, and
the internet bridge cannot be configured.  Configure the driver to listen on
port 80.  Add a DNS entry so that traffic from the internet bridge is sent to
'pi' instead of the cloud.

Example 4: weewx is running on host 'pi', nothing is listening on port 80, and
the internet bridge cannot be configured.  Configure the driver to listen on
port 80.  Configure the router to redirect traffic from the internet bridge
and send it to 'pi' instead of the cloud.

Example 5: weewx is running on host 'pi', which has a web server on port 80
to display weewx reports.  Configure the driver to listen on port 9999.  Add a
reverse proxy to the web server configuration to direct traffic on port 80 from
the device to port 9999.  Add a DNS entry so that traffic from the device is
sent to 'pi' instead of the cloud.

These are strategies for getting data to the driver when the simple approach
(direct from device to driver) is not possible:

  1) Hijack DNS
     use a local DNS entry to make the internet bridge send directly to weewx
     internet_bridge ---> driver ( ---> web_service )

  2) HTTP proxy/redirect
     configure the internet bridge to send to an HTTP proxy that you control
     internet_bridge ---> proxy ---> driver ( ---> web_service )

  3) Packet capture
     listen to traffic on the network and capture anything from the bridge
     internet_bridge ---> tap ( ---> web_service )
                           \-> driver ( ---> web_service )

Which one you choose depends on your network configuration, network hardware,
and your ability to add and configure devices on the network.

In the examples that follow,
  X.X.X.X is the address of the internet bridge
  Y.Y.Y.Y is the address of the computer on which weewx is running
  PPPP is the port on which the driver is listening


===============================================================================
1) Hijack DNS

Change the DNS entry so that the internet bridge device sends directly to the
driver.  If you control DNS on the network, you can make the internet bridge
send to the driver by creating a DNS entry for the host to which the internet
bridge tries to send its data.

1a) If you run pfsense, simply add an entry in the Services -> DNS forwarder

  host: www
  domain: acu-link.com
  ip address: Y.Y.Y.Y

OpenWrt has a similar configuration.

1b) If you run your own nameserver, add an entry to your DNS configuration.
For example, a bind9 configuration looks something like this:

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

This will redirect any requests to www.acu-link.com, but it will not redirect
any requests to acu-link.com.

1c) Alternative bind configuration using DNS views.  This configuration sends
the hijacked DNS entry for queries from the weather station, but the standard
DNS entry for wunderground for every other DNS client query.  Thanks to Lee H-W
for this very simple DNS solution.

view "watson" {
  match-clients { 172.17.1.131/32; }; // weather station
  recursion yes;
  // view statements as required
  zone "rtupdate.wunderground.com" {
    type master;
    file "/etc/bind/override1.zone";
  };
};


===============================================================================
2) HTTP proxy/redirect

Use a proxy to capture HTTP traffic and redirect it to the driver.

2a) Here is an example of an Apache 'reverse proxy' configuration for the
Acurite internet bridge.  The Apache server sends any requests from the
internet bridge to the driver.

In the file /etc/apache2/conf.d/aculink.conf:

RewriteEngine on
RewriteCond %{HTTP_POST} www.acu-link.com
RewriteRule ^/messages(.*)$ http://Y.Y.Y.Y/messages$1

2b) Another option is to use an Apache CGI script.  Put a script alias in
the file /etc/apache2/conf.d/aculink.conf:

ScriptAlias /messages/ /usr/lib/cgi-bin/aculink

and copy the cgi script util/usr/lib/cgi-bin/aculink to the Apache
cgi-bin directory (nominally /usr/lib/cgi-bin).

2c) Here is a reverse proxy configuration for the nginx web server:

server {
    location /messages/ {
        proxy_pass http://Y.Y.Y.Y:PPPP/;
    }
}


===============================================================================
3) Packet capture configurations

There are many ways to capture traffic.  In each case, traffic is intercepted
then sent to the driver.  The capture and the driver might run on the same
device, or they can run on separate devices.  The traffic may also be sent on
to its original destination.

One strategy is to use a network capture tool such as tcpdump or ngrep to
capture traffic, then use a tool such as nc to direct the traffic to the
driver.  Another strategy is to use firewall rules to capture and redirect
traffic.

Here are a number of options for capturing network traffic:

option 1: capture using tcpdump, redirect using nc

tcpdump -i eth0 src X.X.X.X and port 80 | nc Y.Y.Y.Y PPPP


option 2: capture using tcpdump, redirect using nc

tcpdump -i eth0 dst www.acu-link.com and port 80 | nc Y.Y.Y.Y PPPP


option 3: capture using ngrep, redirect using nc

ngrep -l -q -d eth0 'ether src host X.X.X.X && dst port 80' | nc Y.Y.Y.Y PPPP


option 4: redirect traffic using iptables firewall rules

# driver is running in weewx on the router listening on port PPPP
iptables -t broute -A BROUTING -p IPv4 --ip-protocol 6 --ip-destination-port 80 -j redirect --redirect-target ACCEPT
iptables -t nat -A PREROUTING -i br0 -p tcp --dport 80 -j REDIRECT --to-port PPPP


option 4: capture using tcpdump via a secure connection to the router

ssh Z.Z.Z.Z "tcpdump -i vr1 src X.X.X.X and port 80" | nc localhost PPPP


option 5: capture using ngrep, filter with sed, forward with curl

ngrep -l -q -d eth0 'xxxxxxxxxxxx' | sed -u '/mac=/!d' | xargs -n 1 curl http://Y.Y.Y.Y:PPPP -s -d


option 6: use stdbuf and strings to aggregate fragments from tcpdump

tcpdump -Anpl -s0 -w - -i eth0 src X.X.X.X and dst port 80 | stdbuf -oL strings -n8 | combine-lines.pl | xargs -n 1 curl http://Y.Y.Y.Y:PPPP -s -d


option 7: use tcpflow in console mode

tcpflow -c | nc localhost PPPP


===============================================================================
Here are configurations that use packet capture:

a) Firewall-on-Router

Use firewall rules to redirect traffic from the internet bridge to the driver.

b) Bridge

Configure a computer or other device with two network interfaces to physically
bridge between the internet bridge and the regular network.  Plug the internet
bridge into one port, and connect the other port into the local network.  The
bridge captures traffic and sends it to the driver.

c) Tap-on-Router

Capture traffic on the network's edge router.  This can be done with a script
that captures traffic from the internet bridge and sends it to the driver.

d) Tap-on-Hub

Configure a device connected to the same hub as the internet bridge.  Since
any device on a hub can see the network traffic from any other device on the
hub, simply listen for traffic from the internet bridge then send it to the
driver.

e) Tap-on-Switch

Configure a device that is connected to a managed switch.  Unmanaged switches
will not work.  Configure the switch to mirror the traffic from one port to a
second port.  Configure a device on the second port to capture traffic from
the internet bridge then send it to the driver.

f) Tap-on-wireless

Configure a device that is connected to the same wireless network as the
internet bridge, or on a wireless segment that is between the internet bridge
and the edge router.  This will probably only work on open, unencrypted
wireless networks.

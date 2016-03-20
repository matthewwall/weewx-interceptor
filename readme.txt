* weewx-tap

This is a driver for weewx that intercepts and parses network traffic.  It can
be used with a variety of "internet bridge" devices such as the Acurite
Internet Bridge, the Oregon Scientific WS301/302, or the Fine Offset
ObserverIP.

* How it works

The driver runs a web server on a separate thread.  Data posted to that server
are parsed then processed as sensor inputs.

There are a few options for getting the data from the network to the driver.

** Hijack DNS

Change the DNS entry so that the internet bridge device sends directly to the
driver.

** Network tap configurations

There are many ways to intercept network traffic from the internet bridge.

** Tap-on-Router

Capture traffic on the router

** Tap-on-Bridge

Capture traffic on a Pi

** Tap-on-Hub

Any device connected to the same hub as the internet bridge.

** Tap-on-Switch

Any device on a mirrored port on a managed switch.

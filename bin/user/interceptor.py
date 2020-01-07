#!/usr/bin/env python
# Copyright 2016-2020 Matthew Wall
# Distributed under the terms of the GNU Public License (GPLv3)

"""
This driver runs a simple web server or sniffs network traffic in order to
capture data directly from an internet weather reporting device including:

  - Acurite Internet Bridge (also known as the SmartHub) (acurite protocol)
  - Acurite Access (wu protocol)
  - Oregon Scientific LW301/302 (OS protocol)
  - Fine Offset HP1000/WH2600
  - Fine Offset GW1000 (ecowitt protocol or wu protocol)
  - Fine Offset wifi consoles (including Ambient)
  - LaCrosse GW1000U (LaCrosse protocol)

When this driver was first written (early 2016), there were many different
firmware versions using different variations of the weather underground
protocol.  The WU protocol has stabilized, and other protocols similar to it
have been developed (e.g., ambient, ecowitt) to provide functionality not
available in the WU protocol.

See the readme file for configuration examples.  The sections below include
details about and quirks of various supported hardware models.

Thanks to rich of modern toil and george nincehelser for acurite parsing
  http://moderntoil.com/?p=794
  http://nincehelser.com/ipwx/

Thanks to Pat at obrienlabs.net for the fine offset parsing
  http://obrienlabs.net/redirecting-weather-station-data-from-observerip/

Thanks to sergei and waebi for the LW301/LW302 samples
  http://www.silent-gardens.com/blog/shark-hunt-lw301/

Thanks to Sam Roza for packet captures from the LW301

Thanks to skydvrz, keckec, mycal, kennkong for publishing their lacrosse work
  http://www.wxforum.net/index.php?topic=14299.0
  https://github.com/lowerpower/LaCrosse
  https://github.com/kennkong/Weather-ERF-Gateway-1000U

Thanks to Jerome Helbert for the pypcap option.


===============================================================================
SniffServer vs TCPServer

The driver can obtain packets by sniffing network traffic using pcap, or by
listening for TCP/IP requests.  The pcap approach requires the python pypcap
module, which in turn requires libpcap.  This means a separate installation
on most platforms.

https://github.com/pynetwork/pypcap

To run a listener, specify an address and port.  This is the default mode.
For example:

[Interceptor]
    mode = listen
    address = localhost
    port = 9999

To run a sniffer, specify an interface and filter.  For example:

[Interceptor]
    mode = sniff
    iface = eth0
    pcap_filter = src host 192.168.1.5 && dst port 80

The following sections provide some details about each type of hardware.


===============================================================================
WUClient

This is not a specific type of hardware, but rather *any* hardware that
communicates data using the weather underground protocol.  The protocol is
defined here:

https://feedback.weather.com/customer/en/portal/articles/2924682-pws-upload-protocol?b_id=17298

Since that protocol has changed over the years, a PDF version of the protocol
as of 03jun2019 is incuded in this distribution in the doc directory.


===============================================================================
Acurite Bridge

The Acurite bridge communicates with Acurite 5-in-1, 3-in-1, temperature, and
temperature/humidity sensors.  It receives signals from any number of sensors,
even though Acurite's web interface is limited to 3 devices (or 10 as of the
July 2016 firmware update).

By default, the bridge transmits data to www.acu-link.com.  Acurite requires
registration of the bridge's MAC address in order to use acu-link.com.
However, the bridge will function even if it is not registered, as long as it
receives the proper response.

The bridge sends data as soon as it receives an observation from the sensors.

Chaney did a firmware update to the bridge in July 2016.  This update made the
bridge emit data using the weather underground protocol instead of the
Chaney protocol.

The old firmware (acurite bridge) sends to aculink.com in a proprietary 'chaney
format'.  The new firmware (smarthub) sends to hubapi.acurite.com as well as to
rtupdate.wunderground.com.  The format for hubapi is similar to the rtupdate
format used at weather underground.  The user interface of the aculink service
has been shut down, and it has been replaced by the myacurite.com user
interface.

From user whorfin regarding barometric pressure:

Contrary to a significant amount of internet misinformation, it IS possible to
have the smartHub send accurate, adjusted barometric pressure directly to
wunderground. The "magic" is to use "Adjusted Pressure" as the "Barometric
Pressure Setting", and fiddle with station elevation.

After some delay of up to a few minutes, after changing this on myacurite.com,
hubapi.acurite.com will send a special, extended response to the smartHub. It
looks like this:

{"localtime":"20:36:10","checkversion":"224","ID1":"","PASSWORD1":"<wunderground_password>","sensor1":"","elevation":""}

Once set, subsequent reports to wunderground by the smarthub will be adusted
for that sensor number.


===============================================================================
Observer

Manufactured by Fine Offset as the WH2600, HP1000, and HP1003.

WH2600: bridge (wifi), cluster, THP
HP1000: console (wifi), cluster, THP
HP1003: console (no wifi), cluster, THP

Sold by Ambient as the 'Observer' including WS1001, WS1200IP, and WS1400IP.

WS0800: bridge, THP, TH
WS1400: bridge (wifi), cluster, THP
WS1200: bridge (wifi), console, cluster, THP
WS1001: console (wifi), cluster, THP

Ambient also sells 'AirBridge' and 'WeatherBridge' variants, but these use a
meteostick and meteohub/plug instead of the Fine Offset bridge.

Sold by Froggit as the HP1000 Profi Funk Wetterstation.

Sold by Aercus as the WeatherSleuth and WeatherRanger.

It looks like this hardware simply sends data in weather underground format.

The bridge sends data every 5 minutes.

The anemometer reports wind gust and wind average.  Readings are reported every
16 seconds, so there is no instantaneous wind speed reading.  The gust measure
has resolution of 1.1 m/s (2.46 mph) - one revolution of the anemometer.  It is
measured as the largest number of revolutions in any one second in the final
8 seconds of the 16 second reporting interval.  The average measure has a
resolution of 0.14 m/s (0.3 mph) - 1/8 revolution of the anemometer.  It is
measured as the number of revolutions divided by 8 in the final 8 seconds of
the 16 second reporting interval.

http://www.wxforum.net/index.php?topic=28713.msg278935#msg278935


===============================================================================
Oregon Scientific LW301/LW302

The "Anywhere Weather Kit" comes in two packages, the LW301 with a full set
of sensors, and the LW302 with only inside and outside temperature/humidity
sensors.  Both kits include the LW300 "Internet connected hub" which is
connected to the sensor base station via USB (for power only?) and to the
network via wired ethernet.

LW300: bridge (ethernet)
LW301: bridge (ethernet), base, rain, wind, TH
LW302: bridge (ethernet), base, TH

The base communicates with many different OS sensors, not just those included
in the Anywhere Weather Kit.  For example, the THGR810 temperature/humidity
sensors (up to 10 channels!) and the sensors included with the WMR86 stations
are recognized by the LW300 base receivers.

Oregon Scientific says that the LW30x works with any protocol 3 sensor.  It
says that THGN801 must be channel 1, THGR800/THGN800 must be chanel 2 or
channel 3, and states no requirements for WGR800 or PCR800 sensors.

By default, the bridge communicates with www.osanywhereweather.com

In 2018, Oregon Scientific apparently shut down the server to which the LW
stations posted their data (gateway.weather.oregonscientific.com).  The result
is weather stations that no longer report any data.  You can continue to use
these stations by making a DNS entry for gateway.weather.orgeonscientific.com
that points to the computer on which the interceptor driver is running.  The
weather station will happily post data to weeWX instead of trying to find the
oregon scientific servers that no longer exist.


===============================================================================
LaCrosse GW1000U

The LaCrosse gateway communicates via radio with the C84612 display, which in
turn communicates with the rain, wind, and TH sensors.  The gateway has a
wired ethernet connection.

The gateway communicates with weatherdirect.com.  LaCrosse alerts is a fee-
based system for receiving alerts from the gateway via lacrossealertsmobile.com

If you have any intention of using LaCrosse's alerts service, you should
register your station with LaCrosse before using this driver.

The bridge attempts to upload to /request.breq

The easiest way to use this driver is to use the Gateway Advance Setup (GAS)
utility from LaCrosse to configure the gateway to send to the computer with
this driver.


===============================================================================
Fine Offset GW1000

The Fine Offset gateway collects data from Fine Offset sensors using 915MHz
(and other?) unlicensed frequencies, then transmits the data via Wifi to
various services.  As of dec2019 these include ecowitt.net, wunderground.com,
weathercloud, weatherobservationswebsite, and metoffice.gov.uk.

This device first appeared on the market in 2018.  Despite the similarity of
name, it is completely unrelated to the LaCrosse GW1000U.  Note that there are
variants of the Fine Offset GW1000, including:

  GW1000 - 433MHz
  GW1000A - 868MHz
  GW1000B - 915MHz
  GW1000BU - 915MHz with better rang

The transmission to wunderground can be captured using the 'wu-client' mode.
However, since the gateway supports many other sensors that are not supported
by wunderground, it is usually better to use the 'fineoffset-bridge' mode.

As of firmware 1.5.5, the device will attempt to upload to ecowitt servers,
even when nothing has been configured.  It is possible to turn this off using
the WSView app.
"""

# FIXME: do a single mapping from GET/POST args to weewx schema names
# FIXME: specify by protocol, not by hardware device
# FIXME: automatically detect the protocol?
# FIXME: add code to skip duplicate and out-of-order packets
# FIXME: default acurite mapping confuses multiple tower sensors

from __future__ import with_statement

# support both python2 and python3.  attempt the python3 import first, then
# fallback to python2.
try:
    from http.server import BaseHTTPRequestHandler
    from socketserver import TCPServer
    import queue as Queue
    import urllib.parse as urlparse
except ImportError:
    from BaseHTTPServer import BaseHTTPRequestHandler
    from SocketServer import TCPServer
    import Queue
    import urlparse

import binascii
import calendar
import fnmatch
import re
import string
import sys
import threading
import time

try:
    # weewx4 logging
    import weeutil.logger
    import logging
    log = logging.getLogger(__name__)
    def logdbg(msg):
        log.debug(msg)
    def loginf(msg):
        log.info(msg)
    def logerr(msg):
        log.error(msg)
except ImportError:
    # old-style weewx logging
    import syslog
    def logmsg(level, msg):
        syslog.syslog(level, 'interceptor: %s: %s' %
                      (threading.currentThread().getName(), msg))
    def logdbg(msg):
        logmsg(syslog.LOG_DEBUG, msg)
    def loginf(msg):
        logmsg(syslog.LOG_INFO, msg)
    def logerr(msg):
        logmsg(syslog.LOG_ERR, msg)

import weewx.drivers
import weeutil.weeutil

DRIVER_NAME = 'Interceptor'
DRIVER_VERSION = '0.49'

DEFAULT_ADDR = ''
DEFAULT_PORT = 80
DEFAULT_IFACE = 'eth0'
DEFAULT_FILTER = 'dst port 80'
DEFAULT_DEVICE_TYPE = 'acurite-bridge'

def loader(config_dict, _):
    return InterceptorDriver(**config_dict[DRIVER_NAME])

def confeditor_loader():
    return InterceptorConfigurationEditor()


def _to_bytes(data):
    if sys.version_info < (3, 0):
        return bytes(data)
    return bytes(data, 'utf8')

def _bytes_to_str(data):
    if sys.version_info < (3, 0):
        return data
    return str(data, 'utf-8')

def _obfuscate_passwords(msg):
    return re.sub(r'(PASSWORD|PASSKEY)=[^&]+', r'\1=XXXX', msg)

def _fmt_bytes(data):
    if not data:
        return ''
    return ' '.join(['%02x' % ord(x) for x in data])

def _cgi_to_dict(s):
    if '=' in s:
        return dict([y.strip() for y in x.split('=')] for x in s.split('&'))
    return dict()


class Consumer(object):
    """The Consumer contains two primary parts - a Server and a Parser.  The
    Server can be a sniff server or a TCP server.  Either type of server
    is a data sink.  When it receives data, it places a string on a queue.
    The driver then pops items of the queue and hands them over to the parser.
    The Parser processes each string and spits out a dictionary that contains
    the parsed data.

    The handler is only used by the TCP server.  It provides the response to
    the client requests.

    Sniffing is not available for every type of hardware.
    """

    queue = Queue.Queue()

    def __init__(self, parser, mode='listen',
                 address=DEFAULT_ADDR, port=DEFAULT_PORT, handler=None,
                 iface=DEFAULT_IFACE, pcap_filter=DEFAULT_FILTER,
                 promiscuous=0):
        self.parser = parser
        loginf("mode is %s" % mode)
        if mode == 'sniff':
            self._server = Consumer.SniffServer(
                iface, pcap_filter, promiscuous)
        elif mode == 'listen':
            self._server = Consumer.TCPServer(address, port, handler)
        else:
            raise TypeError("unrecognized mode '%s'" % mode)

    def run_server(self):
        self._server.run()

    def stop_server(self):
        self._server.stop()
        self._server = None

    def get_queue(self):
        return Consumer.queue

    class Server(object):
        def run(self):
            pass
        def stop(self):
            pass

    class SniffServer(Server):
        """
        Abstraction to deal with the two different python pcap implementations,
        pylibpcap and pypcap.
        """
        def __init__(self, iface, pcap_filter, promiscuous):
            self.running = False
            self.data_buffer = ''
            self.sniffer_type = None
            self.sniffer_version = 'unknown'
            self.sniffer = None
            snaplen = 1600
            timeout_ms = 100
            pval = 1 if weeutil.weeutil.to_bool(promiscuous) else 0
            loginf("sniff iface=%s promiscuous=%s" % (iface, pval))
            loginf("sniff filter '%s'" % pcap_filter)
            import pcap
            try:
                # try pylibpcap
                self.sniffer = pcap.pcapObject()
                self.sniffer.open_live(iface, snaplen, pval, timeout_ms)
                self.sniffer.setfilter(pcap_filter, 0, 0)
                self.sniffer_type = 'pylibpcap'
            except AttributeError:
                # try pypcap
                self.sniffer = pcap.pcap(iface, snaplen, pval)
                self.sniffer.setfilter(pcap_filter)
                self.sniffer_type = 'pypcap'
                self.sniffer_version = pcap.__version__.lower()
            loginf("%s (%s)" % (self.sniffer_type, self.sniffer_version))

        def run(self):
            logdbg("start sniff server")
            self.running = True
            if self.sniffer_type == 'pylibpcap':
                while self.running:
                    self.sniffer.dispatch(1, self.decode_ip_packet)
            elif self.sniffer_type == 'pypcap':
                for ts, pkt in self.sniffer:
                    if not self.running:
                        break
                    self.decode_ip_packet(0, pkt, ts)

        def stop(self):
            logdbg("stop sniff server")
            self.running = False
            if self.sniffer_type == 'pylibpcap':
                self.sniffer.close()
            self.packet_sniffer = None

        def decode_ip_packet(self, _pktlen, data, _timestamp):
            # i would like to queue up each packet so we do not have to
            # maintain state.  unfortunately, sometimes we get data spread
            # across multiple packets, so we have to reassemble them.
            #
            # old acurite: one GET packet
            # new acurite: multiple GET packets
            # observer: one GET packet
            # lw30x: two POST packets
            #
            # examples:
            # POST /update HTTP/1.0\r\nHost: gateway.oregonscientific.com\r\n
            # mac=0004a36903fe&id=84&rid=f3&pwr=0&htr=0&cz=1&oh=41&...
            # GET /weatherstation/updateweatherstation?dateutc=now&rssi=2&...
            # &sensor=00003301&windspeedmph=5&winddir=113&rainin=0.00&...
            if not data:
                return
            logdbg("sniff: timestamp=%s pktlen=%s data=%s" %
                   (_timestamp, _pktlen, _fmt_bytes(data)))
            # FIXME: generalize the packet type detection
            header_len = 0
            idx = 0
            if len(data) >= 15 and data[12:14] == '\x08\x00':
                # this is standard IP packet
                header_len = ord(data[14]) & 0x0f
                idx = 4 * header_len + 34
            elif (len(data) >= 70 and
                data[12:14] == '\x81\x00' and data[16:18] == '\x08\x00'):
                # this is 802.1Q tagged IP packet
                header_len = ord(data[18]) & 0x0f
                idx = 4 * header_len + 38
            if idx and len(data) >= idx:
                _data = data[idx:]
                if 'GET' in _data:
                    self.flush()
                    logdbg("sniff: start GET")
                    self.data_buffer = _data
                elif 'POST' in _data:
                    self.flush()
                    logdbg("sniff: start POST")
                    self.data_buffer = 'POST?' # start buffer with dummy
                elif len(self.data_buffer):
                    if 'HTTP' in data:
                        # looks like the end of a multi-packet GET
                        self.flush()
                    else:
                        printable = set(string.printable)
                        fdata = filter(lambda x: x in printable, _data)
                        if fdata == _data:
                            logdbg("sniff: append %s" % _fmt_bytes(_data))
                            self.data_buffer += _data
                        else:
                            logdbg("sniff: skip %s" % _fmt_bytes(_data))
                else:
                    logdbg("sniff: ignore %s" % _fmt_bytes(_data))
            else:
                logdbg("sniff: unrecognized packet header")

        def flush(self):
            logdbg("sniff: flush %s" % _fmt_bytes(self.data_buffer))
            if not self.data_buffer:
                return
            data = self.data_buffer
            # if this is a query string, parse it
            if '?' in data:
                data = urlparse.urlparse(data).query
            # trim any dangling HTTP/x.x and connection info
            idx = data.find(' HTTP')
            if idx >= 0:
                data = data[:idx]
            if len(data):
                logdbg("SNIFF: %s" % _obfuscate_passwords(data))
                Consumer.queue.put(data)
            # clear the data buffer
            self.data_buffer = ''


    class TCPServer(Server, TCPServer):
        daemon_threads = True
        allow_reuse_address = True

        def __init__(self, address, port, handler):
            if handler is None:
                handler = Consumer.Handler
            loginf("listen on %s:%s" % (address, port))
            TCPServer.__init__(self, (address, int(port)), handler)

        def run(self):
            logdbg("start tcp server")
            self.serve_forever()

        def stop(self):
            logdbg("stop tcp server")
            self.shutdown()
            self.server_close()

    class Handler(BaseHTTPRequestHandler):

        def get_response(self):
            # default reply is a simple 'OK' string
            return 'OK'

        def reply(self):
            # standard reply is HTTP code of 200 and the response string
            response = _to_bytes(self.get_response())
            self.send_response(200)
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)            

        def do_POST(self):
            # get the payload from an HTTP POST
            length = int(self.headers["Content-Length"])
            data = str(self.rfile.read(length))
            logdbg('POST: %s' % _obfuscate_passwords(data))
            Consumer.queue.put(data)
            self.reply()

        def do_PUT(self):
            pass

        def do_GET(self):
            # get the query string from an HTTP GET
            data = urlparse.urlparse(self.path).query
            logdbg('GET: %s' % _obfuscate_passwords(data))
            Consumer.queue.put(data)
            self.reply()

        # do not spew messages on every connection
        def log_message(self, _format, *_args):
            pass

    class Parser(object):

        @staticmethod
        def parse_identifiers(s):
            return dict()

        def parse(self, s):
            return dict()

        @staticmethod
        def map_to_fields(pkt, sensor_map):
            # the sensor map is a dictionary of database field names as keys,
            # each with an associated observation identifier.
            if sensor_map is None:
                return pkt
            packet = dict()
            if 'dateTime' in pkt:
                packet['dateTime'] = pkt['dateTime']
            if 'usUnits' in pkt:
                packet['usUnits'] = pkt['usUnits']
            for n in sensor_map:
                label = Consumer.Parser._find_match(sensor_map[n], pkt.keys())
                if label:
                    packet[n] = pkt.get(label)
            return packet

        @staticmethod
        def _find_match(pattern, keylist):
            # pattern can be a simple label, or an identifier pattern.
            # keylist is an array of observations, each of which is either
            # a simple label, or an identifier tuple.
            match = None
            pparts = pattern.split('.')
            if len(pparts) == 3:
                for k in keylist:
                    kparts = k.split('.')
                    if (len(kparts) == 3 and
                        Consumer.Parser._part_match(pparts[0], kparts[0]) and
                        Consumer.Parser._part_match(pparts[1], kparts[1]) and
                        Consumer.Parser._part_match(pparts[2], kparts[2])):
                        match = k
                    elif pparts[0] == k:
                        match = k
            else:
                for k in keylist:
                    if pattern == k:
                        match = k
            return match

        @staticmethod
        def _part_match(pattern, value):
            # use glob matching for parts of the tuple
            matches = fnmatch.filter([value], pattern)
            return True if matches else False

        @staticmethod
        def _delta_rain(rain, last_rain):
            if last_rain is None:
                loginf("skipping rain measurement of %s: no last rain" % rain)
                return None
            if rain < last_rain:
                loginf("rain counter wraparound detected: new=%s last=%s" %
                       (rain, last_rain))
                return rain
            return rain - last_rain

        @staticmethod
        def decode_float(x):
            return None if x is None else float(x)

        @staticmethod
        def decode_int(x):
            return None if x is None else int(x)

        @staticmethod
        def decode_datetime(s):
            if isinstance(s, int):
                return s
            if s == 'now':
                return int(time.time() + 0.5)
            s = s.replace("%20", " ")
            s = s.replace("%3A", ":")
            if '+' in s:
                # this is a fine offset (ambient, ecowitt) timestamp
                ts = time.strptime(s, "%Y-%m-%d+%H:%M:%S")
            else:
                # this is a weather underground timestamp
                ts = time.strptime(s, "%Y-%m-%d %H:%M:%S")
            return calendar.timegm(ts)


# capture data from hardware that sends using the weather underground protocol

class WUClient(Consumer):

    def __init__(self, **stn_dict):
        super(WUClient, self).__init__(
            WUClient.Parser(), handler=WUClient.Handler, **stn_dict)

    class Handler(Consumer.Handler):

        def get_response(self):
            return 'success'

    class Parser(Consumer.Parser):

        # map database fields to observation names
        DEFAULT_SENSOR_MAP = {
            'pressure': 'pressure',
            'barometer': 'barometer',
            'outHumidity': 'humidity_out',
            'inHumidity': 'humidity_in',
            'outTemp': 'temperature_out',
            'inTemp': 'temperature_in',
            'windSpeed': 'wind_speed',
            'windGust': 'wind_gust',
            'windDir': 'wind_dir',
            'windGustDir': 'wind_gust_dir',
            'radiation': 'radiation',
            'dewpoint': 'dewpoint',
            'windchill': 'windchill',
            'rain': 'rain',
            'rainRate': 'rain_rate',
            'UV': 'uv',
            'txBatteryStatus': 'battery',
            'extraTemp1': 'temperature_1',
            'extraTemp2': 'temperature_2',
            'extraTemp3': 'temperature_3',
            'soilTemp1': 'temperature_soil_1',
            'soilTemp2': 'temperature_soil_2',
            'soilTemp3': 'temperature_soil_3',
            'soilTemp4': 'temperature_soil_4',
            'soilMoist1': 'moisture_soil_1',
            'soilMoist2': 'moisture_soil_2',
            'soilMoist3': 'moisture_soil_3',
            'soilMoist4': 'moisture_soil_4',
            'leafWet1': 'leafwetness',
            'leafWet2': 'leafwetness2',
        }

        # map labels to observation names
        LABEL_MAP = {
            'winddir': 'wind_dir',
            'windspeedmph': 'wind_speed',
            'windgustmph': 'wind_gust',
            'windgustdir': 'wind_gust_dir',
            'humidity': 'humidity_out',
            'dewptf': 'dewpoint',
            'tempf': 'temperature_out',
            'temp2f': 'temperature_1',
            'temp3f': 'temperature_2',
            'temp4f': 'temperature_3',
            'baromin': 'barometer',
            'soiltempf': 'temperature_soil_1',
            'soiltemp2f': 'temperature_soil_2',
            'soiltemp3f': 'temperature_soil_3',
            'soiltemp4f': 'temperature_soil_4',
            'soilmoisture': 'moisture_soil_1',
            'soilmoisture2': 'moisture_soil_2',
            'soilmoisture3': 'moisture_soil_3',
            'soilmoisture4': 'moisture_soil_4',
            'leafwetness': 'leafwetness',
            'solarradiation': 'radiation',
            'UV': 'uv',
            'visibility': 'visibility',
            'indoortempf': 'temperature_in',
            'indoorhumidity': 'humidity_in',
            'AqNO': 'AqNO',
            'AqNO2T': 'AqNO2T',
            'AqNO2': 'AqNO2',
            'AqNO2Y': 'AqNO2Y',
            'AqNOX': 'AqNOX',
            'AqNOY': 'AqNOY',
            'AqNO3': 'AqNO3',
            'AqSO4': 'AqSO4',
            'AqSO2': 'AqSO',
            'AqSO2T': 'AqSO2T',
            'AqCO': 'AqCO',
            'AqCOT': 'AqCOT',
            'AqEC': 'AqEC',
            'AqOC': 'AqOC',
            'AqBC': 'AqBC',
            'AqUV-AETH': 'AqUV_AETH',
            'AqPM2.5': 'AqPM2_5',
            'AqPM10': 'AqPM10_0',
            'AqOZONE': 'AqOZONE',
            # these have been observed, but apparently are unsupported?
            'windchillf': 'windchill',
            'lowbatt': 'battery',
        }

        IGNORED_LABELS = [
            'ID', 'PASSWORD', 'dateutc', 'softwaretype',
            'action', 'realtime', 'rtfreq',
            'weather', 'clouds',
            'windspdmph_avg2m', 'winddir_avg2m',
            'windgustmph_10m', 'windgustdir_10m'
        ]

        def __init__(self):
            self._last_rain = None

        def parse(self, s):
            pkt = dict()
            try:
                data = _cgi_to_dict(s)
                pkt['dateTime'] = self.decode_datetime(
                    data.pop('dateutc', int(time.time() + 0.5)))
                pkt['usUnits'] = weewx.US

                # different firmware seems to report rain in different ways.
                # prefer to get rain total from the yearly count, but if
                # that is not available, get it from the daily count.
                rain_total = None
                field = None
                if 'dailyrainin' in data:
                    rain_total = self.decode_float(data.pop('dailyrainin', None))
                    field = 'dailyrainin'
                    year_total = self.decode_float(data.pop('yearlyrainin', None))
                    if year_total is not None:
                        rain_total = year_total
                        field = 'yearlyrainin'
                elif 'dailyrain' in data:
                    rain_total = self.decode_float(data.pop('dailyrain', None))
                    field = 'dailyrain'
                    year_total = self.decode_float(data.pop('yearlyrain', None))
                    if year_total is not None:
                        rain_total = year_total
                        field = 'yearlyrain'
                if rain_total is not None:
                    pkt['rain_total'] = rain_total
                    logdbg("using rain_total %s from %s" % (rain_total, field))

                # get all of the other parameters
                for n in data:
                    if n in self.LABEL_MAP:
                        pkt[self.LABEL_MAP[n]] = self.decode_float(data[n])
                    elif n in self.IGNORED_LABELS:
                        val = data[n]
                        if n == 'PASSWORD':
                            val = 'X' * len(data[n])
                        logdbg("ignored parameter %s=%s" % (n, val))
                    else:
                        loginf("unrecognized parameter %s=%s" % (n, data[n]))

                # get the rain this period from total
                if 'rain_total' in pkt:
                    newtot = pkt['rain_total']
                    pkt['rain'] = self._delta_rain(newtot, self._last_rain)
                    self._last_rain = newtot

            except ValueError as e:
                logerr("parse failed for %s: %s" % (s, e))
            return pkt

        @staticmethod
        def map_to_fields(pkt, sensor_map):
            if sensor_map is None:
                sensor_map = WUClient.Parser.DEFAULT_SENSOR_MAP
            return Consumer.Parser.map_to_fields(pkt, sensor_map)

        @staticmethod
        def decode_float(x):
            # these stations send a value of -9999 to indicate no value, so
            # convert that to a proper None.
            x = Consumer.Parser.decode_float(x)
            return None if x == -9999 else x


# sample output from an acurite bridge with 3 t/h sensors and 1 5-in-1
#
# Chaney format (pre-July2016):
# id=X&mt=pressure&C1=452D&C2=0D7F&C3=010D&C4=0330&C5=8472&C6=1858&C7=09C4&A=07&B=1B&C=06&D=09&PR=91CA&TR=8270
# id=X&sensor=02004&mt=5N1x31&windspeed=A001660000&winddir=8&rainfall=A0000000&battery=normal&rssi=3
# id=X&sensor=02004&mt=5N1x38&windspeed=A001890000&humidity=A0280&temperature=A014722222&battery=normal&rssi=3
# id=X&sensor=06022&mt=tower&humidity=A0270&temperature=A020100000&battery=normal&rssi=3
# id=X&sensor=05961&mt=tower&humidity=A0300&temperature=A017400000&battery=normal&rssi=3
# id=X&sensor=14074&mt=tower&humidity=A0300&temperature=A021500000&battery=normal&rssi=4
#
# WU format (as of July 2016):
# GET /weatherstation/updateweatherstation?dateutc=now&action=updateraw&realtime=1&id=X&mt=5N1x31&sensor=00003301&windspeedmph=5&winddir=113&rainin=0.00&dailyrainin=0.00&humidity=45&tempf=95.6&dewptf=76.0&baromin=30.11&battery=normal&rssi=2
#
# new format samples from nincehelser (July 2016):
# dateutc=now&action=updateraw&realtime=1&id=24C86Exxxxxx&mt=tower&sensor=00002719&humidity=15&tempf=83.8&baromin=29.92&battery=normal&rssi=3
# dateutc=now&action=updateraw&realtime=1&id=24C86Exxxxxx&mt=5N1x31&sensor=00001398&windspeedmph=9&winddir=180&rainin=0.00&dailyrainin=0.03&baromin=29.92&battery=normal&rssi=1
# dateutc=now&action=updateraw&realtime=1&id=24C86Exxxxxx&mt=5N1x38&sensor=00001398&windspeedmph=9&humidity=76&tempf=84.0&baromin=29.92&battery=normal&rssi=1
#
# new format samples from radar on the weewx-user forum 21aug2016
# (docbee posted about ptempf, probe, and check on wxforum 24aug2016)
#
# 5n1
# &id=MAC&mt=5N1x31&sensor=0000xxxx
# &windspeedmph=1&winddir=45&rainin=0.00&dailyrainin=0.00
# &baromin=28.77&battery=normal&rssi=2
#
# &id=MAC&mt=5N1x38&sensor=0000xxxx
# &windspeedmph=1&humidity=53&tempf=73.8
# &baromin=28.77&battery=normal&rssi=2
#
# tower
# &id=MAC&mt=tower&sensor=0000xxxx
# &humidity=54&tempf=66.0
# &baromin=28.77&battery=normal&rssi=2
#
# room-monitor with one water decetor
# &id=MAC&mt=ProIn&sensor=0000xxxx
# &indoorhumidity=61&indoortempf=65.8
# &probe=1&check=0&water=0
# &baromin=28.77&battery=normal&rssi=2
#
# outside temp and humidity with Liquid and or Soil Temp
# &id=MAC&mt=ProOut&sensor=0000xxxx
# &humidity=63&tempf=65.2
# &probe=2&check=0&ptempf=64.9
# &baromin=28.77&battery=normal&rssi=3
#
# rain gauge
# &id=MAC&mt=rain899&sensor=000xxxxx
# &rainin=0.00&dailyrainin=0.00
# &baromin=28.77&battery=normal&rssi=2
#
# ProIn sensor no indicators
# &id=MAC&mt=ProIn&sensor=0000xxxx
# &indoorhumidity=61&indoortempf=67.1
# &baromin=28.69&battery=normal&rssi=2
#
# ProIn sensor with one Water Detector
# &id=MAC&mt=ProIn&sensor=0000xxxx
# &indoorhumidity=60&indoortempf=67.1
# &probe=1&check=0&water=0
# &baromin=28.68&battery=normal&rssi=2
#
# ProIn sensor with Liquide and or Soil Temp
# &id=MAC&mt=ProIn&sensor=0000xxxx
# &indoorhumidity=58&indoortempf=69.0
# &probe=2&check=0&ptempf=66.9
# &baromin=28.68&battery=normal&rssi=3
#
# ProIn with water detector when water is detected
# &id=MAC&mt=ProIn&sensor=0000xxxx
# &indoorhumidity=59&indoortempf=67.2
# &probe=1&check=0&water=1
# &baromin=28.65&battery=normal&rssi=2
#
# ProIn sensor with Spot Check Temperature and Humidity Sensor model# 06012RM
# &id=MAC&mt=ProIn&sensor=0000xxxx
# &indoorhumidity=63&indoortempf=66.9
# &probe=3&check=0&ptempf=74.3&phumidity=50
# &baromin=28.90&battery=normal&rssi=2

# the room monitor with water detector
#   Model: 00276WD-bundle
# the outdoor monitor with liquid & soil temperature sensor
#   Model: 00275LS-bundle

# resulting raw packet format:
#   <observation_name>.<sensor>.<id> : value

class AcuriteBridge(Consumer):

    # these are the known firmware versions as of 15oct2016:
    #
    # 126 is the version for the chaney format (pre july 2016)
    # 224 is the version for the wu format (circa july 2016)
    #
    # if the firmware version does not match that of the bridge, the bridge
    # will attempt to download the latest firmware from chaney, and the rain
    # count might get messed up.

    _firmware_version = 224

    def __init__(self, **stn_dict):
        AcuriteBridge._firmware_version = stn_dict.pop(
            'firmware_version', AcuriteBridge._firmware_version)
        super(AcuriteBridge, self).__init__(
            AcuriteBridge.Parser(), handler=AcuriteBridge.Handler, **stn_dict)

    class Handler(Consumer.Handler):

        def get_response(self):
            # the response depends on the firmware in the device, but we have
            # no way of knowing that from the device.  so the firmware version
            # is an option one must set in the driver, then this will make the
            # appropriate response.
            if AcuriteBridge._firmware_version == 126:
                return '{ "success": 1, "checkversion": "126" }'
            ts = time.strftime("%H:%M:%S", time.localtime(time.time()))
            return '{ "localtime": "%s", "checkversion": "224" }' % ts

    class Parser(Consumer.Parser):

        # map database fields to observation identifiers.  this map should work
        # out-of-the-box for either wu format or chaney format, with a basic
        # set of sensors.  if there are more than one remote sensor then a
        # custom sensor map is necessary to avoid confusion of outputs.
        DEFAULT_SENSOR_MAP = {
            # wu format uses station pressure in every packet
            'pressure': 'pressure.*.*',
            # chaney format uses station pressure in bridge packets only
            #'pressure': 'pressure..*',
            # both formats
            'inTemp': 'temperature_in.*.*',
            'inHumidity': 'humidity_in.*.*',
            'outTemp': 'temperature.?*.*',
            'outHumidity': 'humidity.?*.*',
            'windSpeed': 'windspeed.?*.*',
            'windDir': 'winddir.?*.*',
            'rain': 'rainfall.?*.*',
            'txBatteryStatus': 'battery.?*.*',
            'rxCheckPercent': 'rssi.?*.*'}

        # this is *not* the same as the acurite console mapping!
        IDX_TO_DEG = {5: 0.0, 7: 22.5, 3: 45.0, 1: 67.5, 9: 90.0, 11: 112.5,
                      15: 135.0, 13: 157.5, 12: 180.0, 14: 202.5, 10: 225.0,
                      8: 247.5, 0: 270.0, 2: 292.5, 6: 315.0, 4: 337.5}

        # map wu names to observation names
        LABEL_MAP = {
            'humidity': 'humidity',
            'tempf': 'temperature',
            'indoorhumidity': 'humidity_in',
            'indoortempf': 'temperature_in',
            'ptempf': 'temperature_probe',
            'baromin': 'pressure', # baromin is actually station pressure
            'windspeedmph': 'windspeed',
            'winddir': 'winddir',
            'dailyrainin': 'rainfall'
            # WARNING: since rainfall is obtained from dailyrainin, there
            # will be a counter wraparound at 00:00 each day.
        }

        IGNORED_LABELS = [
            'ID', 'PASSWORD', 'dateutc',
            'action', 'realtime', 'rtfreq', 'updateraw',
            'rainin', 'dewptf',
            'sensor', 'mt', 'id', 'probe', 'check', 'water'
        ]

        @staticmethod
        def parse_identifiers(s):
            data = _cgi_to_dict(s)
            return {'sensor_type': data.get('mt'),
                    'sensor_id': data.get('sensor'),
                    'bridge_id': data.get('id')}

        def __init__(self):
            self._last_rain = dict()

        # be ready for either the chaney format or the wu format
        def parse(self, s):
            pkt = dict()
            if '=' in s:
                if s.find('action') >= 0:
                    pkt = self.parse_wu(s)
                else:
                    pkt = self.parse_chaney(s)
            return pkt

        # parse packets that are in the weather underground -ish format
        def parse_wu(self, s):
            pkt = dict()
            try:
                data = _cgi_to_dict(s)
                # FIXME: add option to use computer time instead of station
                pkt['dateTime'] = self.decode_datetime(
                    data.pop('dateutc', int(time.time() + 0.5)))
                pkt['usUnits'] = weewx.US
                for n in data:
                    if n == 'id':
                        pkt['bridge_id'] = data[n]
                    elif n == 'sensor':
                        pkt['sensor_id'] = data[n]
                    elif n == 'mt':
                        pkt['sensor_type'] = data[n]
                    elif n == 'battery':
                        pkt['battery'] = 0 if data[n] == 'normal' else 1
                    elif n == 'rssi':
                        pkt['rssi'] = float(data[n]) * 25 # [0,100]
                    elif n in self.LABEL_MAP:
                        pkt[self.LABEL_MAP[n]] = self.decode_float(data[n])
                    elif n in self.IGNORED_LABELS:
                        val = data[n]
                        if n == 'PASSWORD':
                            val = 'X' * len(data[n])
                        logdbg("ignored parameter %s=%s" % (n, val))
                    else:
                        loginf("unrecognized parameter %s=%s" % (n, data[n]))
            except ValueError as e:
                logerr("parse failed for %s: %s" % (s, e))
            # convert rainfall to a delta
            if 'rainfall' in pkt:
                rain_total = pkt['rainfall']
                if 'sensor_id' in pkt:
                    last_rain = self._last_rain.get(pkt['sensor_id'])
                    pkt['rainfall'] = self._delta_rain(rain_total, last_rain)
                    pkt['rain_total'] = rain_total
                    self._last_rain[pkt['sensor_id']] = rain_total
                else:
                    loginf("ignored rainfall %s: no sensor_id" % rain_total)
                    pkt['rainfall'] = None
            return self.add_identifiers(pkt)

        # parse packets that are in the chaney format
        def parse_chaney(self, s):
            pkt = dict()
            parts = s.split('&')
            for x in parts:
                if not x:
                    continue
                if '=' not in x:
                    loginf("unexpected un-assigned variable '%s'" % x)
                    continue
                (n, v) = x.split('=')
                n = n.strip()
                v = v.strip()
                try:
                    if n == 'id':
                        pkt['bridge_id'] = v
                    elif n == 'sensor':
                        pkt['sensor_id'] = v
                    elif n == 'mt':
                        pkt['sensor_type'] = v
                    elif n == 'battery':
                        pkt['battery'] = 0 if v == 'normal' else 1
                    elif n == 'rssi':
                        pkt['rssi'] = float(v) * 25 # [0,100]
                    elif n == 'humidity':
                        pkt['humidity'] = float(v[2:5]) / 10.0 # %
                    elif n == 'temperature':
                        pkt['temperature'] = float(v[1:5]) / 10.0 # C
                    elif n == 'windspeed':
                        pkt['windspeed'] = float(v[2:5]) / 10.0 # m/s
                    elif n == 'winddir':
                        pkt['winddir'] = AcuriteBridge.Parser.IDX_TO_DEG.get(int(v, 16))
                    elif n == 'rainfall':
                        pkt['rainfall'] = float(v[2:8]) / 1000.0 # mm (delta)
                    elif n in ['C1', 'C2', 'C3', 'C4', 'C5', 'C6', 'C7',
                               'A', 'B', 'C', 'D', 'PR', 'TR']:
                        pkt[n] = int(v, 16)
                    else:
                        loginf("unknown element '%s' with value '%s'" % (n, v))
                except (ValueError, IndexError) as e:
                    logerr("decode failed for %s '%s': %s" % (n, v, e))

            # if this is a pressure packet, calculate the pressure
            if 'sensor_type' in pkt and pkt['sensor_type'] == 'pressure':
                pkt['pressure'], pkt['temperature_in'] = AcuriteBridge.Parser.decode_pressure(pkt)

            # apply timestamp and units
            pkt['dateTime'] = int(time.time() + 0.5)
            pkt['usUnits'] = weewx.METRICWX

            return self.add_identifiers(pkt)

        @staticmethod
        def add_identifiers(pkt):
            # tag each observation with identifiers:
            #   observation.<sensor_id>.<bridge_id>
            packet = dict()
            if 'dateTime' in pkt:
                packet['dateTime'] = pkt['dateTime']
            if 'usUnits' in pkt:
                packet['usUnits'] = pkt['usUnits']
            _id = '%s.%s' % (
                pkt.get('sensor_id', ''), pkt.get('bridge_id', ''))
            for n in pkt:
                packet["%s.%s" % (n, _id)] = pkt[n]
            return packet

        @staticmethod
        def map_to_fields(pkt, sensor_map):
            if sensor_map is None:
                sensor_map = AcuriteBridge.Parser.DEFAULT_SENSOR_MAP
            return Consumer.Parser.map_to_fields(pkt, sensor_map)

        @staticmethod
        def decode_pressure(pkt):
            # pressure in mbar, temperature in degree C
            if (0x100 <= pkt['C1'] <= 0xffff and
                0x0 <= pkt['C2'] <= 0x1fff and
                0x0 <= pkt['C3'] <= 0x400 and
                0x0 <= pkt['C4'] <= 0x1000 and
                0x1000 <= pkt['C5'] <= 0xffff and
                0x0 <= pkt['C6'] <= 0x4000 and
                0x960 <= pkt['C7'] <= 0xa28 and
                0x01 <= pkt['A'] <= 0x3f and 0x01 <= pkt['B'] <= 0x3f and
                0x01 <= pkt['C'] <= 0x0f and 0x01 <= pkt['D'] <= 0x0f):
                return AcuriteBridge.Parser.decode_HP03S(
                    pkt['C1'], pkt['C2'], pkt['C3'], pkt['C4'], pkt['C5'],
                    pkt['C6'], pkt['C7'], pkt['A'], pkt['B'], pkt['C'],
                    pkt['D'], pkt['PR'], pkt['TR'])
            logerr("one or more bogus constants in pressure packet: %s" % pkt)
            return None, None

        @staticmethod
        def decode_HP03S(c1, c2, c3, c4, c5, c6, c7, a, b, c, d, d1, d2):
            if d2 >= c5:
                dut = d2 - c5 - ((d2-c5)/128) * ((d2-c5)/128) * a / (2<<(c-1))
            else:
                dut = d2 - c5 - ((d2-c5)/128) * ((d2-c5)/128) * b / (2<<(c-1))
            off = 4 * (c2 + (c4 - 1024) * dut / 16384)
            sens = c1 + c3 * dut / 1024
            x = sens * (d1 - 7168) / 16384 - off
            p = 0.1 * (x * 10 / 32 + c7)
            t = 0.1 * (250 + dut * c6 / 65536 - dut / (2<<(d-1)))
            return p, t


# the observer emits data in weather underground format or in ambient weather
# format.
#
# known firmware versions
#
# Weather logger V2.1.9
# Weather logger V3.0.7
# HP1001 V2.2.2
# WeatherSmart V1.7.0
# EasyWeather V1.1.2
# AMBWeather V3.0.0
# AMBWeather V4.0.3
#
#
# sample output from an observer
#
# ID=XXXX&PASSWORD=PASSWORD&tempf=43.3&humidity=98&dewptf=42.8&windchil
# lf=43.3&winddir=129&windspeedmph=0.00&windgustmph=0.00&rainin=0.00&da
# ilyrainin=0.04&weeklyrainin=0.04&monthlyrainin=0.91&yearlyrainin=0.91
# &solarradiation=0.00&UV=0&indoortempf=76.5&indoorhumidity=49&baromin=
# 29.05&lowbatt=0&dateutc=2016-1-4%2021:2:35&softwaretype=Weather%20log
# ger%20V2.1.9&action=updateraw&realtime=1&rtfreq=5
#
# ID=XXXX&PASSWORD=PASSWORD&intemp=22.8&outtemp=1.4&dewpoint=1.1&windch
# ill=1.4&inhumi=36&outhumi=98&windspeed=0.0&windgust=0.0&winddir=193&a
# bsbaro=1009.5&relbaro=1033.4&rainrate=0.0&dailyrain=0.0&weeklyrain=10
# .5&monthlyrain=10.5&yearlyrain=10.5&light=1724.9&UV=38&dateutc=2016-4
# -19%204:42:35&softwaretype=HP1001%20V2.2.2&action=updateraw&realtime=
# 1&rtfreq=5
#
# ID=XXXX&PASSWORD=PASSWORD&intemp=23.2&outtemp=10.1&dewpoint=2.0&windc
# hill=10.1&inhumi=32&outhumi=57&windspeed=0.0&windgust=0.0&winddir=212
# &absbaro=1010.1&relbaro=1034.0&rainrate=0.0&dailyrain=0.0&weeklyrain=
# 10.5&monthlyrain=10.5&yearlyrain=10.5&light=31892.0&UV=919&dateutc=20
# 16-4-19%207:54:4&softwaretype=HP1001%20V2.2.2&action=updateraw&realti
# me=1&rtfreq=5
#
# GET /weatherstation/updateweatherstation.asp?ID=XXXXXXXXXXXXX&PASSWOR
# D=PASSWORD&outtemp=6.3&outhumi=80&dewpoint=3.1&windchill=6.3&winddir=
# 197&windspeed=0.0&windgust=0.0&rainrate=0.0&dailyrain=0.0&weeklyrain=
# 0.0&monthlyrain=0.0&yearlyrain=0.0&light=0.00&UV=1&intemp=19.8&inhumi
# =46&absbaro=1018.30&relbaro=1018.30&lowbatt=0&dateutc=2016-4-30%2021:
# 5:1&softwaretype=Weather%20logger%20V2.1.9&action=updateraw&realtime=
# 1&rtfreq=5 HTTP/1.0 
#
# GET /weatherstation/updateweatherstation.php?ID=XXXXXXXXXXXXX&PASSWOR
# D=PASSWORD&tempf=-9999&humidity=-9999&dewptf=-9999&windchillf=-9999&w
# inddir=-9999&windspeedmph=-9999&windgustmph=-9999&rainin=0.00&dailyra
# inin=0.00&weeklyrainin=0.00&monthlyrainin=0.00&yearlyrainin=0.00&sola
# rradiation=-9999&UV=-9999&indoortempf=66.2&indoorhumidity=47&baromin=
# 29.94&lowbatt=0&dateutc=2016-5-10%202:34:15&softwaretype=Weather%20lo
# gger%20V3.0.7&action=updateraw&realtime=1&rtfreq=5
#
# stationtype=AMBWeatherV4.0.2&PASSKEY=DUMMYDATADUMMYDATADUMMYDATADATAD
# &dateutc=2018-06-20+13:39:00&winddir=169&windspeedmph=1.8&windgustmph
# =2.2&maxdailygust=3.4&tempf=69.1&hourlyrainin=0.00&eventrainin=0.00&d
# ailyrainin=0.00&weeklyrainin=0.87&monthlyrainin=0.87&totalrainin=0.87
# &baromrelin=29.89&baromabsin=29.48&humidity=61&tempinf=73.4&humidityi
# n=51&uv=3&solarradiation=299.23
#
# from an ecowitt HP2550 with PM2.5 and soilmoisture:
#
# indoortempf=71.6&tempf=55.2&dewptf=51.6&windchillf=55.2&indoorhumidit
# y=64&humidity=88&windspeedmph=2.0&windgustmph=2.2&winddir=25&absbarom
# in=29.729&baromin=29.729&rainin=0.000&dailyrainin=0.000&weeklyrainin=
# 0.000&monthlyrainin=0.091&yearlyrainin=0.091&solarradiation=0.00&UV=0
# &soilmoisture=52&AqPM2.5=309.0&dateutc=2019-06-16%2001:05:39&software
# type=EasyWeatherV1.3.9&action=updateraw&realtime=1&rtfreq=5

# resulting raw packet format:
#   <observation_name> : value

class Observer(Consumer):

    def __init__(self, **stn_dict):
        super(Observer, self).__init__(
            Observer.Parser(), handler=Observer.Handler, **stn_dict)

    class Handler(Consumer.Handler):

        def get_response(self):
            return 'success'

    class Parser(Consumer.Parser):

        # map database fields to observation names
        DEFAULT_SENSOR_MAP = {
            'pressure': 'pressure',
            'barometer': 'barometer',
            'outHumidity': 'humidity_out',
            'inHumidity': 'humidity_in',
            'outTemp': 'temperature_out',
            'inTemp': 'temperature_in',
            'windSpeed': 'wind_speed',
            'windGust': 'wind_gust',
            'windDir': 'wind_dir',
            'windGustDir': 'wind_gust_dir',
            'radiation': 'radiation',
            'dewpoint': 'dewpoint',
            'windchill': 'windchill',
            'rain': 'rain',
            'rainRate': 'rain_rate',
            'UV': 'uv',
            'txBatteryStatus': 'battery',
            'soilMoist1': 'soilmoisture',
            'pm2_5': 'pm2_5',
        }

        # map labels to observation names
        LABEL_MAP = {
            # firmware Weather logger V2.1.9
            'humidity': 'humidity_out',
            'indoorhumidity': 'humidity_in',
            'tempf': 'temperature_out',
            'indoortempf': 'temperature_in',
            'baromin': 'barometer',
            'windspeedmph': 'wind_speed',
            'windgustmph': 'wind_gust',
            'solarradiation': 'radiation',
            'dewptf': 'dewpoint',
            'windchillf': 'windchill',

            # firmware HP1001 2.2.2
            'outhumi': 'humidity_out',
            'inhumi': 'humidity_in',
            'outtemp': 'temperature_out',
            'intemp': 'temperature_in',
            'absbaro': 'pressure',
            'windspeed': 'wind_speed',
            'windgust': 'wind_gust',
            'light': 'luminosity',
            'dewpoint': 'dewpoint',
            'windchill': 'windchill',
            'rainrate': 'rain_rate',

            # firmware AMBWeatherV4.0.2
            'baromabsin': 'pressure',
            'tempinf': 'temperature_in',
            'humidityin': 'humidity_in',
            'uv': 'uv',

            # firmware WS-1002 V2.4.3 also reports station pressure
            'absbaromin': 'pressure',

            # firmware EasyWeatherV1.3.9 (ecowitt HP2550)
            'AqPM2.5': 'pm2_5',
            'soilmoisture': 'soilmoisture',

            # for all firmware
            'winddir': 'wind_dir',
            'windgustdir': 'wind_gust_dir',
            'UV': 'uv',
            'lowbatt': 'battery',
        }

        IGNORED_LABELS = [
            'ID', 'PASSWORD', 'PASSKEY', 'dateutc', 'softwaretype',
            'action', 'realtime', 'rtfreq',
            'relbaro', 'rainin',
            'weeklyrain', 'monthlyrain',
            'weeklyrainin', 'monthlyrainin',
        ]

        def __init__(self):
            self._last_rain = None

        def parse(self, s):
            # FIXME: explicitly distinguish between ambient and wu packets
            pkt = dict()
            try:
                data = _cgi_to_dict(s)
                # FIXME: add option to use computer time instead of station
                pkt['dateTime'] = self.decode_datetime(
                    data.pop('dateutc', int(time.time() + 0.5)))
                pkt['usUnits'] = weewx.US if 'tempf' in data else weewx.METRIC

                # different firmware seems to report rain in different ways.
                # prefer to get rain total from the yearly count, but if
                # that is not available, get it from the daily count.
                rain_total = None
                field = None
                if 'dailyrainin' in data:
                    rain_total = self.decode_float(data.pop('dailyrainin', None))
                    field = 'dailyrainin'
                    year_total = self.decode_float(data.pop('yearlyrainin', None))
                    if year_total is not None:
                        rain_total = year_total
                        field = 'yearlyrainin'
                elif 'dailyrain' in data:
                    rain_total = self.decode_float(data.pop('dailyrain', None))
                    field = 'dailyrain'
                    year_total = self.decode_float(data.pop('yearlyrain', None))
                    if year_total is not None:
                        rain_total = year_total
                        field = 'yearlyrain'
                if rain_total is not None:
                    pkt['rain_total'] = rain_total
                    logdbg("using rain_total %s from %s" % (rain_total, field))

                # some firmware reports baromin as station pressure, but others
                # report it as barometer.
                if 'softwaretype' in data:
                    fw = data['softwaretype']
                    if fw == 'WH2600GEN_V2.2.5' or fw == 'WH2650A_V1.2.1':
                        self.LABEL_MAP['baromin'] = 'pressure'
                    logdbg("firmware %s: baromin is %s" %
                           (fw, self.LABEL_MAP['baromin']))

                # get all of the other parameters
                for n in data:
                    if n in self.LABEL_MAP:
                        pkt[self.LABEL_MAP[n]] = self.decode_float(data[n])
                    elif n in self.IGNORED_LABELS:
                        val = data[n]
                        if n == 'PASSWORD' or n == 'PASSKEY':
                            val = 'X' * len(data[n])
                        logdbg("ignored parameter %s=%s" % (n, val))
                    else:
                        loginf("unrecognized parameter %s=%s" % (n, data[n]))

                # get the rain this period from total
                if 'rain_total' in pkt:
                    newtot = pkt['rain_total']
                    if pkt['usUnits'] == weewx.METRIC:
                        newtot /= 10.0 # METRIC wants cm, not mm
                    pkt['rain'] = self._delta_rain(newtot, self._last_rain)
                    self._last_rain = newtot

                # ensure that the rain rate has the right units
                if ('rainRate' in pkt and pkt['rainRate'] is not None and
                    pkt['usUnits'] == weewx.METRIC):
                    pkt['rainRate'] /= 10.0 # METRIC wants cm/hr, not mm/hr

                # convert luminosity to solar radiation
                # FIXME: this should be done in StdWXCalculate
                if 'luminosity' in pkt and not 'radiation' in pkt:
                    lum2rad = 0.01075 # lux to W/m^2 (approximation)
                    pkt['radiation'] = pkt['luminosity'] * lum2rad
            except ValueError as e:
                logerr("parse failed for %s: %s" % (s, e))
            return pkt

        @staticmethod
        def map_to_fields(pkt, sensor_map):
            if sensor_map is None:
                sensor_map = Observer.Parser.DEFAULT_SENSOR_MAP
            return Consumer.Parser.map_to_fields(pkt, sensor_map)

        @staticmethod
        def decode_float(x):
            # these stations send a value of -9999 to indicate no value, so
            # convert that to a proper None.
            x = Consumer.Parser.decode_float(x)
            return None if x == -9999 else x


# sample output from a LW301
#
# mac=XX&id=8e&rid=af&pwr=0&or=0&uvh=0&uv=125&ch=1&p=1
# mac=XX&id=90&rid=9d&pwr=0&gw=0&av=0&wd=315&wg=1.9&ws=1.1&ch=1&p=1
# mac=XX&id=84&rid=20&pwr=0&htr=0&cz=3&oh=90&ttr=0&ot=18.9&ch=1&p=1
# mac=XX&id=82&rid=1d&pwr=0&rro=0&rr=0.00&rfa=5.114&ch=1&p=1
# mac=XX&id=c2&pv=0&lb=0&ac=0&reg=1803&lost=0000&baro=806&ptr=0&wfor=3&p=1
# mac=XX&id=90&rid=9d&pwr=0&gw=0&av=0&wd=247&wg=1.9&ws=1.1&ch=1&p=1
# mac=XX&id=8e&rid=63&pwr=0&or=0&uvh=0&uv=365&ch=1&p=1
#
# observed values for lost:
# 0000: ?
# 0803: wind, t/h, rain
# 1803: wind, t/h, rain, uv
#
# observed values for wfor:
# 0=partly_cloudy, 1=sunny, 2=cloudy, 3=rainy, 4=snowy
#
# all packets
#  mac - mac address of the bridge
#  id - sensor type identifier       samples: 82, 84, 8e, 90, c2
#  p - ?                             samples: 1
#
# base station packets (0xc2)
#  pv - ?                      samples: 0
#  lb - ?                      samples: 0
#  ac - ?                      samples: 0
#  reg - registered sensors?   samples: 1803, 1009, 1809
#  lost - lost contact?        samples: 0000
#  baro - pressure mbar
#  ptr - ?                     samples: 0, 1
#  wfor - weather forecast
#
# all non-base packets
#  rid - sensor identifier
#  pwr - battery status?       samples: 0
#  ch - channel                samples: 1, 3
#
# uv sensor (0x8e)
#  or - ?              samples: 0
#  uvh - index         samples: 0
#  uv - ?              samples: 125-382
#
# wind sensor (0x90)
#  gw - ?              samples: 0
#  av - ?              samples: 0
#  wd - wind direction in compass degrees
#  wg - wind gust m/s
#  ws - wind speed m/s
#
# temperature/humidity sensor (0x84)
#  htr - ?             samples: 0, 1, 2
#  cz - ?              samples: 0, 1, 2, 3
#  oh - humidity %
#  ttr - ?             samples: 0, 1
#  ot - temperature C
#
# rain sensor (0x82)
#  rro - ?             samples: 0
#  rr - rain rate? inch/hr
#  rfa - rain fall accumulated? inch

# resulting raw packet format:
#   <observation_name>.<ch>:<rid>.<mac> : value

class LW30x(Consumer):

    def __init__(self, **stn_dict):
        super(LW30x, self).__init__(LW30x.Parser(), **stn_dict)

    class Parser(Consumer.Parser):

        def __init__(self):
            self._last_rain = dict()

        FLOATS = ['baro', 'ot', 'oh', 'ws', 'wg', 'wd', 'rr', 'rfa', 'uvh']

        # map database fields to sensor tuples
        DEFAULT_SENSOR_MAP = {
            'pressure': 'baro.*.*',
            'outTemp': 'ot.?:*.*',
            'outHumidity': 'oh.?:*.*',
            'windSpeed': 'ws.?:*.*',
            'windGust': 'wg.?:*.*',
            'windDir': 'wd.?:*.*',
            'rainRate': 'rr.?:*.*',
            'rain': 'rain.?:*.*',
            'UV': 'uvh.?:*.*'}

        @staticmethod
        def parse_identifiers(s):
            data = _cgi_to_dict(s)
            return {'sensor_type': data.get('id'),
                    'channel': data.get('ch'),
                    'sensor_id': data.get('rid'),
                    'bridge_id': data.get('mac')}

        def parse(self, s):
            pkt = dict()
            try:
                data = _cgi_to_dict(s)
                for n in data:
                    if n in LW30x.Parser.FLOATS:
                        pkt[n] = self.decode_float(data[n])
                    else:
                        pkt[n] = data[n]
            except ValueError as e:
                logerr("parse failed for %s: %s" % (s, e))

            # convert rain from inches to mm
            if 'rfa' in pkt:
                pkt['rfa'] *= 25.4
            if 'rr' in pkt:
                pkt['rr'] *= 25.4

            # convert accumulated rain to rain delta
            if 'rfa' in pkt:
                rain_total = pkt['rfa']
                if 'ch' in pkt and 'rid' in pkt:
                    sensor_id = "%s:%s" % (pkt['ch'], pkt['rid'])
                    last_rain = self._last_rain.get(sensor_id)
                    pkt['rain'] = self._delta_rain(rain_total, last_rain)
                    self._last_rain[sensor_id] = rain_total
                else:
                    loginf("ignored rainfall %s: no sensor_id" % rain_total)
                    pkt['rain'] = None

            # tag each observation with identifiers:
            #   observation.<channel>:<sensor_id>.<bridge_id>
            packet = {'dateTime': int(time.time() + 0.5),
                      'usUnits': weewx.METRICWX}
            _id = '%s:%s.%s' % (pkt.get('ch', ''), pkt.get('rid', ''),
                                pkt.get('mac', ''))
            for n in pkt:
                packet["%s.%s" % (n, _id)] = pkt[n]
            return packet

        @staticmethod
        def map_to_fields(pkt, sensor_map):
            if sensor_map is None:
                sensor_map = LW30x.Parser.DEFAULT_SENSOR_MAP
            return Consumer.Parser.map_to_fields(pkt, sensor_map)


"""
The output from a GW1000U is more complicated that a simply http GET/POST.
What follows is the dissection using conventions from mycal and skyspy.

Each request has a header HTTP_IDENTIFY with the following contents:

  HTTP_IDENTIFY: 8009E3A7:00:45A49CAF5B9ED7E2:70
                 ^^^^^^^^ ^^ ^^^^^^^^^^^^^^^^ ^^
                 A B      C  D                E

  A - always 80 (2 characters)
  B - MAC address less vendor ID (6 characters)
  C - packet code (2 characters)
  D - registration code (16 characters)
  E - packet code (2 characters)

Some packets have data, many do not.
The packet code C:E is used to identify incoming packet types.

Some replies have data, many do not.
Each reply includes a HTTP_FLAGS header in the form 00:00.

Packet types

Sent by the gateway:

CC:EE len description
----- --- -----------
00:10   0 gateway power up
00:20   0 gateway registration
00:30   0 gateway registration finished
00:70   0 gateway ping
01:00   5 weather station ping
01:01 197 current data (type 01)
01:01 210 history data (type 21, also lengths 30, 48, ...)
01:14  14 weather station registration verification
7f:10  13 weather station registration

Sent by the server:

xx:xx len description
----- --- -----------
10:00   0 reply to 00:10
20:00 252 reply to 00:20
30:00   0 reply to 00:30
30:01   0 reply to 00:30
70:00  18 reply to 00:70
20:01 252 reply to 00:70
14:00  38 reply to 7f:10
14:01  38 reply to 01:00
1c:00   0 reply to 01:14
00:01   0 reply to 01:01
00:00   0 reply to 01:01 197
00:00   0 reply to 01:01 210
00:01   0 reply to 01:01 210 (terminate the history packets?)

Data packets

5-byte 01:00

00 packet type 0x41
01 rf signal strength
02
03
04

197-byte packet (current data)

This is the decoding based on mycal description:

start nyb  nybble encoding description
00H   0    2      byte     Record type, always 01
01H   2    4      ???      rf signal strength
03H   6    3      byte     status?
04L   9    10     BDC      Date/Time of Max Inside Temp
09L   13   10     BCD      Date/Time of Min Inside Temp
0eL   1d   3      BCD      Max Inside Temp
10H   20   2      ???      Unknown
11H   22   3      BCD      Min Inside Temp
12L   25   2      ???      Unknown
13L   27   3      BCD      Current Inside Temp
15H   2a   3      ???      Unknown
16L   2d   10     BCD      Date/Time of Max Outside Temp
1bL   37   10     BCD      Date/Time of Min Outside Temp
20L   41   3      BCD      Max Outside Temp
22H   44   2      ???      Unknown
23H   46   3      BCD      Min Outside Temp
24L   49   2      ???      Unknown
25L   4b   3      BCD      Current Outside Temp
27H   4e   3      ???      Unknown
28L   51   10     BCD      Unknown Date/Time 1
2dL   5b   10     BCD      Unknown Date/Time 2
32L   65   10     ???      Unknown
37L   6f   3      BCD      Copy of outside temp?
39H   72   2      ???      Status byte-per skydvr 0xA0 error
3aH   74   10     BCD      Date/Time of Max Inside Humidity
3fH   7e   10     BCD      Date/Time of Min Inside Humidity
44H   88   2      binary   Max Inside Humidity
45H   8a   2      binary   Min Inside Humidity
46H   8c   2      binary   Current Inside Humidity
47H   8e   10     BCD      Date/Time of Max Outside Humidity
4cH   98   10     BCD      Date/Time of Min Outside Humidity
51H   a2   2      binary   Max Outside Humidity
52H   a4   2      binary   Min Outside Humidity
53H   a6   2      binary   Current Outside Humidity
54H   a8   18     ???      Unknown all 0s
5dH   ba   4      ???      Unknown
5fH   be   20     ???      Unknown all 0s
69H   d2   2      ???      Unknown
6aH   d4   10     BCD      Unknown Date/Time 3
6fH   de   12     ???      Unknown
75H   ea   10     BCD      Date/Time last 1-hour rain window ended
7aH   f4   13     ???      Unknown
80L   101  10     BCD      Date/Time of Last Rain Reset
85L   10b  23     ???      Unknown - skydvr says rainfall array
91H   122  4      binary   Current Ave Wind Speed
93H   126  4      ???      Unknown
95H   12a  6      nybbles  Wind direction history -- One nybble per time period
98H   130  10     BCD      Time of Max Wind Gust
9dH   13a  4      binary   Max Wind Gust since reset in 100th of km/h
9fH   13e  2      ???      Unknown
a0H   140  4      binary   Max Wind Gust this Cycle in 100th of km/h
a2H   144  4      ???      Unknown - skydvr says wind status
a4H   148  6      nybbles  Copy of wind direction history?
a7H   14e  1      ???      Unknown
a7L   14f  4      BCD      Current barometer in inches Hg
a9L   153  6      ???      Unknown - skydvr says 0xAA might be pressure delta
acL   159  4      BCD      Min Barometer
aeL   15d  6      ???      Unknown
b1L   163  4      BCD      Max Barometer
b3L   167  5      ???      Unknown
b6H   16c  10     BCD      Unknown Date/Time 5
bbH   176  10     BCD      Unknown Date/Time 6
c0H   180  6      ???      Unknown
c3H   186  2      binary   Checksum1
c4H   188  2      binary   Checksum2 May be one 16-bit checksum

historical data packet

these packets have length that is a multiple of 18-bytes (0x12).  the largest
is 210-bytes, the shortest is 30-bytes.  observed lengths include 30, 48, 66,
84, 102, 120, 138, 156, 174, or 192 bytes.

each packet contains an 8-byte header, n 18-byte records, and a 4-byte footer

1: 8 + 18 + 4 -> 30
2: 8 + 36 + 4 -> 48
11: 8 + 198 + 4 -> 210

30-byte packet

00..01   data type indicator (0x21 0x64)
02       rf signal strength
03       ?
04..05   current_address
06..07   next_address (current + 0x12)
08..09   rainfall
09H      wind gust direction; 0x0-0xf
0aH      wind direction; 0x0-0xf
0aL..0bL wind gust; 3 nybbles in 0.01 kph
0cH..0dH wind speed; 3 nybbles in 0.01 kph
0dL..0eH outside humidity; %
0eL..0fH inside humidity; %
0fL..11L barometer; 0.1 mbar
12H..13H outside temperature; 0.1 C + 400
13L..14L inside temperature; 0.1 C + 400
15..19   date ymdhi
1a..1d   ?

00|01|02|03|04|05|06|07|08|09|0a|0b|0c|0d|0e|0f|10|11|12|13|14|15|16|17|18|19
                                                               xx xx xx xx xx
                                                          x xx inside temp
                                                      xx x outside temp
                                              x xx xx barometer
                                           x x inside humidity
                                        x x outside humidity
                                    xx x wind speed
                               x xx wind gust
                              x wind direction
                            x wind gust direction
                        xx x rainfall
                  xx xx next address
            xx xx current address
         ?
      xx rf signal strengh
   64
21 - data type

210-byte packet (history)

00..01 data type indicator (0x21 0x64)
02     rf signal strength
03     ?
04..05 current_address
06..07 next_address (current + 0x12)
08..cd eleven 18-byte records
ce..d1 ?

Gateway registration

Gateway can be reset by holding the reset button while the gateway is powered
up.  It will then attempt to re-register.

Once registered, the gateway periodically sends a ping of 00:70.  The reply to
this ping determines how often the gateway should ping.

Weather station registration

To register a station, press the rain button on the weather station to get a
blinking REG, then push the gateway button.  This should generate the station
registration packet 7F:10, which contains the registration key.  A registration
key that starts with 7FFF is a valid registration key, and the driver should
respond with that key.  A registration key of 0102030405060708 indicates that
the station has not been registered, and the registration key in the response
from the driver will be set as the station's registration key.

The station responds to registration with a 01:14 packet.

Flush data packets

Press the rain button until beep on a registered station to flush data packets.
"""

# resulting raw packet format:
#   <observation_name>..<mac> : value

# FIXME: implement packet sniffing mode for gw1000u
# FIXME: implement standalone option to detect gw1000u broadcasts and configure
#        the proxy settings to point to the machine running weewx

class GW1000U(Consumer):

    # values for history interval:
    #  0x00 - 1 minute
    #  0x01 - 5 minutes
    #  0x02 - 10 minutes
    #  0x03 - 15 minutes (default)
    #  0x04 - 20 minutes
    #  0x05 - 30 minutes
    #  0x06 - 1 hour
    #  0x07 - 2 hours
    HISTORY_INTERVALS = {
        0: '1m', 1: '5m', 2: '10m', 3: '15m', 4: '20m', 5: '30m',
        6: '1h', 7: '2h'}

    UNREGISTERED_SERIAL = '0102030405060708'
    EMPTY_SERIAL = '0' * 16

    station_serial = EMPTY_SERIAL # serial from lacrosse, starts with 7fff
    ping_interval = 240 # how often gateway should ping the server, in seconds
    sensor_interval = 1 # minutes between data packets
    history_interval_idx = 1 # index of history interval
    lcd_brightness = 4
    server_name = 'box.weatherdirect.com'
    
    def __init__(self, **stn_dict):
        stn_dict['mode'] = 'listen' # sniffing not supported for this hardware
        GW1000U.station_serial = stn_dict.pop('serial', GW1000U.station_serial)
        if len(GW1000U.station_serial) != 16:
            raise weewx.ViolatedPrecondition("serial must be 16 characters")
        loginf('using station serial %s' % GW1000U.station_serial)
        GW1000U.ping_interval = int(stn_dict.pop(
            'ping_interval', GW1000U.ping_interval))
        loginf('using ping interval %ss' % GW1000U.ping_interval)
        GW1000U.sensor_interval = int(stn_dict.pop(
            'sensor_interval', GW1000U.sensor_interval))
        if GW1000U.sensor_interval < 1:
            raise weewx.ViolatedPrecondition("sensor_interval must be >= 1")
        loginf('using sensor interval %sm' % GW1000U.sensor_interval)
        GW1000U.history_interval_idx = int(stn_dict.pop(
            'history_interval', GW1000U.history_interval_idx))
        if GW1000U.history_interval_idx not in GW1000U.HISTORY_INTERVALS:
            raise weewx.ViolatedPrecondition("history interval must be 0-7")
        loginf('using history interval %s (%s)' %
               (GW1000U.history_interval_idx,
                GW1000U.HISTORY_INTERVALS.pop(GW1000U.history_interval_idx)))
        super(GW1000U, self).__init__(
            GW1000U.Parser(), handler=GW1000U.Handler, **stn_dict)

    @staticmethod
    def encode_ts(ts):
        # encode a 12-character time stamp into 6 bytes
        # FIXME: verify that this should be localtime, not utc
        tstr = time.strftime("%H%M%S%d%m%y", time.localtime(ts))
        s = ''
        for x in range(0, 6):
            s += chr(GW1000U.encode_bcd(tstr[x * 2:x * 2 + 2]))
        return s

    @staticmethod
    def decode_serial(data):
        return binascii.hexlify(data)

    @staticmethod
    def encode_serial(sn):
        # encode a 16-character serial number into 8 bytes
        return _bytes_to_str(binascii.unhexlify(sn))

    @staticmethod
    def encode_bcd(x):
        x = int(x)
        msb = x // 10
        lsb = x % 10
        if msb > 10:
            msb = 10
        return (msb << 4) | (lsb & 0xf)

    class Handler(Consumer.Handler):
        protocol_version = 'HTTP/1.1'
        last_history_address = 0

        def do_PUT(self):
            flags = '00:00'
            response = ''
            parts = self.headers.get('HTTP_IDENTIFY', '').split(':')
            if len(parts) == 4:
                (mac, id1, code, id2) = parts
                pkt_type = ("%s:%s" % (id1, id2)).upper()
                length = int(self.headers.get('Content-Length', 0))
                data = self.rfile.read(length) if length else ''
                logdbg("recv: %s:%s %s %s %s" %
                       (id1, id2, mac, code, _fmt_bytes(data)))
                if pkt_type == '00:10':
                    # gateway power up
                    loginf("power up from gateway with mac %s" % mac)
                    flags = '10:00'
                elif pkt_type == '00:14':
                    # received after response to 7f:10 packet.
                    # gateway sends 14 bytes.
                    loginf("registration confirmed for mac %s (%s)"
                           % (mac, _fmt_bytes(data)))
                    flags = '1C:00'
                elif pkt_type == '00:20':
                    # gateway registration
                    loginf("registration from gateway with mac %s" % mac)
                    flags = '20:00' # sometimes replies with 20:01
                    response = self._create_gateway_reg_response(
                        GW1000U.server_name)
                elif pkt_type == '00:30':
                    # received after response to 00:20 packet
                    flags = '30:00' # also observed 30:01
                elif pkt_type == '00:70':
                    # gateway ping
                    flags = '70:00' # also observed 20:01
                    response = self._create_gateway_ping_response(
                        GW1000U.ping_interval)
                elif pkt_type == '01:00':
                    # station ping.  gateway sends 5 bytes.
                    flags = '14:01'
                    response = self._create_station_ping_response(
                        int(time.time()),
                        GW1000U.station_serial,
                        GW1000U.sensor_interval,
                        GW1000U.history_interval_idx,
                        GW1000U.lcd_brightness,
                        GW1000U.Handler.last_history_address)
                elif pkt_type == '01:14':
                    # unknown.  gateway sends 14 bytes.
                    # the first 8 bytes are the serial 7fffxxxxxxxx
                    if data and len(data) >= 8:
                        sn = GW1000U.decode_serial(data[0:8])
                        if (sn.startswith('7fff') and
                            GW1000U.station_serial == GW1000U.EMPTY_SERIAL):
                            loginf("using serial %s" % sn)
                            GW1000U.station_serial = sn
                        if sn == GW1000U.station_serial:
                            flags = '1C:00'
                            loginf("responded to msg 01:14 mac=%s sn=%s (%s)"
                                   % (mac, sn, _fmt_bytes(data)))
                        else:
                            loginf("ignored msg 01:14 mac=%s sn=%s (%s)"
                                   % (mac, sn, _fmt_bytes(data)))
                    else:
                        loginf("ignored msg 01:14 with no serial mac=%s (%s)"
                               % (mac, _fmt_bytes(data)))
                elif pkt_type == '7F:10':
                    # station registration.  gateway sends 13 bytes.
                    # the first 8 bytes are the serial 7fffxxxxxxxx
                    if data and len(data) >= 8:
                        sn = GW1000U.decode_serial(data[0:8])
                        if (sn.startswith('7fff') and
                            GW1000U.station_serial == GW1000U.EMPTY_SERIAL):
                            loginf("using serial %s" % sn)
                            GW1000U.station_serial = sn
                        do_reply = False
                        if sn == GW1000U.station_serial:
                            do_reply = True
                        if sn == GW1000U.UNREGISTERED_SERIAL:
                            if GW1000U.station_serial.startswith('7fff'):
                                loginf("assigning serial %s to unregistered"
                                       " station mac=%s (%s)"
                                       % (GW1000U.station_serial, mac,
                                          _fmt_bytes(data)))
                                do_reply = True
                            else:
                                # FIXME: generate a new registration key
                                loginf("ignored unregistered station mac=%s"
                                       " (%s)" % (mac, _fmt_bytes(data)))
                        if do_reply:
                            flags = '14:00'
                            response = self._create_station_reg_response(
                                int(time.time()), sn, GW1000U.lcd_brightness)
                            loginf("responded to msg 7F:10 mac=%s sn=%s (%s)"
                                   % (mac, sn, _fmt_bytes(data)))
                        else:
                            loginf("ignored msg 7F:10 mac=%s sn=%s (%s)"
                                   % (mac, sn, _fmt_bytes(data)))
                    else:
                        loginf("ignored msg 7F:10 with no serial mac=%s (%s)"
                               % (mac, _fmt_bytes(data)))
                elif pkt_type == '01:01':
                    # data packet
                    flags = '00:00' # also observed 00:01
                    if data and ord(data[0]) == 0x01:
                        # this is a current conditions packet, process it
                        Consumer.queue.put({'mac': mac,
                                            'data': binascii.b2a_hex(data)})
                    elif data and ord(data[0]) == 0x21:
                        # this is a history packet, get the history address
                        caddr = ord(data[4]) * 256 + ord(data[5])
                        naddr = ord(data[6]) * 256 + ord(data[7])
                        logdbg("current_addr=0x%04x next_addr=0x%04x" %
                               (caddr, naddr))
                        GW1000U.Handler.last_history_address = caddr
                    else:
                        loginf("unknown data packet type: %s" %
                               _fmt_bytes(data))
                else:
                    loginf("unknown packet type %s" % pkt_type)
            elif 'HTTP_IDENTIFY' not in self.headers:
                loginf('no HTTP_IDENTIFY in headers')
            else:
                loginf("unknown format for HTTP_IDENTIFY: '%s'" %
                       self.headers.get('HTTP_IDENTIFY', ''))

            logdbg("send: %s %s" % (flags, _fmt_bytes(response)))

            tstr = time.strftime("%a, %d %b %Y %H:%M:%S GMT",
                                 time.gmtime(time.time()))

            self.send_response(200)
            self.send_header('HTTP_FLAGS', flags)
            self.send_header('Server', 'Microsoft-IIS/8.0')
            self.send_header('X-Powered-By', 'ASP.NET')
            self.send_header('X-ApsNet-Version', '2.0.50727')
            self.send_header('Cache-Control', 'private')
            self.send_header('Content-Length', len(response))
            self.send_header('Content-Type', 'application/octet-stream')
            self.send_header('Date', tstr)
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(response)

        @staticmethod
        def _create_gateway_reg_response(server):
            # 252-byte reply
            return ''.join(
                [chr(0) * 8, # FIXME: what should these 8 bytes be?
                 server.ljust(0x98, chr(0)),
                 ("%s%s%s" % (server, chr(0), server)).ljust(0x56, chr(0)),
                 chr(0) * 5, # FIXME: what should these 5 bytes be?
                 chr(0xff)])

        @staticmethod
        def _create_gateway_ping_response(interval):
            # 18-byte reply
            hi = interval // 256
            lo = interval % 256
            return ''.join([chr(0) * 16, chr(hi), chr(lo)])
        
        @staticmethod
        def _create_station_reg_response(ts, serial, brightness):
            # 38-byte reply
            # FIXME: this looks a lot like the ping response, with the checksum
            # the only difference.  need more samples from lacrosse alerts to
            # see whether the last two bytes really should be calculated the
            # same way as those of the ping response.
            payload = ''.join(
                [chr(1),
                 GW1000U.encode_serial(serial), # 8 bytes
                 chr(0) + chr(0x30) + chr(0) + chr(0xf) + chr(0) + chr(0) + chr(0) + chr(0xf) + chr(0) + chr(0) + chr(0),
                 chr(0x77), # FIXME: should be sensor interval minus one?
                 chr(0),
                 chr(0xe) + chr(0xff), # FIXME: should be last history address?
                 GW1000U.encode_ts(ts), # 6 bytes
                 chr(0x53),
                 chr(0x7), # history interval?
                 chr(brightness - 1), # LCD brightness
                 chr(0) + chr(0), # beep weather station
                 chr(0), # unknown
                 chr(0x7)]) # unknown - 0x7 is from lacrosse alerts
            cs = GW1000U.Handler.checksum8(payload)
            return payload + chr(cs)

        @staticmethod
        def _create_station_ping_response(ts, serial,
                                          sensor_interval, history_interval,
                                          brightness, last_history_address):
            # 38-byte reply
            # sensor_interval is in minutes
            hi = last_history_address // 256
            lo = last_history_address % 256
            payload = ''.join(
                [chr(1),
                 GW1000U.encode_serial(serial), # 8 bytes starting with 7fff
                 chr(0) + chr(0x32) + chr(0) + chr(0xb) + chr(0) + chr(0) + chr(0) + chr(0xf) + chr(0) + chr(0) + chr(0),
                 chr(sensor_interval - 1), # byte 0x14 (0x3)
                 chr(0),
                 chr(hi) + chr(lo), # last_history_address 2 bytes (0x3e 0xde)
                 GW1000U.encode_ts(ts), # 6 bytes
                 chr(0x53),
                 chr(history_interval), # byte 0x1f (0x7)
                 chr(brightness - 1), # byte 0x20 (0x4)
                 chr(0) + chr(0),
                 chr(0)])
            cs = GW1000U.Handler.checksum16p7(payload)
            return payload + chr(cs >> 8) + chr(cs & 0xff)

        @staticmethod
        def checksum8(x):
            n = 0
            for c in x:
                n += ord(c)
            return n & 0xff

        @staticmethod
        def checksum16p7(x):
            n = 7 # the checksum has a seed of 7
            for c in x:
                n += ord(c)
            return n & 0xffff

    class Parser(Consumer.Parser):

        # map database fields to sensor identifier tuples
        DEFAULT_SENSOR_MAP = {
            'barometer': 'barometer..*',
            'inTemp': 'temperature_in..*',
            'outTemp': 'temperature_out..*',
            'inHumidity': 'humidity_in..*',
            'outHumidity': 'humidity_out..*',
            'windSpeed': 'wind_speed..*',
            'windGust': 'gust_speed..*',
            'windDir': 'wind_dir..*',
            'windGustDir': 'gust_dir..*',
            'rain': 'rain..*',
            'rxCheckPercent': 'rf_signal_strength..*'}

        def __init__(self):
            self._last_rain = None

        @staticmethod
        def parse_identifiers(payload):
            return {'bridge_id': payload.get('mac')}

        def parse(self, payload):
            # parse the bytes from the payload
            s = payload.get('data', '')
            pkt = dict()
            try:
                if len(s) == 394 and s[0:2] == '01':
                    pkt = self.parse_current(s)
                elif len(s) in [60,96,132,168,204,240,276,312,348,384,420] and s[0:2] == '21':
                    pkt = self.parse_history(s)
                else:
                    loginf("unhandled data len=%s (%s)" % (len(s), s))
            except ValueError as e:
                logerr("parse failed for %s: %s" % (payload, e))
            # now tag each value with identifiers
            mac = payload.get('mac')
            packet = {'dateTime': int(time.time() + 0.5),
                      'usUnits': weewx.METRIC}
            for n in pkt:
                packet["%s..%s" % (n, mac)] = pkt[n]
            return packet

        def parse_current(self, s):
            # this expects a string of hex characters.  the data packet length
            # is 197, so the hex string should be 394 characters.
            pkt = dict()
            pkt['record_type'] = s[0:2] # always 01
            pkt['rf_signal_strength'] = int(s[2:4], 16) # %
            pkt['status'] = s[4:6] # 0x10, 0x20, 0x30
            pkt['forecast'] = s[6:8] # 0x11, 0x12, 0x20, 0x21
            pkt['temperature_in'] = self.to_temperature(s, 39) # C
            pkt['temperature_out'] = self.to_temperature(s, 75) # C
            ok = int(s[114], 16) == 0 # 0=ok, 0xa=err
            pkt['windchill'] = self.to_temperature(s, 111) if ok else None # C
            pkt['humidity_in'] = self.to_hum(s, 140) # %
            pkt['humidity_out'] = self.to_hum(s, 166) # %
            pkt['rain_total'] = self.to_rainfall(s, 267) / 10.0 # cm
            pkt['rain'] = self._delta_rain(pkt['rain_total'], self._last_rain)
            self._last_rain = pkt['rain_total']
            ok = int(s[297], 16) == 0 # 0=ok, 5=err
            if ok:
                pkt['wind_speed'] = self.to_windspeed(s, 290) # kph
                pkt['wind_dir'] = self.to_winddir(s, 298) # degrees
                pkt['gust_speed'] = self.to_windspeed(s, 320) # kph
                pkt['gust_dir'] = self.to_winddir(s, 328) # degrees
            else:
                pkt['wind_speed'] = None
                pkt['wind_dir'] = None
                pkt['gust_speed'] = None
                pkt['gust_dir'] = None
            pkt['barometer'] = self.to_pressure(s, 339) # mbar
            return pkt

        def parse_history(self, s):
            pkt = dict()
            pkt['record_type'] = s[0:2] # always 21
            pkt['current_address'] = self.to_addr(s, 8)
            pkt['next_address'] = self.to_addr(s, 12)
            # FIXME: decode the records
            return pkt

        @staticmethod
        def map_to_fields(pkt, sensor_map):
            if sensor_map is None:
                sensor_map = GW1000U.Parser.DEFAULT_SENSOR_MAP
            return Consumer.Parser.map_to_fields(pkt, sensor_map)
        
        @staticmethod
        def to_addr(x, idx):
            hi = int(x[idx: idx + 2], 16)
            lo = int(x[idx + 2:idx + 4], 16)
            return hi * 256 + lo

        @staticmethod
        def to_temperature(x, idx):
            # returns temperature in degree C
            s = x[idx:idx + 3]
            if s.lower() == 'aaa' or s.lower() == 'aa3' or s.lower() == 'aa6':
                return None
            return GW1000U.Parser.bcd2int(s) / 10.0 - 40.0

        @staticmethod
        def to_hum(x, idx):
            # returns humidity in percent
            s = x[idx:idx + 2]
            if s.lower() == 'aa':
                return None
            return GW1000U.Parser.bcd2int(s)

        @staticmethod
        def to_windspeed(x, idx):
            # returns windspeed in km per hour
            return GW1000U.Parser.bin2int(x[idx:idx + 4]) / 100.0

        @staticmethod
        def to_winddir(x, idx):
            # returns compass degrees in [0,360]
            return int(x[idx:idx + 1], 16) * 22.5

        @staticmethod
        def to_pressure(x, idx):
            # returns barometric pressure in mbar
            return GW1000U.Parser.bcd2int(x[idx:idx + 5]) / 10.0

        @staticmethod
        def to_rainfall(x, idx, n=7):
            # each tip is 0.01", returns rain total in mm
            v = GW1000U.Parser.bcd2int(x[idx:idx + n])
            if n == 6:
                v /= 100.0
            else:
                v /= 1000.0
            return v
                
        @staticmethod
        def bcd2int(x):
            v = 0
            for y in x:
                v = v * 10 + int(y)
            return v
                
        @staticmethod
        def bin2int(x):
            v = 0
            for y in x:
                v = (v << 4) + int(y, 16)
            return v


"""
Capture data from devices that transmit using ecowitt protocol, such as the
Fine Offset GW1000 bridge.

* the bridge attempts to upload to rtpdate.ecowitt.net using HTTP GET
* the protocol is called 'ecowitt' - it is similar to but incompatible with WU

The ecowitt.net server responds with HTTP 200.  However, the payload varies
depending on the configuration.

When the device is not registered, the ecowitt.net server replies with:

{"errcode":"40001","errmsg":"invalid passkey"}

When the device has been registered, the ecowitt.net server replies with:

{"errcode":"0","errmsg":"ok","UTC_offset":"-18000"}

The device is a bit chatty - every 2 seconds it does a UDP broadcast.  Every
10 seconds it does an ARP broadcast.

The UDP broadcast packet is 35 bytes.  It contains the MAC address, IP address,
and SSID of the GW1000.  For example:

FFFF120021807D5A3D537AC0A84C08AFC810475731303030422D5749464935333741B3

which breaks down to:

FFFF 120021 807D5A3D537A C0A84C08 AFC810 475731303030422D5749464935333741
     ------ ------------ -------- ------ --------------------------------
     ?      MAC          IPADDR   ?       G W 1 0 0 0 B - W I F I 5 3 7 A

Here the IPADDR is 192.168.76.8, and the SSID uses the last 4 digits of the
MAC address.
"""
class EcowittClient(Consumer):
    """Use the ecowitt protocol (not WU protocol) to capture data"""

    def __init__(self, **stn_dict):
        super(EcowittClient, self).__init__(
            EcowittClient.Parser(), handler=EcowittClient.Handler, **stn_dict)

    class Handler(Consumer.Handler):

        def get_response(self):
            return '{"errcode":"0","errmsg":"ok","UTC_offset":"-18000"}'

    class Parser(Consumer.Parser):

        # map database fields to observation names
        DEFAULT_SENSOR_MAP = {
            'pressure': 'pressure',
            'barometer': 'barometer',
            'outHumidity': 'humidity_out',
            'inHumidity': 'humidity_in',
            'outTemp': 'temperature_out',
            'inTemp': 'temperature_in',
            'windSpeed': 'wind_speed',
            'windGust': 'wind_gust',
            'windDir': 'wind_dir',
            'windGustDir': 'wind_gust_dir',
            'radiation': 'radiation',
            'dewpoint': 'dewpoint',
            'windchill': 'windchill',
            'rain_total': 'rain_total',
            'rainRate': 'rain_rate',
            'UV': 'uv',
            'txBatteryStatus': 'battery'
        }

        # map labels to observation names
        LABEL_MAP = {
            'baromabsin': 'pressure',
            'humidity': 'humidity_out',
            'humidityin': 'humidity_in',
            'tempf': 'temperature_out',
            'tempinf': 'temperature_in',
            'windspeedmph': 'wind_speed',
            'windgustmph': 'wind_gust',
            'winddir': 'wind_dir',
            'solarradiation': 'solar_radiation',
            'uv': 'uv',
            'totalrainin': 'rain_total',
            'rainratein': 'rain_rate',
            'wh25batt': 'battery_wh25_1',
            'wh26batt': 'battery_wh26_1',
            'wh65batt': 'battery_wind',
        }

        IGNORED_LABELS = [
            'PASSKEY', 'dateutc', 'stationtype', 'model', 'freq', 'baromrelin',
            'eventrainin', 'maxdailygust', 'hourlyrainin',
            'dailyrainin', 'weeklyrainin', 'monthlyrainin', 'yearlyrinin',
        ]

        def __init__(self):
            self._last_rain = None

        def parse(self, s):
            pkt = dict()
            try:
                data = _cgi_to_dict(s)
                pkt['dateTime'] = self.decode_datetime(
                    data.pop('dateutc', int(time.time() + 0.5)))
                pkt['usUnits'] = weewx.US

                # get all of the other parameters
                for n in data:
                    if n in self.LABEL_MAP:
                        pkt[self.LABEL_MAP[n]] = self.decode_float(data[n])
                    elif n in self.IGNORED_LABELS:
                        val = data[n]
                        if n == 'PASSKEY':
                            val = 'X' * len(data[n])
                        logdbg("ignored parameter %s=%s" % (n, val))
                    else:
                        loginf("unrecognized parameter %s=%s" % (n, data[n]))

                # get the rain this period from total
                if 'rain_total' in pkt:
                    newtot = pkt['rain_total']
                    pkt['rain'] = self._delta_rain(newtot, self._last_rain)
                    self._last_rain = newtot

            except ValueError as e:
                logerr("parse failed for %s: %s" % (s, e))
            return pkt

        @staticmethod
        def map_to_fields(pkt, sensor_map):
            if sensor_map is None:
                sensor_map = EcowittClient.Parser.DEFAULT_SENSOR_MAP
            return Consumer.Parser.map_to_fields(pkt, sensor_map)

        @staticmethod
        def decode_float(x):
            # these stations send a value of -9999 to indicate no value, so
            # convert that to a proper None.
            x = Consumer.Parser.decode_float(x)
            return None if x == -9999 else x
        

class InterceptorConfigurationEditor(weewx.drivers.AbstractConfEditor):
    @property
    def default_stanza(self):
        return """
[Interceptor]
    # This section is for the network traffic interceptor driver.

    # The driver to use:
    driver = user.interceptor

    # Specify the hardware device to capture.  Options include:
    #   acurite-bridge - acurite internet bridge, smarthub, or access
    #   observer - fine offset WH2600/HP1000/HP1003, ambient WS2902
    #   lw30x - oregon scientific LW301/LW302
    #   lacrosse-bridge - lacrosse GW1000U/C84612 internet bridge
    #   ecowitt-client - any hardware that uses the ecowitt protocol
    #   wu-client - any hardware that uses the weather underground protocol
    device_type = acurite-bridge

    # For acurite, fine offset, and oregon scientific hardware, the driver
    # can sniff packets directly or run a socket server that listens for
    # connections.  Packet sniffing requires the installation of the pcap
    # python module.  The default mode is to listen using a socket server.
    # Options are 'listen' and 'sniff'.
    #mode = listen

    # When listening, specify at least a port on which to bind.
    #address = 127.0.0.1
    #port = 80

    # When sniffing, specify a network interface and a pcap filter.
    #iface = eth0
    #pcap_filter = src 192.168.4.12 and dst port 80
    # If your interface requires promiscuous mode, then set this to True.
    #promiscuous = False

    # Specify a sensor map to associate sensor observations with fields in
    # the database.  This is most appropriate for hardware that supports
    # a variable number of sensors.  The values in the tuple on the right
    # side are hardware-specific, but follow the pattern:
    #
    #  <observation_name>.<hardware_id>.<bridge_id>
    #
    #[[sensor_map]]
    #    inTemp = temperature_in.*.*
    #    inHumidity = humidity_in.*.*
    #    outTemp = temperature.?*.*
    #    outHumidity = humidity.?*.*

"""

    def prompt_for_settings(self):
        print("Specify the type of device whose data will be captured")
        device_type = self._prompt(
            'device_type', 'acurite-bridge',
            ['acurite-bridge', 'observer', 'lw30x', 'lacrosse-bridge',
             'fineoffset-bridge', 'wu-client'])
        return {'device_type': device_type}


class InterceptorDriver(weewx.drivers.AbstractDevice):
    DEVICE_TYPES = {
        'acurite-bridge': AcuriteBridge,
        'observer': Observer,
        'observerip': Observer,
        'lw30x': LW30x,
        'lacrosse-bridge': GW1000U,
        'ecowitt-client': EcowittClient,
        'fineoffset-bridge': EcowittClient,
        'wu-client': WUClient
    }

    def __init__(self, **stn_dict):
        loginf('driver version is %s' % DRIVER_VERSION)
        stn_dict.pop('driver')
        self._device_type = stn_dict.pop('device_type', 'acurite-bridge')
        if not self._device_type in self.DEVICE_TYPES:
            raise TypeError("unsupported device type '%s'" % self._device_type)
        loginf('device type: %s' % self._device_type)
        self._obs_map = stn_dict.pop('sensor_map', None)
        loginf('sensor map: %s' % self._obs_map)
        self._queue_timeout = int(stn_dict.pop('queue_timeout', 10))
        self._device = self.DEVICE_TYPES.get(self._device_type)(**stn_dict)
        self._server_thread = threading.Thread(target=self._device.run_server)
        self._server_thread.setDaemon(True)
        self._server_thread.setName('ServerThread')
        self._server_thread.start()

    def closePort(self):
        loginf('shutting down server thread')
        self._device.stop_server()
        self._server_thread.join(20.0)
        if self._server_thread.isAlive():
            logerr('unable to shut down server thread')

    @property
    def hardware_name(self):
        return self._device_type

    def genLoopPackets(self):
        while True:
            try:
                data = self._device.get_queue().get(True, self._queue_timeout)
                logdbg('raw data: %s' % data)
                pkt = self._device.parser.parse(data)
                logdbg('raw packet: %s' % pkt)
                pkt = self._device.parser.map_to_fields(pkt, self._obs_map)
                logdbg('mapped packet: %s' % pkt)
                if pkt and 'dateTime' in pkt and 'usUnits' in pkt:
                    yield pkt
                else:
                    logdbg("skipping bogus packet %s ('%s')" % (pkt, data))
            except Queue.Empty:
                logdbg('empty queue')


# define a main entry point for determining sensor identifiers.
# invoke this as follows from the weewx root dir:
#
# PYTHONPATH=bin python bin/user/interceptor.py

if __name__ == '__main__':
    import optparse

    usage = """%prog [options] [--debug] [--help]"""

    parser = optparse.OptionParser(usage=usage)
    parser.add_option('--version', dest='version', action='store_true',
                      help='display driver version')
    parser.add_option('--debug', dest='debug', action='store_true',
                      default=False,
                      help='display diagnostic information while running')
    parser.add_option('--mode', dest='mode', metavar='MODE',
                      default='listen',
                      help='how to capture traffic: listen or sniff')
    parser.add_option('--port', dest='port', metavar='PORT', type=int,
                      default=DEFAULT_PORT,
                      help='port on which to listen')
    parser.add_option('--address', dest='addr', metavar='ADDRESS',
                      default=DEFAULT_ADDR,
                      help='address on which to bind')
    parser.add_option('--iface', dest='iface', metavar='IFACE',
                      default=DEFAULT_IFACE,
                      help='network interface to sniff')
    parser.add_option('--filter', dest='filter', metavar='FILTER',
                      default=DEFAULT_FILTER,
                      help='pcap filter for sniffing')
    parser.add_option('--device', dest='device_type', metavar='DEVICE_TYPE',
                      default=DEFAULT_DEVICE_TYPE,
                      help='type of device for which to listen')
    parser.add_option('--data', dest='data', metavar='DATA',
                      default='',
                      help='data string for parse testing')
    parser.add_option('--no-obfuscate', action='store_true', default=False,
                      help='do not obfuscate passkeys/passwords')
    parser.add_option('--parse-gw1000u', action='store_true',
                      default=False,
                      help='test gw1000u packet parsing')
    parser.add_option('--test-gw1000u-response', action='store_true',
                      default=False,
                      help='test gw1000u responses')

    (options, args) = parser.parse_args()

    if options.version:
        print("driver version is %s" % DRIVER_VERSION)
        exit(0)

    if options.debug:
        weewx.debug = 1

    #    weeutil.logger.setup('interceptor', {})

    if options.data:
        options.data = options.data.replace(' ', '')

    if options.parse_gw1000u:
        parser = GW1000U.Parser()
        print(parser.parse({'mac': 'tester', 'data': options.data}))
        exit(0)

    if options.test_gw1000u_response:
        ts = int(time.time())
#        ts = 1577681257 # for deterministic test comparisons
        serial = GW1000U.station_serial
        server = GW1000U.server_name
        ping_interval = GW1000U.ping_interval
        brightness = GW1000U.lcd_brightness
        sensor_interval = GW1000U.sensor_interval
        history_interval = GW1000U.history_interval_idx
        last_history_address = GW1000U.Handler.last_history_address
        print("ts: %s" % ts)
        print("serial: %s" % serial)
        print("server: %s" % server)
        print("ping_interval: %s" % ping_interval)
        print("brightness: %s" % brightness)
        print("sensor_interval: %s" % sensor_interval)
        print("history_interval: %s" % history_interval)
        print("last_address: %s" % last_history_address)
        print("gateway_reg_response: %s" % _fmt_bytes(GW1000U.Handler._create_gateway_reg_response(server)))
        print("gateway_ping_response: %s" % _fmt_bytes(GW1000U.Handler._create_gateway_ping_response(ping_interval)))
        print("station_reg_response: %s" % _fmt_bytes(GW1000U.Handler._create_station_reg_response(ts, serial, brightness)))
        print("station_ping_response: %s" % _fmt_bytes(GW1000U.Handler._create_station_ping_response(ts, serial, sensor_interval, history_interval, brightness, last_history_address)))
        exit(0)

    if not options.device_type in InterceptorDriver.DEVICE_TYPES:
        raise TypeError("unsupported device type '%s'.  options include %s" %
                        (options.device_type,
                         ', '.join(InterceptorDriver.DEVICE_TYPES.keys())))

    device = InterceptorDriver.DEVICE_TYPES.get(options.device_type)(
        mode=options.mode,
        iface=options.iface, pcap_filter=options.filter,
        address=options.addr, port=options.port)

    server_thread = threading.Thread(target=device.run_server)
    server_thread.setDaemon(True)
    server_thread.setName('ServerThread')
    server_thread.start()

    while True:
        try:
            _data = device.get_queue().get(True, 1)
            ids = device.parser.parse_identifiers(_data)
            if ids:
                print('identifiers: %s' % ids)
            if options.debug:
                s = '%s' % _data
                if not options.no_obfuscate:
                    s = _obfuscate_passwords(s)
                print('raw data: %s' % s)
            _pkt = device.parser.parse(_data)
            if options.debug:
                s = '%s' % _pkt
                if not options.no_obfuscate:
                    s = _obfuscate_passwords(s)
                print('raw packet: %s' % s)
            _pkt = device.parser.map_to_fields(_pkt, None)
            s = '%s' % _pkt
            if not options.no_obfuscate:
                s = _obfuscate_passwords(s)
            print('mapped packet: %s' % s)
        except Queue.Empty:
            pass
        except KeyboardInterrupt:
            break

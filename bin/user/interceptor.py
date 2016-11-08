#!/usr/bin/env python
# Copyright 2016 Matthew Wall, all rights reserved
"""
This driver runs a simple web server designed to receive data directly from an
internet weather reporting device such as the Acurite internet bridge, the
LaCrosse GW1000U internet bridge, the Oregon Scientific LW300 (LW301/LW302)
internet bridge, or the FineOffset HP1000 console or WH2600 internet bridge.

Thanks to rich of modern toil and george nincehelser for acurite parsing
  http://moderntoil.com/?p=794
  http://nincehelser.com/ipwx/

Thanks to Pat at obrienlabs.net for the fine offset parsing
  http://obrienlabs.net/redirecting-weather-station-data-from-observerip/

Thanks to sergei and waebi for the LW301/LW302 samples
  http://www.silent-gardens.com/blog/shark-hunt-lw301/

Thanks to Sam Roza for packet captures from the LW301

Thanks to skydvrz, mycal, kennkong for publishing their lacrosse work
  http://www.wxforum.net/index.php?topic=14299.0
  https://github.com/lowerpower/LaCrosse
  https://github.com/kennkong/Weather-ERF-Gateway-1000U

About the stations

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

Oregon Scientific LW301/LW302

The "Anywhere Weather Kit" comes in two packages, the LW301 with a full set
of sensors, and the LW302 with only inside and outside temperature/humidity
sensors.  Both kits include the LW300 "Internet connected hub" which is
connected to the sensor base station via USB (for power only?) and to the
network via wired ethernet.

LW301: bridge (ethernet), base, rain, wind, TH
LW302: bridge (ethernet), base, TH

The base communicates with many different OS sensors, not just those included
in the Anywhere Weather Kit.  For example, the THGR810 temperature/humidity
sensors (up to 10 channels!) and the sensors included with the WMR86 stations
are recognized by the LW300 base receivers.

By default, the bridge communicates with www.osanywhereweather.com

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
    filter = src host 192.168.1.5 && dst port 80

"""

# FIXME: automatically detect the traffic type
# FIXME: default acurite mapping confuses multiple tower sensors

from __future__ import with_statement
import BaseHTTPServer
import SocketServer
import Queue
import binascii
import calendar
import fnmatch
import syslog
import threading
import time
import urlparse

import weewx.drivers

DRIVER_NAME = 'Interceptor'
DRIVER_VERSION = '0.15'

DEFAULT_ADDR = ''
DEFAULT_PORT = 80
DEFAULT_IFACE = 'eth0'
DEFAULT_FILTER = 'dst port 80'
DEFAULT_DEVICE_TYPE = 'acurite-bridge'

def loader(config_dict, _):
    return InterceptorDriver(**config_dict[DRIVER_NAME])

def confeditor_loader():
    return InterceptorConfigurationEditor()


def logmsg(level, msg):
    syslog.syslog(level, 'interceptor: %s: %s' %
                  (threading.currentThread().getName(), msg))

def logdbg(msg):
    logmsg(syslog.LOG_DEBUG, msg)

def loginf(msg):
    logmsg(syslog.LOG_INFO, msg)

def logerr(msg):
    logmsg(syslog.LOG_ERR, msg)


def _obfuscate_passwords(msg):
    idx = msg.find('PASSWORD')
    if idx >= 0:
        import re
        msg = re.sub(r'PASSWORD=[^&]+', r'PASSWORD=XXXX', msg)
    return msg

def _fmt_bytes(data):
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
                 iface=DEFAULT_IFACE, pcap_filter=DEFAULT_FILTER):
        self.parser = parser
        loginf("mode is %s" % mode)
        if mode == 'sniff':
            self._server = Consumer.SniffServer(iface, pcap_filter)
        elif mode == 'listen':
            self._server = Consumer.TCPServer(address, port, handler)
        else:
            raise Exception("unrecognized mode '%s'" % mode)

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
        SNAPLEN = 1600
        PROMISCUOUS = 0
        TIMEOUT_MS = 100

        def __init__(self, iface, pcap_filter):
            import pcap
            self.packet_sniffer = pcap.pcapObject()
            loginf("sniff iface %s" % iface)
            self.packet_sniffer.open_live(
                iface, self.SNAPLEN, self.PROMISCUOUS, self.TIMEOUT_MS)
            loginf("sniff filter '%s'" % pcap_filter)
            self.packet_sniffer.setfilter(pcap_filter, 0, 0)
            self.running = False
            self.reassembled_string = ''
            self.sniff_active = False

        def run(self):
            self.running = True
            while self.running:
                self.packet_sniffer.dispatch(1, self.decode_ip_packet)

        def stop(self):
            self.running = False
            self.packet_sniffer.close()
            self.packet_sniffer = None

        def decode_ip_packet(self, _pktlen, data, _timestamp):
            if data:
                logdbg("sniff: pktlen=%s timestamp=%s data=%s" %
                       (_pktlen, _timestamp, _fmt_bytes(data)))
                if data[12:14] == '\x08\x00':
                    header_len = ord(data[14]) & 0x0f
                    _data = data[4 * header_len + 34:]
                    logdbg("sniff: header_len=%s _data=%s" %
                           (header_len, _fmt_bytes(_data)))
                    if 'GET' in _data:
                        self.reassembled_string = _data
                        self.sniff_active = True
                    elif 'HTTP' in data and self.sniff_active:
                        self.sniff_active = False
                        data = urlparse.urlparse(self.reassembled_string).query
                        logdbg("SNIFF: %s" % _obfuscate_passwords(data))
                        Consumer.queue.put(data)
                    elif self.sniff_active:
                        self.reassembled_string += _data


    class TCPServer(Server, SocketServer.TCPServer):
        daemon_threads = True
        allow_reuse_address = True

        def __init__(self, address, port, handler):
            if handler is None:
                handler = Consumer.Handler
            loginf("listen on %s:%s" % (address, port))
            SocketServer.TCPServer.__init__(self, (address, int(port)), handler)

        def run(self):
            self.serve_forever()

        def stop(self):
            self.shutdown()
            self.server_close()


    class Handler(BaseHTTPServer.BaseHTTPRequestHandler):

        def get_response(self):
            # default reply is a simple 'OK' string
            return 'OK'

        def reply(self):
            # standard reply is HTTP code of 200 and the response string
            response = bytes(self.get_response())
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
            packet = {'dateTime': pkt['dateTime'], 'usUnits': pkt['usUnits']}
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
        def decode_wu_datetime(s):
            if s == 'now':
                return int(time.time() + 0.5)
            s = s.replace("%20", " ")
            ts = time.strptime(s, "%Y-%m-%d %H:%M:%S")
            return calendar.timegm(ts)


# sample output from a bridge with 3 t/h sensors and 1 5-in-1
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
    # will attempt to download the latest firmware from chaney.

    _firmware_version = 126

    def __init__(self, **stn_dict):
        super(AcuriteBridge, self).__init__(
            AcuriteBridge.Parser(), handler=AcuriteBridge.Handler, **stn_dict)
        if 'firmware_version' in stn_dict:
            AcuriteBridge._firmware_version = stn_dict['firmware_version']

    class Handler(Consumer.Handler):

        def get_response(self):
            return '{ "success": 1, "checkversion": "%s" }' % AcuriteBridge._firmware_version

    class Parser(Consumer.Parser):

        # map database fields to observation identifiers.  this map should work
        # out-of-the-box for either wu format or chaney format, with a basic
        # set of sensors.  if there are more than one remote sensor then a
        # custom sensor map is necessary to avoid confusion of outputs.
        DEFAULT_SENSOR_MAP = {
            # wu format uses barometer in every packet
            'barometer': 'barometer.?*.*',
            # chaney format uses barometer in bridge packets only
            'pressure': 'pressure..*',
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
            'baromin': 'barometer',
            'windspeedmph': 'windspeed',
            'winddir': 'winddir',
            'dailyrainin': 'rainfall'
            # WARNING: since rainfall is obtained from dailyrainin, there
            # will be a counter wraparound at 00:00 each day.
        }

        IGNORED_LABELS = ['rainin', 'dewptf',
                          'realtime', 'rtfreq',
                          'action', 'ID', 'PASSWORD', 'dateutc',
                          'updateraw', 'sensor', 'mt', 'id',
                          'probe', 'check', 'water']

        @staticmethod
        def parse_identifiers(s):
            data = _cgi_to_dict(s)
            return {'sensor_type': data.get('mt'),
                    'sensor_id': data.get('sensor'),
                    'bridge_id': data.get('id')}

        def __init__(self):
            self._last_rain = None

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
                pkt['dateTime'] = self.decode_wu_datetime(
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
                        pkt['rssi'] = float(data[n]) / 4.0
                    elif n in self.LABEL_MAP:
                        pkt[self.LABEL_MAP[n]] = self.decode_float(data[n])
                    elif n in self.IGNORED_LABELS:
                        logdbg("ignored parameter %s=%s" % (n, data[n]))
                    else:
                        loginf("unrecognized parameter %s=%s" % (n, data[n]))
            except ValueError, e:
                logerr("parse failed for %s: %s" % (s, e))
            # convert rainfall to a delta
            if 'rainfall' in pkt:
                rain_total = pkt['rainfall']
                pkt['rainfall'] = self._delta_rain(rain_total, self._last_rain)
                self._last_rain = rain_total
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
                        pkt['rssi'] = float(v) / 4.0
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
                except (ValueError, IndexError), e:
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
            packet = {'dateTime': pkt['dateTime'], 'usUnits': pkt['usUnits']}
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

# resulting raw packet format:
#   <observation_name> : value

class Observer(Consumer):

    def __init__(self, **stn_dict):
        super(Observer, self).__init__(Observer.Parser(), **stn_dict)

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
            'radiation': 'radiation',
            'dewpoint': 'dewpoint',
            'windchill': 'windchill',
            'rain': 'rain',
            'rainRate': 'rain_rate',
            'UV': 'uv',
            'txBatteryStatus': 'battery'}

        # map labels to observation names
        LABEL_MAP = {
            # for firmware Weather logger V2.1.9
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
            'yearlyrainin': 'rain_total',

            # for firmware HP1001 2.2.2
            'outhumi': 'humidity_out',
            'inhumi': 'humidity_in',
            'outtemp': 'temperature_out',
            'intemp': 'temperature_in',
            'absbaro': 'pressure',
            'windspeed': 'wind_speed',
            'windgust': 'wind_gust',
            'light': 'radiation',
            'dewpoint': 'dewpoint',
            'windchill': 'windchill',
            'rainrate': 'rain_rate',
            'yearlyrain': 'rain_total',

            # for all firmware
            'winddir': 'wind_dir',
            'UV': 'uv',
            'lowbatt': 'battery',
        }

        IGNORED_LABELS = ['relbaro',
                          'dailyrain', 'weeklyrain', 'monthlyrain',
                          'rainin',
                          'dailyrainin', 'weeklyrainin', 'monthlyrainin',
                          'realtime', 'rtfreq',
                          'action', 'ID', 'PASSWORD', 'dateutc',
                          'softwaretype']

        def __init__(self):
            self._last_rain = None

        def parse(self, s):
            pkt = dict()
            try:
                data = _cgi_to_dict(s)
                # FIXME: add option to use computer time instead of station
                pkt['dateTime'] = self.decode_wu_datetime(
                    data.pop('dateutc', int(time.time() + 0.5)))
                pkt['usUnits'] = weewx.US if 'tempf' in data else weewx.METRIC
                for n in data:
                    if n in self.LABEL_MAP:
                        pkt[self.LABEL_MAP[n]] = self.decode_float(data[n])
                    elif n in self.IGNORED_LABELS:
                        logdbg("ignored parameter %s=%s" % (n, data[n]))
                    else:
                        loginf("unrecognized parameter %s=%s" % (n, data[n]))
                # get the rain this period from yearly total
                if 'rain_total' in pkt:
                    newtot = pkt['rain_total']
                    if pkt['usUnits'] == weewx.METRIC:
                        newtot /= 10.0 # METRIC wants cm, not mm
                    pkt['rain'] = self._delta_rain(newtot, self._last_rain)
                    self._last_rain = newtot
            except ValueError, e:
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
#  id - sensor type identifier?
#
# base station packets (0xc2)
#  pv - ?                      samples: 0
#  lb - ?                      samples: 0
#  ac - ?                      samples: 0
#  reg - registered sensors?   samples: 1803, 1009
#  lost - lost contact?        samples: 0000
#  baro - barometer mbar
#  ptr - ?                     samples: 0
#  wfor - weather forecast?
#
# all non-base packets
#  rid - sensor identifier
#  pwr - battery status?
#  ch - channel
#
# uv sensor (0x8e)
#  or - ?              samples: 0
#  uvh - ?             samples: 0
#  uv - index? what is range?   samples: 125, 365
#
# wind sensor (0x90)
#  gw - ?              samples: 0
#  av - ?              samples: 0
#  wd - wind direction in compass degrees
#  wg - wind gust m/s
#  ws - wind speed m/s
#
# temperature/humidity sensor (0x84)
#  htr - ?             samples: 0, 1
#  cz - ?              samples: 3, 2
#  oh - humidity %
#  ttr - ?             samples: 0, 1
#  ot - temperature C
#
# rain sensor (0x82)
#  rro - ?             samples: 0
#  rr - rain rate? mm/hr
#  rfa - rain fall accumulated? mm

# resulting raw packet format:
#   <observation_name>.<ch><rid>.<mac> : value

class LW30x(Consumer):

    def __init__(self, **stn_dict):
        super(LW30x, self).__init__(LW30x.Parser(), **stn_dict)

    class Parser(Consumer.Parser):

        def __init__(self):
            self._last_rain = None

        FLOATS = ['baro', 'ot', 'oh', 'ws', 'wg', 'wd', 'rr', 'rfa', 'uv']

        # map database fields to sensor tuples
        DEFAULT_SENSOR_MAP = {
            'barometer': 'baro..*', # FIXME: should this be pressure?
            'outTemp': 'ot.?*.*',
            'outHumidity': 'oh.?*.*',
            'windSpeed': 'ws.?*.*',
            'windGust': 'wg.?*.*',
            'windDir': 'wd.?*.*',
            'rainRate': 'rr.?*.*',
            'rain': 'rain.?*.*',
            'UV': 'uv.?*.*'}

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
            except ValueError, e:
                logerr("parse failed for %s: %s" % (s, e))

            # convert accumulated rain to rain delta
            if 'rfa' in pkt:
                pkt['rain'] = self._delta_rain(pkt['rfa'], self._last_rain)
                self._last_rain = pkt['rfa']

            # tag each observation with identifiers:
            #   observation.<channel><sensor_id>.<bridge_id>
            packet = {'dateTime': int(time.time() + 0.5),
                      'usUnits': weewx.METRICWX}
            _id = '%s%s.%s' % (pkt.get('ch', ''), pkt.get('rid', ''),
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
What follows is the dissection using conventions from mycal.

Each request has a header HTTP_IDENTIFY that specifys the request type,
gateway identification, and key.  For example:

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

00:01 ?

00:10 gateway power up

00:20 gateway unregistered

00:30 gateway finished registration

00:70 gateway ping

01:00 weather station ping
  41 46 30 67 39

01:01 weather station data

01:14 weather station registration verification

7f:10 weather station registration

00:14 ?

Data packets

This is the decoding of the data, based on mycal description:

start nyb  nybble encoding description
00H   0    2      byte     Record type, always 01
01H   2    4      ???      Unknown
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
"""

# resulting raw packet format:
#   <observation_name>..<mac> : value

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

    station_serial = '0' * 16
    ping_interval = 60 # how often gateway should ping the server, in seconds
    sensor_interval = 300 # seconds between data packets (5m is default)
    history_interval = 3
    lcd_brightness = 4
    server_name = 'box.weatherdirect.com'
    
    def __init__(self, **stn_dict):
        stn_dict['mode'] = 'listen' # sniffing not supported for this hardware
        super(GW1000U, self).__init__(
            GW1000U.Parser(), handler=GW1000U.Handler, **stn_dict)
        GW1000U.station_serial = stn_dict.get('serial', '0' * 16)
        if len(GW1000U.station_serial) != 16:
            raise weewx.ViolatedPrecondition("serial number must be 16 characters")
        loginf('using serial number %s' % GW1000U.station_serial)
        GW1000U.sensor_interval = stn_dict.get('sensor_interval', 300)
        loginf('using sensor interval %ss' % GW1000U.sensor_interval)
        GW1000U.history_interval = stn_dict.get('history_interval', 3)
        if GW1000U.history_interval not in GW1000U.HISTORY_INTERVALS:
            raise weewx.ViolatedPrecondition("history interval must be 0-7")
        loginf('using history interval %s (%s)' %
               (GW1000U.history_interval,
                GW1000U.HISTORY_INTERVALS.get(GW1000U.history_interval)))

    @staticmethod
    def encode_ts(ts):
        # encode a 12-character time stamp into 6 bytes
        tstr = time.strftime("%H%M%S%d%m%y", time.localtime(ts))
        s = ''
        for x in range(0, 6):
            s += chr(GW1000U.encode_bcd(tstr[x*2: x*2+2]))
        return s

    @staticmethod
    def decode_serial(data):
        return binascii.hexlify(data)

    @staticmethod
    def encode_serial(sn):
        # encode a 16-character serial number into 8 bytes
        return binascii.unhexlify(sn)

    @staticmethod
    def encode_bcd(x):
        x = int(x)
        msb = x / 10
        lsb = x % 10
        if msb > 10:
            msb = 10
        return ((msb << 4) | (lsb & 0xf))


    class Handler(Consumer.Handler):

        last_history_address = 0
        
        def handle(self):
            Consumer.Handler.handle(self)
            flags = '00:00'
            response = ''
            parts = self.headers.get('HTTP_IDENTIFY', '').split(':')
            if len(parts) == 4:
                (mac, id1, key, id2) = parts
                pkt_type = ("%s:%s" % (id1, id2)).upper()
                length = int(self.headers.get('Content-Length', 0))
                data = self.rfile.read(length) if length else ''
                logdbg("recv: %s:%s %s %s %s" %
                       (id1, id2, mac, key, _fmt_bytes(data)))
                if pkt_type == '00:10':
                    # power up for unregistered gateway
                    flags = '10:00'
                    loginf("power up from gateway with mac %s" % mac)
                elif pkt_type == '00:20':
                    # push button registration
                    flags = '20:00' # sometimes replies with 20:01
                    response = self._create_gateway_reg_response()
                    loginf("registration from gateway with mac %s" % mac)
                elif pkt_type == '00:30':
                    # received after response to 00:70 packet
                    flags = '30:00'
                elif pkt_type == '00:70':
                    # gateway ping
                    flags = '70:00'
                    response = self._create_gateway_ping_response()
                elif pkt_type == '7F:10':
                    # station registration.  station sends its serial number
                    # as the first 8 digits of the packet.  if it is the
                    # default serial number, there should be 13 bytes.  ignore
                    # requests from anything other than the known serial.
                    if data and len(data) >= 8:
                        sn = GW1000U.decode_serial(data[0:8])
                        if sn == GW1000U.station_serial:
                            flags = '14:00'
                            response = self._create_station_reg_response()
                        else:
                            loginf("ignore registration from serial %s" % sn)
                    else:
                        loginf('cannot extract serial from packet: %s'
                               % _fmt_bytes(data))
                elif pkt_type == '00:14':
                    # reply after 7f:10 packet.  station sends 14 bytes.
                    flags = '1C:00'
                elif pkt_type == '01:14':
                    # station sends 14 bytes of data.  data is new serial in
                    # same format as 7f:10 with one extra byte on the end.
                    flags = '1C:00'
                elif pkt_type == '01:00':
                    # weather station ping.  station sends 5 bytes.
                    flags = '14:01'
                    response = self._create_station_ping_response()
                elif pkt_type == '01:01':
                    # data packet - current or history
                    if len(data) == 197:
                        Consumer.queue.put({'mac': mac,
                                            'data': binascii.b2a_hex(data)})
                    else:
                        loginf('ignore data packet: unexpected length %s'
                               % len(data))
                else:
                    loginf("unknown packet type %s" % pkt_type)
            elif 'HTTP_IDENTIFY' not in self.headers:
                logdbg('no HTTP_IDENTIFY in headers')
            else:
                logdbg("unknown format for HTTP_IDENTIFY: '%s'" %
                       self.headers.get('HTTP_IDENTIFY', ''))

            logdbg("send: %s %s" % (flags, _fmt_bytes(response)))

            self.send_response(200)
            self.send_header('HTTP_FLAGS', flags)
            self.send_header('Server', 'Microsoft-II/6.0')
            self.send_header('X-Powered-By', 'ASP.NET')
            self.send_header('X-ApsNet-Version', '2.0.50727')
            self.send_header('Cache-Control', 'private')
            self.send_header('Content-Length', len(response))
            self.send_header('Content-Type', 'application/octet-stream')
            self.end_headers()
            self.wfile.write(response)

        @staticmethod
        def _create_gateway_reg_response():
            server = GW1000U.server_name
            return ''.join(
                [chr(0) * 8, # used to generate a new key
                 server.ljust(0x98, chr(0)),
                 ("%s%s%s" % (server, chr(0), server)).ljust(0x56, chr(0)),
                 chr(0) * 5,
                 chr(0xff)])

        @staticmethod
        def _create_gateway_ping_response():
            # 18-byte reply.  last two bytes are the ping interval in seconds.
            interval = GW1000U.ping_interval
            hi = interval / 256
            lo = interval % 256
            return ''.join([chr(0xff) * 4, chr(0) * 12, chr(hi), chr(lo)])

        # FIXME: the reg_response and ping_response look awfully similar.
        # can they be replaced with a single response?
        
        @staticmethod
        def _create_station_reg_response():
            # reply to station registration request with 38 bytes of data.
            # this reply can set the serial number of the weather station if
            # the station has the default serial number of 0102030405060708.
            # once changed, the serial number cannot be modified, so it might
            # be advisable to register with lacrosse first so that if you ever
            # want to go back to the lacross service you could.
            sn = GW1000U.station_serial
            payload = ''.join(
                [chr(1),
                 GW1000U.encode_serial(sn), # 8 bytes
                 chr(0) + chr(0x30) + chr(0) + chr(0xf) + chr(0) + chr(0) + chr(0) + chr(0xf) + chr(0) + chr(0) + chr(0) + chr(0x77) + chr(0),
                 chr(0xe) + chr(0xff), # skydriver calls this epoch
                 GW1000U.encode_ts(int(time.time())), # 6 bytes
                 chr(0x53),
                 chr(0x7), # unknown
                 chr(GW1000U.lcd_brightness), # LCD brightness
                 chr(0) + chr(0), # beep weather station
                 chr(0), # unknown
                 chr(0x7)]) # unknown - 0x7 is from lacrosse alerts
            cs = GW1000U.Handler.checksum8(payload)
            return payload + chr(cs)

        @staticmethod
        def _create_station_ping_response():
            # reply with 38 bytes of data
            sn = GW1000U.station_serial
            hi = GW1000U.Handler.last_history_address / 256
            lo = GW1000U.Handler.last_history_address % 256
            interval = GW1000U.sensor_interval / 60
            payload = ''.join(
                [chr(1),
                 GW1000U.encode_serial(sn), # 8 bytes
                 chr(0) + chr(0x32) + chr(0) + chr(0xb) + chr(0) + chr(0) + chr(0) + chr(0xf) + chr(0) + chr(0) + chr(0),
                 chr(interval - 1), # byte 0x14 (0x3)
                 chr(0),
                 chr(hi) + chr(lo), # last_history_address 2 bytes (0x3e 0xde)
                 GW1000U.encode_ts(int(time.time())), # 6 bytes
                 chr(0x53),
                 chr(GW1000U.history_interval), # byte 0x1f (0x7)
                 chr(GW1000U.lcd_brightness), # byte 0x20 (0x4)
                 chr(0) + chr(0),
                 chr(0)])
            cs = GW1000U.Handler.checksum16(payload) + 7
            return payload + chr(cs >> 8) + chr(cs & 0xff)

        @staticmethod
        def checksum8(x):
            n = 0
            for c in x:
                n += int(c, 16)
            return n & 0xff

        @staticmethod
        def checksum16(x):
            n = 0
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
            'windGust': 'wind_gust..*',
            'windDir': 'wind_dir..*',
            'rain': 'rain..*',
            'rxCheckPercent': 'rf_signal_strength..*'}

        def __init__(self):
            self._last_rain = None

        @staticmethod
        def parse_identifiers(payload):
            return {'bridge_id': payload.get('mac')}

        def parse(self, payload):
            mac = payload.get('mac')
            s = payload.get('data', '')
            # this expects a string of hex characters.  the data packet length
            # is 197, so the hex string should be 394 characters.
            pkt = dict()
            if len(s) != 394:
                return pkt
            pkt['record_type'] = int(s[0:2], 16) # always 01
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
                pkt['wind_gust'] = self.to_windspeed(s, 320) # kph
            else:
                pkt['wind_speed'] = None
                pkt['wind_dir'] = None
                pkt['wind_gust'] = None
            pkt['barometer'] = self.to_pressure(s, 339) # mbar

            # now tag each value with identifiers
            packet = {'dateTime': int(time.time() + 0.5),
                      'usUnits': weewx.METRIC}
            for n in pkt:
                packet["%s..%s" % (n, mac)] = pkt[n]
            return packet

        @staticmethod
        def map_to_fields(pkt, sensor_map):
            if sensor_map is None:
                sensor_map = GW1000U.Parser.DEFAULT_SENSOR_MAP
            return Consumer.Parser.map_to_fields(pkt, sensor_map)

        @staticmethod
        def to_temperature(x, idx):
            # returns temperature in degree C
            s = x[idx:idx+3]
            if s.lower() == 'aaa' or s.lower() == 'aa3':
                return None
            return GW1000U.Parser.bcd2int(s) / 10.0 - 40.0

        @staticmethod
        def to_hum(x, idx):
            # returns humidity in percent
            return GW1000U.Parser.bcd2int(x[idx:idx+2])

        @staticmethod
        def to_windspeed(x, idx):
            # returns windspeed in km per hour
            return GW1000U.Parser.bin2int(x[idx:idx+4]) / 100.0

        @staticmethod
        def to_winddir(x, idx):
            # returns compass degrees in [0,360]
            return int(x[idx:idx+1], 16) * 22.5

        @staticmethod
        def to_pressure(x, idx):
            # returns barometric pressure in mbar
            return GW1000U.Parser.bcd2int(x[idx:idx+5]) / 10.0

        @staticmethod
        def to_rainfall(x, idx, n=7):
            # each tip is 0.01", returns rain total in mm
            v = GW1000U.Parser.bcd2int(x[idx:idx+n])
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
        

class InterceptorConfigurationEditor(weewx.drivers.AbstractConfEditor):
    @property
    def default_stanza(self):
        return """
[Interceptor]
    # This section is for the network traffic interceptor driver.

    # The driver to use:
    driver = user.interceptor

    # Specify the hardware device to capture.  Options include:
    #   acurite-bridge - acurite internet bridge
    #   observer - fine offset WH2600/HP1000/HP1003, aka 'observer'
    #   lw30x - oregon scientific LW301/LW302
    #   lacrosse-bridge - lacrosse GW1000U/C84612 internet bridge
    device_type = acurite-bridge

    # For acurite, fine offset, and oregon scientific hardware, the driver
    # can sniff packets directly or run a socket server that listens for
    # connections.  Packet sniffing requires the installation of the pcap
    # python module.  The default mode is to listen using a socket server.
    # Options are 'listen' and 'sniff'.
    #mode = sniff

    # When listening, specify at least a port on which to bind.
    #address = 127.0.0.1
    #port = 80

    # When sniffing, specify a network interface and a pcap filter.
    #iface = eth0
    #filter = src 192.168.4.12 and dst port 80

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
        print "Specify the type of device whose data will be captured"
        device_type = self._prompt(
            'device_type', 'acurite-bridge',
            ['acurite-bridge', 'observer', 'lw30x', 'lacrosse-bridge'])
        return {'device_type': device_type}


class InterceptorDriver(weewx.drivers.AbstractDevice):
    DEVICE_TYPES = {
        'acurite-bridge': AcuriteBridge,
        'observer': Observer,
        'observerip': Observer,
        'lw30x': LW30x,
        'lacrosse-bridge': GW1000U}

    def __init__(self, **stn_dict):
        loginf('driver version is %s' % DRIVER_VERSION)
        stn_dict.pop('driver')
        self._device_type = stn_dict.pop('device_type', 'acurite-bridge')
        if not self._device_type in self.DEVICE_TYPES:
            raise Exception("unsupported device type '%s'" % self._device_type)
        loginf('device type: %s' % self._device_type)
        self._obs_map = stn_dict.pop('sensor_map', None)
        loginf('sensor map: %s' % self._obs_map)
        self._device = self.DEVICE_TYPES.get(self._device_type)(**stn_dict)
        self._server_thread = threading.Thread(target=self._device.run_server)
        self._server_thread.setDaemon(True)
        self._server_thread.setName('ServerThread')
        self._server_thread.start()

    def closePort(self):
        loginf('shutting down server thread')
        self._device.shutdown_server()
        self._server_thread.join(20.0)
        if self._server_thread.isAlive():
            logerr('unable to shut down server thread')

    def hardware_name(self):
        return self._device_type

    def genLoopPackets(self):
        while True:
            try:
                data = self._device.get_queue().get(True, 10)
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

    syslog.openlog('interceptor', syslog.LOG_PID | syslog.LOG_CONS)
    syslog.setlogmask(syslog.LOG_UPTO(syslog.LOG_INFO))

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

    (options, args) = parser.parse_args()

    debug = False
    if options.debug:
        syslog.setlogmask(syslog.LOG_UPTO(syslog.LOG_DEBUG))
        debug = True

    if not options.device_type in InterceptorDriver.DEVICE_TYPES:
        raise Exception("unsupported device type '%s'.  options include %s" %
                        (options.device_type,
                         ', '.join(InterceptorDriver.DEVICE_TYPES.keys())))
    device = InterceptorDriver.DEVICE_TYPES.get(options.device_type)(
        mode=options.mode,
        iface=options.iface, filter=options.filter,
        address=options.addr, port=options.port)

    server_thread = threading.Thread(target=device.run_server)
    server_thread.setDaemon(True)
    server_thread.setName('ServerThread')
    server_thread.start()

    while True:
        try:
            _data = device.get_queue().get(True, 10)
            print 'identifiers:', device.parser.parse_identifiers(_data)
            if debug:
                print 'raw data: %s' % _data
                _pkt = device.parser.parse(_data)
                print 'raw packet: %s' % _pkt
                _pkt = device.parser.map_to_fields(_pkt, None)
                print 'mapped packet: %s' % _pkt
        except Queue.Empty:
            logdbg("empty queue")

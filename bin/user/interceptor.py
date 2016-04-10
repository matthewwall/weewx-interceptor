#!/usr/bin/env python
# Copyright 2016 Matthew Wall, all rights reserved
"""
This driver runs a simple web server designed to receive data directly from an
internet weather reporting device such as the Acurite internet bridge, the
LaCross GW1000U, the Oregon Scientific LW301/302, or the FineOffset ObserverIP.

Thanks to Pat at obrienlabs.net for the observerip parsing
  http://obrienlabs.net/redirecting-weather-station-data-from-observerip/

Thanks to rich of modern toil and george nincehelser for acurite parsing
  http://moderntoil.com/?p=794
  http://nincehelser.com/ipwx/

Thanks to sergei and weibi for the LW301/LW302 samples
  http://www.silent-gardens.com/blog/shark-hunt-lw301/

Thanks to skydvrz, mycal, kennkong for publishing results of their lacross work
  http://www.wxforum.net/index.php?topic=14299.0
  https://github.com/lowerpower/LaCrosse
  https://github.com/kennkong/Weather-ERF-Gateway-1000U
"""

# FIXME: automatically detect the traffic type
# FIXME: handle traffic from multiple types of devices
# FIXME: default acurite mapping confuses multiple tower sensors
# FIXME: does observerip ever post in non-us units?

from __future__ import with_statement
import BaseHTTPServer
import SocketServer
import Queue
import calendar
import syslog
import threading
import time

import weewx.drivers

DRIVER_NAME = 'Interceptor'
DRIVER_VERSION = '0.4'

DEFAULT_PORT = 80
DEFAULT_ADDR = ''
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


class Consumer(object):
    queue = Queue.Queue()

    def __init__(self, server_address, handler, parser):
        self.parser = parser
        self._server = Consumer.Server(server_address, handler)

    def run_server(self):
        self._server.serve_forever()

    def shutdown(self):
        self._server.shutdown()

    def get_queue(self):
        return Consumer.queue

    class Server(SocketServer.TCPServer):
        daemon_threads = True
        allow_reuse_address = True

        def __init__(self, server_address, handler):
            SocketServer.TCPServer.__init__(self, server_address, handler)

    class Handler(BaseHTTPServer.BaseHTTPRequestHandler):

        def get_response(self):
            return 'OK'

        def do_POST(self):
            length = int(self.headers["Content-Length"])
            data = str(self.rfile.read(length))
            logdbg('POST: %s' % data)
            Consumer.queue.put(data)
            response = bytes(self.get_response())
            self.send_response(200)
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)

        # do not spew messages on every connection
        def log_message(self, format, *args):
            pass

    class Parser(object):

        @staticmethod
        def parse_identifiers(s):
            return None, None, None

        def parse(self, s):
            return dict()

        @staticmethod
        def map_to_fields(pkt, sensor_map):
            if sensor_map is None:
                return pkt
            packet = {'dateTime': pkt['dateTime'], 'usUnits': pkt['usUnits']}
            for n in sensor_map:
                label = Consumer.Parser._find_match(n, pkt.keys())
                if label:
                    packet[sensor_map[n]] = pkt.get(label)
            return packet

        @staticmethod
        def _find_match(pattern, keylist):
            pparts = pattern.split('.')
            if len(pparts) != 3:
                logerr("bogus pattern '%s'" % pattern)
                return None
            match = None
            for k in keylist:
                kparts = k.split('.')
                if (Consumer.Parser._part_match(pparts[0], kparts[0]) and
                    Consumer.Parser._part_match(pparts[1], kparts[1]) and
                    Consumer.Parser._part_match(pparts[2], kparts[2])):
                    match = k
            return match

        @staticmethod
        def _part_match(pattern, value):
            if pattern == value:
                return True
            if pattern == '*' and value:
                return True
            return False

        @staticmethod
        def _delta_rain(rain, last_rain):
            if last_rain is None:
                return None
            if rain < last_rain:
                return None
            return rain - last_rain


class AcuriteBridge(Consumer):

    def __init__(self, server_address):
        super(AcuriteBridge, self).__init__(
            server_address, AcuriteBridge.Handler, AcuriteBridge.Parser())

    class Handler(Consumer.Handler):

        def get_response(self):
            return '{ "success": 1, "checkversion": "126" }'

    class Parser(Consumer.Parser):
        # sample output from a bridge with 3 t/h sensors and 1 5-in-1
        # id=X&mt=pressure&C1=452D&C2=0D7F&C3=010D&C4=0330&C5=8472&C6=1858&C7=09C4&A=07&B=1B&C=06&D=09&PR=91CA&TR=8270
        # id=X&sensor=02004&mt=5N1x31&windspeed=A001660000&winddir=8&rainfall=A0000000&battery=normal&rssi=3
        # id=X&sensor=02004&mt=5N1x38&windspeed=A001890000&humidity=A0280&temperature=A014722222&battery=normal&rssi=3
        # id=X&sensor=06022&mt=tower&humidity=A0270&temperature=A020100000&battery=normal&rssi=3
        # id=X&sensor=05961&mt=tower&humidity=A0300&temperature=A017400000&battery=normal&rssi=3
        # id=X&sensor=14074&mt=tower&humidity=A0300&temperature=A021500000&battery=normal&rssi=4

        DEFAULT_SENSOR_MAP = {
            'pressure..*': 'pressure',
            'temperature..*': 'inTemp',
            'temperature.*.*': 'outTemp',
            'humidity.*.*': 'outHumidity',
            'windspeed.*.*': 'windSpeed',
            'winddir.*.*': 'windDir',
            'rainfall.*.*': 'rain'}

        # this is *not* the same as the acurite console mapping!
        IDX_TO_DEG = {5: 0.0, 7: 22.5, 3: 45.0, 1: 67.5, 9: 90.0, 11: 112.5,
                      15: 135.0, 13: 157.5, 12: 180.0, 14: 202.5, 10: 225.0,
                      8: 247.5, 0: 270.0, 2: 292.5, 6: 315.0, 4: 337.5}

        @staticmethod
        def parse_identifiers(s):
            bridge_id = sensor_id = sensor_type = None
            parts = s.split('&')
            for x in parts:
                (n, v) = x.split('=')
                if n == 'id':
                    bridge_id = v
                if n == 'sensor':
                    sensor_id = v
                if n == 'mt':
                    sensor_type = v
            return bridge_id, sensor_id, sensor_type

        def parse(self, s):
            pkt = dict()
            parts = s.split('&')
            for x in parts:
                (n, v) = x.split('=')
                if n == 'id':
                    pkt['bridge_id'] = v
                elif n == 'sensor':
                    pkt['sensor_id'] = v
                elif n == 'mt':
                    pkt['sensor_type'] = v
                elif hasattr(AcuriteBridge.Parser, 'decode_%s' % n):
                    try:
                        func = 'decode_%s' % n
                        pkt[n] = getattr(AcuriteBridge.Parser, func)(v)
                    except (ValueError, IndexError), e:
                        logerr("decode failed for %s '%s': %s" % (n, v, e))
                elif n in ['C1', 'C2', 'C3', 'C4', 'C5', 'C6', 'C7',
                           'A', 'B', 'C', 'D', 'PR', 'TR']:
                    pkt[n] = v
                else:
                    loginf("unknown element '%s' with value '%s'" % (n, v))

            # if this is a pressure packet, calculate the pressure
            if pkt['sensor_type'] == 'pressure':
                pkt['pressure'], pkt['temperature'] = AcuriteBridge.Parser.decode_pressure(pkt)

            # now tag each value with identifiers
            packet = {'dateTime': int(time.time() + 0.5),
                      'usUnits': weewx.METRICWX}
            label_id = '%s.%s' % (
                pkt.get('sensor_id', ''), pkt.get('bridge_id', ''))
            for n in pkt:
                packet["%s.%s" % (n, label_id)] = pkt[n]
            return packet

        @staticmethod
        def map_to_fields(pkt, sensor_map):
            if sensor_map is None:
                sensor_map = AcuriteBridge.Parser.DEFAULT_SENSOR_MAP
            return Consumer.Parser.map_to_fields(pkt, sensor_map)

        @staticmethod
        def decode_battery(s):
            return 1 if s != 'normal' else 0

        @staticmethod
        def decode_rssi(s):
            return int(s)

        @staticmethod
        def decode_humidity(s):
            # humidity in [0, 100]
            return float(s[2:5]) / 10.0

        @staticmethod
        def decode_temperature(s):
            # temperature in degree C
            return float(s[1:5]) / 10.0

        @staticmethod
        def decode_windspeed(s):
            # wind speed in meters per second
            return float(s[2:5]) / 10.0

        @staticmethod
        def decode_winddir(s):
            # wind direction in compass degrees [0, 360]
            return AcuriteBridge.Parser.IDX_TO_DEG.get(int(s, 16))

        @staticmethod
        def decode_rainfall(s):
            # rainfall since last report, in mm
            return float(s[2:8]) / 1000.0

        @staticmethod
        def decode_pressure(pkt):
            # pressure in mbar, temperature in degree C
            c1 = int(pkt['C1'], 16)
            c2 = int(pkt['C2'], 16)
            c3 = int(pkt['C3'], 16)
            c4 = int(pkt['C4'], 16)
            c5 = int(pkt['C5'], 16)
            c6 = int(pkt['C6'], 16)
            c7 = int(pkt['C7'], 16)
            a = int(pkt['A'], 16)
            b = int(pkt['B'], 16)
            c = int(pkt['C'], 16)
            d = int(pkt['D'], 16)
            pr = int(pkt['PR'], 16)
            tr = int(pkt['TR'], 16)
            if (0x100 <= c1 <= 0xffff and
                0x0 <= c2 <= 0x1fff and
                0x0 <= c3 <= 0x400 and
                0x0 <= c4 <= 0x1000 and
                0x1000 <= c5 <= 0xffff and
                0x0 <= c6 <= 0x4000 and
                0x960 <= c7 <= 0xa28 and
                0x01 <= a <= 0x3f and 0x01 <= b <= 0x3f and
                0x01 <= c <= 0x0f and 0x01 <= d <= 0x0f):
                return AcuriteBridge.Parser.decode_HP03S(
                    c1, c2, c3, c4, c5, c6, c7, a, b, c, d, pr, tr)
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


class ObserverIP(Consumer):

    def __init__(self, server_address):
        super(ObserverIP, self).__init__(
            server_address, Consumer.Handler, ObserverIP.Parser())

    class Parser(Consumer.Parser):

        def __init__(self):
            self._last_rain = None

        # sample output from an observer ip
        # ID=XXXX&PASSWORD=PPPPPPPP&tempf=43.3&humidity=98&dewptf=42.8&windchil
        # lf=43.3&winddir=129&windspeedmph=0.00&windgustmph=0.00&rainin=0.00&da
        # ilyrainin=0.04&weeklyrainin=0.04&monthlyrainin=0.91&yearlyrainin=0.91
        # &solarradiation=0.00&UV=0&indoortempf=76.5&indoorhumidity=49&baromin=
        # 29.05&lowbatt=0&dateutc=2016-1-4%2021:2:35&softwaretype=Weather%20log
        # ger%20V2.1.9&action=updateraw&realtime=1&rtfreq=5

        def parse(self, s):
            pkt = dict()
            try:
                parts = s.split('&')
                data = dict([x.split('=') for x in parts])
                pkt['dateTime'] = decode_datetime(data['dateutc'])
                pkt['usUnits'] = weewx.US
                pkt['inTemp'] = decode_float(data['indoortempf'])
                pkt['inHumidity'] = decode_float(data['indoorhumidity'])
                pkt['outTemp'] = decode_float(data['tempf'])
                pkt['outHumidity'] = decode_float(data['humidity'])
                pkt['barometer'] = decode_float(data['baromin'])
                pkt['rain'] = self._delta_rain(data['rainin'], self._last_rain)
                self._last_rain = data['rainin']
                pkt['windDir'] = decode_float(data['windDir'])
                pkt['windSpeed'] = decode_float(data['windSpeed'])
                pkt['windGust'] = decode_float(data['windgustmph'])
                pkt['radiation'] = decode_float(data['solarradiation'])
                pkt['txBatteryStatus'] = decode_float(data['lowbatt'])
            except ValueError, e:
                logerr("parse failed for %s: %s" % (s, e))
            return pkt

        @staticmethod
        def map_to_fields(pkt, sensor_map):
            return pkt

        @staticmethod
        def decode_datetime(s):
            s = s.replace("%20", " ")
            ts = time.strptime(s, "%Y-%m-%d %H:%M:%S")
            return calendar.timegm(ts)

        @staticmethod
        def decode_float(x):
            return None if x is None else float(x)


class LW30x(Consumer):

    def __init__(self, server_address):
        super(LW30x, self).__init__(
            server_address, Consumer.Handler, LW30x.Parser())

    class Parser(Consumer.Parser):
        # sample output from a LW301
        # mac=XX&id=8e&rid=af&pwr=0&or=0&uvh=0&uv=125&ch=1&p=1
        # mac=XX&id=90&rid=9d&pwr=0&gw=0&av=0&wd=315&wg=1.9&ws=1.1&ch=1&p=1
        # mac=XX&id=84&rid=20&pwr=0&htr=0&cz=3&oh=90&ttr=0&ot=18.9&ch=1&p=1
        # mac=XX&id=82&rid=1d&pwr=0&rro=0&rr=0.00&rfa=5.114&ch=1&p=1
        # mac=XX&id=c2&pv=0&lb=0&ac=0&reg=1803&lost=0000&baro=806&ptr=0&wfor=3&p=1
        # mac=XX&id=90&rid=9d&pwr=0&gw=0&av=0&wd=247&wg=1.9&ws=1.1&ch=1&p=1

        DEFAULT_SENSOR_MAP = {
            'baro..*': 'barometer',
            'ot.*.*': 'outTemp',
            'oh.*.*': 'outHumidity',
            'ws.*.*': 'windSpeed',
            'wg.*.*': 'windGust',
            'wd.*.*': 'windDir',
            'rfa.*.*': 'rain',
            'uv.*.*': 'uv'}

        @staticmethod
        def parse_identifiers(s):
            bridge_id = sensor_id = sensor_type = None
            parts = s.split('&')
            for x in parts:
                (n, v) = x.split('=')
                if n == 'mac':
                    bridge_id = v
                if n == 'rid':
                    sensor_id = v
                if n == 'id':
                    sensor_type = v
            return bridge_id, sensor_id, sensor_type

        def parse(self, s):
            pkt = dict()
            parts = s.split('&')
            data = dict([x.split('=') for x in parts])
            try:
                pkt['dateTime'] = int(time.time() + 0.5)
                pkt['mac'] = data['mac']
                pkt['id'] = data['id']
                pkt['rid'] = data['rid']
                pkt['pwr'] = data['pwr']
                pkt['channel'] = data['ch']
                pkt['p'] = data['p']

                # uv sensor
                pkt['or'] = data['or']
                pkt['uvh'] = data['uvh']
                pkt['uv'] = data['uv'] # index? what is range?

                # wind sensor
                pkt['gw'] = data['gw']
                pkt['av'] = data['av']
                pkt['winddir'] = decode_float(data['wd']) # compass degrees
                pkt['windgust'] = decode_float(data['wg']) # m/s
                pkt['windspeed'] = decode_float(data['ws']) # m/s

                # temperature/humidity sensor
                pkt['htr'] = data['htr']
                pkt['cz'] = data['cz']
                pkt['humidity'] = decode_float(data['oh']) # %
                pkt['ttr'] = data['ttr']
                pkt['temperature'] = decode_float(data['ot']) # C

                # rain sensor
                pkt['rro'] = data['rro']
                pkt['rainRate'] = decode_float(data['rr']) # mm/hr ?
                pkt['rain'] = decode_float(data['rfa']) # mm

                # pressure sensor
                pkt['pv'] = data['pv']
                pkt['lb'] = data['lb']
                pkt['ac'] = data['ac']
                # known sensors
                # 0803: wind, t/h, rain
                # 1803: wind, t/h, rain, uv
                pkt['reg'] = data['reg']
                # lost contact?
                pkt['lost'] = data['lost']
                pkt['barometer'] = decode_float(data['baro']) # mbar
                pkt['ptr'] = data['ptr']
                # forecast:
                # 0=partly_cloudy, 1=sunny, 2=cloudy, 3=rainy, 4=snowy
                pkt['forecast'] = data['wfor']
            except ValueError, e:
                logerr("parse failed for %s: %s" % (s, e))

            # now tag each value identifiers
            packet = {'dateTime': pkt['dateTime'], 'usUnits': weewx.METRICWX}
            label_id = '%s.%s' % (pkt.get('rid', ''), pkt.get('mac', ''))
            for n in pkt:
                packet["%s.%s" % (n, label_id)] = pkt[n]
            return packet

        @staticmethod
        def map_to_fields(pkt, sensor_map):
            if sensor_map is None:
                sensor_map = LW30x.Parser.DEFAULT_SENSOR_MAP
            return Consumer.Parser.map_to_fields(pkt, sensor_map)

        @staticmethod
        def decode_datetime(s):
            s = s.replace("%20", " ")
            ts = time.strptime(s, "%Y-%m-%d %H:%M:%S")
            return calendar.timegm(ts)

        @staticmethod
        def decode_float(x):
            return None if x is None else float(x)


class GW1000U(Consumer):

    station_serial = 0

    def __init__(self, server_address):
        super(GW1000U, self).__init__(
            server_address, GW1000U.Handler, GW1000U.Parser())

    class Handler(Consumer.Handler):

        def do_POST(self):
            flags = '00:00'
            response = ''
            ctype = True
            parts = self.headers.get('HTTP_IDENTIFY', '').split(':')
            if len(parts) == 4:
                (mac, id1, key, id2) = parts
                pkt_type = ("%s:%s" % (id1, id2)).upper()
                length = int(self.headers.get('Content-Length', 0))
                data = str(self.rfile.read(length)) if length else ''
                logdbg("POST: %s %s %s:%s: %s" % (mac, key, id1, id2, data))
                if pkt_type == '00:10':
                    # power up packet for unregistered gateway
                    flags = '10:00'
                elif pkt_type == '00:20':
                    # push button registration packet
                    flags = '20:00'
                    response = self._create_gateway_reg_response()
                elif pkt_type == '00:30':
                    # received after response to 00:70 packet
                    flags = '30:00'
                elif pkt_type == '00:70':
                    # gateway ping
                    flags = '70:00'
                    response = self._create_gateway_ping_response()
                elif pkt_type == '7F:10':
                    # station registration packet
                    sn = self._extract_serial(data)
                    if sn == GW1000U.station_serial:
                        flags = '14:00'
                        response = self._create_station_reg_response(sn)
                elif pkt_type == '00:14' or pkt_type == '01:14':
                    # reply after 7f:10 packet
                    flags = '1C:00'
                elif pkt_type == '01:00':
                    # weather station ping
                    flags = '14:01'
                    response = self._create_station_ping_response(GW1000U.station_serial)
                elif pkt_type == '01:01':
                    # data packet - current or history
                    Consumer.queue.put(data)
                else:
                    loginf("unknown packet type %s" % pkt_type)
                    ctype = False
            elif 'HTTP_IDENTIFY' not in self.headers:
                logdbg('no HTTP_IDENTIFY in headers')
            else:
                logdbg("unknown format for HTTP_IDENTIFY: '%s'" %
                       self.headers.get('HTTP_IDENTIFY', ''))

            logdbg("http_flags: %s" % flags)
            logdbg("response: %s" % response)

            #self.send_response(200) # FIXME: is this necessary?
            self.send_header('HTTP_FLAGS', flags)
            self.send_header('Server', 'Microsoft-II/6.0')
            self.send_header('X-Powered-By', 'ASP.NET')
            self.send_header('X-ApsNet-Version', '2.0.50727')
            self.send_header('Cache-Control', 'private')
            self.send_header('Content-Length', len(response))
            if ctype:
                self.send_header('Content-Type', 'application/octet-stream')
            self.end_headers()
            self.wfile.write(response)

        def _extract_serial(self, data):
            if data and len(data) >= 8:
                return data[0:8]
            return None

        def _create_gateway_reg_response(self):
            server = 'box.weatherdirect.com'
            return ''.join(
                [chr(0) * 8,
                 server.ljust(0x98, chr(0)),
                 ("%s%s%s" % (server, chr(0), server)).ljust(0x56, chr(0)),
                 chr(0) * 5,
                 chr(0xff)])

        def _create_gateway_ping_response(self):
            # 0xf0 = 240 seconds
            return ''.join([chr(0xff) * 4, chr(0) * 12, chr(0), chr(0xf0)])

        def _create_station_reg_response(self, serial):
            now = int(time.time())
            payload = ''.join(
                [chr(1),
                 serial,
                 chr(0) + chr(0x30) + chr(0) + chr(0xf) + chr(0) + chr(0) + chr(0) + chr(0xf) + chr(0) + chr(0) + chr(0) + chr(0x77) + chr(0) + chr(0xe) + chr(0xff),
                 chr(bin2bcd(date('h', now))) + chr(bin2bcd(date('i', now))) + chr(bin2bcd(date('s', now))), # hour, minute, second
                 chr(bin2bcd(date('d', now))) + chr(bin2bcd(date('m', now))) + chr(bin2bcd(date('y', now))), # day, month, year                 
                 chr(0x53),
                 chr(0x7), # unknown
                 chr(0x5), # LCD brightness
                 chr(0) + chr(0), # beep weather station
                 chr(0), # unknown
                 chr(0x7)]) # unknown
            cs = self.checksum8(payload))
            return payload + chr(cs)

        def _create_station_ping_response(self, serial):
            now = int(time.time())
            payload = ''.join(
                [chr(1),
                 serial, # 8 bytes
                 chr(0) + chr(0x32) + chr(0) + chr(0xb) + chr(0) + chr(0) + chr(0) + chr(0xf) + chr(0) + chr(0) + chr(0),
                 sensor_interval, # byte 0x14 (0x3)
                 chr(0),
                 last_history_address, # 2 bytes (0x3e 0xde)
                 chr(bin2bcd(date('h', now))) + chr(bin2bcd(date('i', now))) + chr(bin2bcd(date('s', now))), # 3 bytes: hour, minute, second
                 chr(bin2bcd(date('d', now))) + chr(bin2bcd(date('m', now))) + chr(bin2bcd(date('y', now))), # 3 bytes: day, month, year                 
                 chr(0x53),
                 history_interval, # byte 0x1f (0x7)
                 chr(0x4),
                 chr(0) + chr(0),
                 chr(0)])
            cs = self.checksum16(payload) + 7
            return payload + chr(cs >> 8) + chr(cs & 0xff)

    class Parser(Consumer.Parser):

        DEFAULT_SENSOR_MAP = {
            'pressure..*': 'pressure',
            'in_temperature..*': 'inTemp',
            'out_temperature..*': 'outTemp',
            'in_humidity..*': 'inHumidity',
            'out_humidity..*': 'outHumidity',
            'wind_speed..*': 'windSpeed',
            'wind_gust..*': 'windGust',
            'wind_dir..*': 'windDir',
            'rain..*': 'rain',
            'rf_signal_strength..*': 'rxCheckPercent'}

        def __init__(self):
            self._last_rain = None

        @staticmethod
        def parse_identifiers(s):
            bridge_id = 'mac' # FIXME
            return bridge_id, None, None

        def parse(self, s):
            pkt = dict()
            pkt['record_type'] = s[0] # always 01
            pkt['rf_signal_strength'] = int(s[1], 16) # %
            pkt['status'] = s[2] # 0x10, 0x20, 0x30
            pkt['forecast'] = s[3] # 0x11, 0x12, 0x20, 0x21
            pkt['in_temperature'] = self.hex2degC(s[39:3]) # C
            pkt['out_temperature'] = self.hex2degC(s[75:3]) # C
            ok = h[114:1] == 0 # 0=ok, 0xa=err
            pkt['windchill'] = self.hex2degC(s[111:3]) if ok else None # C
            pkt['in_humidity'] = int(s[70], 16) # %
            pkt['out_humidity'] = int(s[83], 16) # %
            pkt['rain_count'] = int(s[267:7], 16) / 1000.0 # 0.001 mm
            pkt['rain'] = self._delta_rain(data['rain_count'], self._last_rain)
            self._last_rain = data['rain_count']
            ok = h[297:1] == 0 # 0=ok, 5=err
            pkt['wind_speed'] = int(s[290:4], 16) / 100.0 if ok else None # 0.01km/h
            pkt['wind_dir'] = 0 # FIXME: figure out wind dir
            pkt['wind_gust'] = 0 # FIXME: figure out wind gust
            pkt['pressure'] = int(s[339:5], 16) / 10.0 # mbar

            # now tag each value with identifiers
            packet = {'dateTime': int(time.time() + 0.5),
                      'usUnits': weewx.METRICWX}
            label_id = pkt.get('mac') # FIXME
            for n in pkt:
                packet["%s..%s" % (n, label_id)] = pkt[n]
            return packet

        @staticmethod
        def map_to_fields(pkt, sensor_map):
            if sensor_map is None:
                sensor_map = GW1000U.Parser.DEFAULT_SENSOR_MAP
            return Consumer.Parser.map_to_fields(pkt, sensor_map)

        @staticmethod
        def hex2degC(x):
            if x == 'AAA':
                return None
            if len(x) != 3:
                return None
            return int(x, 16) / 10 - 40.0

        @staticmethod
        def checksum8(x):
            sum = 0
            for c in x:
                sum += int(c, 16)
            return sum & 0xff

        @staticmethod
        def checksum16(x):
            sum = 0
            for c in x:
                sum += ord(c)
            return sum & 0xffff

class InterceptorConfigurationEditor(weewx.drivers.AbstractConfEditor):
    @property
    def default_stanza(self):
        return """
[Interceptor]
    # This section is for the network traffic interceptor driver.

    # Specify the hardware device to capture.  Options include:
    #   acurite-bridge - acurite internet bridge
    #   observerip - fine offset ObserverIP or WH140x/WH120x
    #   lw30x - oregon scientific LW301/LW302
    #   lacross-bridge - lacross C84612 internet bridge
    #   netatmo - netatmo weather stations
    device_type = acurite-bridge

    # The driver to use:
    driver = user.interceptor
"""

    def prompt_for_settings(self):
        print "Specify the type of device whose data will be captured"
        device_type = self._prompt('device_type', 'acurite-bridge',
                                   ['acurite-bridge', 'observerip', 'lw30x',
                                    'lacross-bridge', 'netatmo'])
        return {'device_type': device_type}


class InterceptorDriver(weewx.drivers.AbstractDevice):
    DEVICE_TYPES = {
        'acurite-bridge': AcuriteBridge,
        'observerip': ObserverIP,
        'lw30x': LW30x,
        'lacrosse-bridge': GW1000U}

    def __init__(self, **stn_dict):
        loginf('driver version is %s' % DRIVER_VERSION)
        self._addr = stn_dict.get('address', DEFAULT_ADDR)
        self._port = stn_dict.get('port', DEFAULT_PORT)
        loginf('server will listen on %s:%s' % (self._addr, self._port))
        self._obs_map = stn_dict.get('sensor_map', None)
        loginf('sensor map: %s' % self._obs_map)
        self._device_type = stn_dict.get('device_type', 'acurite-bridge')
        if not self._device_type in self.DEVICE_TYPES:
            raise Exception("unsupported device type '%s'" % self._device_type)
        self._device = self.DEVICE_TYPES.get(self._device_type)(
            (self._addr, self._port))
        self._server_thread = threading.Thread(target=self._device.run_server)
        self._server_thread.setDaemon(True)
        self._server_thread.setName('ServerThread')
        self._server_thread.start()

    def closePort(self):
        loginf('shutting down server thread')
        self._device.shutdown()
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
                yield pkt
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
                      help='display diagnostic information while running')
    parser.add_option('--port', dest='port', metavar='PORT',
                      default=DEFAULT_PORT,
                      help='port on which to listen')
    parser.add_option('--address', dest='addr', metavar='ADDRESS',
                      default=DEFAULT_ADDR,
                      help='address on which to bind')
    parser.add_option('--device', dest='device_type', metavar='DEVICE_TYPE',
                      default=DEFAULT_DEVICE_TYPE,
                      help='type of device for which to listen')

    (options, args) = parser.parse_args()

    debug = False
    if options.debug is not None:
        syslog.setlogmask(syslog.LOG_UPTO(syslog.LOG_DEBUG))
        debug = True

    if not options.device_type in InterceptorDriver.DEVICE_TYPES:
        raise Exception("unsupported device type '%s'.  options include %s" %
                        (options.device_type,
                         ', '.join(InterceptorDriver.DEVICE_TYPES.keys())))
    device = InterceptorDriver.DEVICE_TYPES.get(options.device_type)(
        (options.addr, options.port))

    server_thread = threading.Thread(target=device.run_server)
    server_thread.setDaemon(True)
    server_thread.setName('ServerThread')
    server_thread.start()

    while True:
        try:
            data = device.get_queue().get(True, 10)
            if debug:
                print 'raw data: %s' % data
            if debug:
                pkt = device.parser.parse(data)
                print 'raw packet: %s' % pkt
#                pkt = device.parser.map_to_fields(pkt, obs_map)
#                print 'mapped packet: %s' % pkt
            ids = device.parser.parse_identifiers(data)
            print "bridge_id: %s sensor_id: %s sensor_type: %s" % ids
        except Queue.Empty:
            pass

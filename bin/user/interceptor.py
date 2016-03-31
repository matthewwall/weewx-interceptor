#!/usr/bin/env python
# Copyright 2016 Matthew Wall, all rights reserved
"""
This driver runs a simple web server designed to receive data directly from an
internet weather reporting device such as the Acurite internet bridge, the
LaCross C84612, the Oregon Scientific WS301/302, or the Fine Offset ObserverIP.


"""

# FIXME: automatically detect the traffic type
# FIXME: handle traffic from multiple types of devices

from __future__ import with_statement
import BaseHTTPServer
import SocketServer
import Queue
import syslog
import threading
import time

import weewx.drivers

DRIVER_NAME = 'Interceptor'
DRIVER_VERSION = '0.1'

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


class AcuriteBridge():
    queue = Queue.Queue()

    def __init__(self, server_address):
        self.parser = AcuriteBridge.Parser()
        self._server = AcuriteBridge.Server(server_address)

    def run_server(self):
        self._server.serve_forever()

    def shutdown(self):
        self._server.shutdown()

    def get_queue(self):
        return AcuriteBridge.queue

    class Server(SocketServer.TCPServer):
        daemon_threads = True
        allow_reuse_address = True

        def __init__(self, server_address):
            SocketServer.TCPServer.__init__(
                self, server_address, AcuriteBridge.Handler)

    class Handler(BaseHTTPServer.BaseHTTPRequestHandler):
        RESPONSE = '{ "success": 1, "checkversion": "126" }'

        def do_POST(self):
            length = int(self.headers["Content-Length"])
            data = str(self.rfile.read(length))
            logdbg('acurite POST: %s' % data)
            AcuriteBridge.queue.put(data)
            response = bytes(self.RESPONSE)
            self.send_response(200)
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)

        # do not spew messages on every connection
        def log_message(self, format, *args):
            pass

    class Parser():
        # sample output from a bridge with 3 t/h sensors and 1 5-in-1
        # id=X&mt=pressure&C1=452D&C2=0D7F&C3=010D&C4=0330&C5=8472&C6=1858&C7=09C4&A=07&B=1B&C=06&D=09&PR=91CA&TR=8270
        # id=X&sensor=02004&mt=5N1x31&windspeed=A001660000&winddir=8&rainfall=A0000000&battery=normal&rssi=3
        # id=X&sensor=02004&mt=5N1x38&windspeed=A001890000&humidity=A0280&temperature=A014722222&battery=normal&rssi=3
        # id=X&sensor=06022&mt=tower&humidity=A0270&temperature=A020100000&battery=normal&rssi=3
        # id=X&sensor=05961&mt=tower&humidity=A0300&temperature=A017400000&battery=normal&rssi=3
        # id=X&sensor=14074&mt=tower&humidity=A0300&temperature=A021500000&battery=normal&rssi=4

        DEFAULT_FIELD_MAP = {
            'pressure..*': 'pressure',
            'temperature..*': 'inTemp',
            'temperature.*.*': 'outTemp',
            'humidity.*.*': 'outHumidity',
            'windspeed.*.*': 'windSpeed',
            'winddir.*.*': 'windDir',
            'rainfall.*.*': 'rain'}

        IDX_TO_DEG = {6: 0.0, 14: 22.5, 12: 45.0, 8: 67.5, 10: 90.0, 11: 112.5,
                      9: 135.0, 13: 157.5, 15: 180.0, 7: 202.5, 5: 225.0,
                      1: 247.5, 3: 270.0, 2: 292.5, 0: 315.0, 4: 337.5}

        @staticmethod
        def parse(s):
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
            if pkt['sensor_type'] == 'pressure':
                pkt['pressure'], pkt['temperature'] = AcuriteBridge.Parser.decode_pressure(pkt)

            # now tag each value with the sensor and bridge identifiers
            packet = {'dateTime': int(time.time() + 0.5),
                      'usUnits': weewx.METRICWX}
            for n in pkt:
                label = "%s.%s.%s" % (
                    n, pkt.get('sensor_id', ''), pkt.get('bridge_id', ''))
                packet[label] = pkt[n]
            return packet

        @staticmethod
        def map_to_fields(pkt, field_map):
            if field_map is None:
                field_map = AcuriteBridge.Parser.DEFAULT_FIELD_MAP
            packet = {'dateTime': pkt['dateTime'], 'usUnits': pkt['usUnits']}
            for n in field_map:
                label = AcuriteBridge.Parser._find_match(n, pkt.keys())
                if label:
                    packet[field_map[n]] = pkt.get(label)
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
                if (AcuriteBridge.Parser._part_match(pparts[0], kparts[0]) and
                    AcuriteBridge.Parser._part_match(pparts[1], kparts[1]) and
                    AcuriteBridge.Parser._part_match(pparts[2], kparts[2])):
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
            return float(s[2:8]) / 10.0

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


class InterceptorDriver(weewx.drivers.AbstractDevice):
    DEFAULT_PORT = 9999
    DEVICES = {'acurite-bridge': AcuriteBridge}

    def __init__(self, **stn_dict):
        loginf('driver version is %s' % DRIVER_VERSION)
        self._addr = stn_dict.get('address', '')
        self._port = stn_dict.get('port', self.DEFAULT_PORT)
        loginf('server will listen on %s:%s' % (self._addr, self._port))
        self._obs_map = stn_dict.get('map', None)
        loginf('observation map: %s' % self._obs_map)
        self._device_type = stn_dict.get('device_type', 'acurite-bridge')
        if self._device_type in self.DEVICES:
            self._device = self.DEVICES[self._device_type](
                (self._addr, self._port))
        else:
            raise Exception("unsupported device type '%s'" % self._device_type)
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


class InterceptorConfigurationEditor(weewx.drivers.AbstractConfEditor):
    @property
    def default_stanza(self):
        return """
[Interceptor]
    # This section is for the network traffic nterceptor driver.

    # Specify the hardware device to capture.  Options include:
    #   acurite-bridge - acurite internet bridge
    #   observerip - fine offset ObserverIP or WS140x/WS120x
    #   ws30x - oregon scientific WS301/WS302
    #   lacross-bridge - lacross C84612 internet bridge
    #   netatmo - netatmo weather stations
    device_type = acurite-bridge

    # The driver to use:
    driver = user.interceptor
"""

    def prompt_for_settings(self):
        print "Specify the type of device whose data will be captured"
        device_type = self._prompt('device_type', 'acurite-bridge',
                                   ['acurite-bridge', 'observerip', 'ws30x',
                                    'lacross-bridge', 'netatmo'])
        return {'device_type': device_type}

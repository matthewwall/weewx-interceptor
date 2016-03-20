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


class InterceptorDriver(weewx.drivers.AbstractDevice):
    DEFAULT_PORT = 9999

    def __init__(self, **stn_dict):
        loginf('driver version is %s' % DRIVER_VERSION)
        self._device_type = stn_dict.get('device_type', 'acurite-bridge')
        self._addr = stn_dict.get('address', '')
        self._port = stn_dict.get('port', self.DEFAULT_PORT)
        self._hardware_type = 'Acurite Bridge'
        self._handler = AcuriteBridgeHandler()
        self._parser = AcuriteBridgeParser()
        self._obs_map = stn_dict.get('map', self._parser.DEFAULT_MAP)
        self.server_thread = ServerThread(handler,
                                          addr=self._addr, port=self._port)
        self.server_thread.start()

    def closePort(self):
        if self.server_thread.isAlive():
            self.server_thread.shutdown()
            self.server_thread.join(20.0)
            if self.server_thread.isAlive():
                logerr("unable to shut down server thread")
            else:
                loginf("server thread has been shut down")

    def hardware_name(self):
        return self._hardware_type

    def genLoopPackets(self):
        while True:
            data = self._handler.queue.get()
            packet = self._parser.parse(data)
            packet = self.remap_fields(packet)
            yield packet

    def remap_fields(self, pkt):
        packet = {'dateTime': pkt['dateTime'], 'usUnits': pkt['usUnits']}
        for n in self._obs_map:
            packet[self._obs_map[n]] = pkt.get(n)
        return packet


class ServerThread(threading.Thread):
    def __init__(self, handler, addr='', port=80):
        threading.Thread.__init__(self, name='InterceptorServerThread')
        self.setDaemon(True)
        self._server = SocketServer.TCPServer((addr, port), handler)
        loginf("server will listen on %s:%s" % (addr, port))

    def run(self):
        loginf("start socket server")
        self._server.serve_forever()

    def shutdown(self):
        loginf("shutdown socket server")
        self._server.shutdown()
        loginf("shutdown server thread")
        super(ServerThread, self).shutdown()


class AcuriteBridgeHandler(BaseHTTPRequestHandler):
    RESPONSE = '{ "success": 1, "checkversion": "126" }'

    def __init__(self):
        self.queue = Queue.Queue()

    def do_POST(self):
        length = int(self.headers["Content-Length"])
        data = str(self.rfile.read(length))
        loginf('POST: %s' % data)
        self.queue.put(data)
        response = bytes(self.RESPONSE)
        self.send_response(200)
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(reponse)


class AcuriteBridgeParser():
    # sample output from a bridge with 3 t/h sensors and 1 5-in-1
    # id=X&mt=pressure&C1=452D&C2=0D7F&C3=010D&C4=0330&C5=8472&C6=1858&C7=09C4&A=07&B=1B&C=06&D=09&PR=91CA&TR=8270
    # id=X&sensor=02004&mt=5N1x31&windspeed=A001660000&winddir=8&rainfall=A0000000&battery=normal&rssi=3
    # id=X&sensor=02004&mt=5N1x38&windspeed=A001890000&humidity=A0280&temperature=A014722222&battery=normal&rssi=3
    # id=X&sensor=06022&mt=tower&humidity=A0270&temperature=A020100000&battery=normal&rssi=3
    # id=X&sensor=05961&mt=tower&humidity=A0300&temperature=A017400000&battery=normal&rssi=3
    # id=X&sensor=14074&mt=tower&humidity=A0300&temperature=A021500000&battery=normal&rssi=4

    DEFAULT_MAP = {
        'pressure': 'pressure',
        'temperature': 'inTemp',
        'windspeed': 'windSpeed',
        'winddir': 'windDir',
        'rainfall': 'rain',
        'battery': 'battery',
        'rssi': 'rssi'}

    IDX_TO_DEG = {6: 0.0, 14: 22.5, 12: 45.0, 8: 67.5, 10: 90.0, 11: 112.5,
                  9: 135.0, 13: 157.5, 15: 180.0, 7: 202.5, 5: 225.0, 1: 247.5,
                  3: 270.0, 2: 292.5, 0: 315.0, 4: 337.5}

    @staticmethod
    def parse(s):
        packet = {'dateTime': int(time.time() + 0.5),
                  'usUnits': weewx.METRICWX}
        parts = s.split('&')
        for x in parts:
            (n, v) = x.split('=')
            if n == 'id':
                packet['bridge_id'] = v
            elif n == 'sensor':
                packet['sensor_id'] = v
            elif n == 'mt':
                packet['sensor_type'] = v
            elif hasattr(AcuriteBridgeParser, '_decode_%s' % n):
                try:
                    packet[n] = getattr(AcuriteBridgeParser, '_decode_%s' % n)
                except (ValueError, IndexError), e:
                    logerr("decode failed for %s '%s': %s" % (n, v, e))
            elif n in ['C1', 'C1', 'C3', 'C4', 'C5', 'C6', 'C7',
                       'A', 'B', 'C', 'D', 'PR', 'TR']:
                packet[n] = v
            else:
                loginf("unknown element '%s' with value '%s'" % (n, v))
        if packet['sensor_type'] == 'pressure':
            packet['pressure'], packet['temperature'] = self._decode_pressure(packet)
        return packet

    @staticmethod
    def _decode_battery(s):
        return 1 if s != 'normal' else 0

    @staticmethod
    def _decode_rssi(s):
        return int(s)

    @staticmethod
    def _decode_humidity(s):
        # humidity in [0, 100]
        return float(s[2:5]) / 10.0

    @staticmethod
    def _decode_temperature(s):
        # temperature in degree C
        return float(s[1:5]) / 10.0

    @staticmethod
    def _decode_windspeed(s):
        # wind speed in meters per second
        return float(s) / 100.0

    @staticmethod
    def _decode_winddir(s):
        # wind direction in compass degrees [0, 360]
        return AcuriteBridgeParser.IDX_TO_DEG.get(int(s))

    @staticmethod
    def _decode_rainfall(s):
        # rainfall since last report, in mm
        return float(s)

    @staticmethod
    def _decode_pressure(pkt):
        # pressure in mbar, temperature in degree C
        c1 = hex(pkt['C1'])
        c2 = hex(pkt['C2'])
        c3 = hex(pkt['C3'])
        c4 = hex(pkt['C4'])
        c5 = hex(pkt['C5'])
        c6 = hex(pkt['C6'])
        c7 = hex(pkt['C7'])
        a = hex(pkt['A'])
        b = hex(pkt['B'])
        c = hex(pkt['C'])
        d = hex(pkt['D'])
        pr = hex(pkt['PR'])
        tr = hex(pkt['TR'])
        if (0x100 <= c1 <= 0xffff and
            0x0 <= c2 <= 0x1fff and
            0x0 <= c3 <= 0x400 and
            0x0 <= c4 <= 0x1000 and
            0x1000 <= c5 <= 0xffff and
            0x0 <= c6 <= 0x4000 and
            0x960 <= c7 <= 0xa28 and
            0x01 <= a <= 0x3f and 0x01 <= b <= 0x3f and
            0x01 <= c <= 0x0f and 0x01 <= d <= 0x0f):
            return AcuriteBridgeParser._decode_HP03S(
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

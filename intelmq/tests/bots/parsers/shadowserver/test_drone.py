# -*- coding: utf-8 -*-
from __future__ import unicode_literals, print_function

import os
import unittest

import intelmq.lib.test as test
import intelmq.lib.utils as utils
from intelmq.bots.parsers.shadowserver.drone_parser import \
    ShadowServerDroneParserBot

with open(os.path.join(os.path.dirname(__file__), 'drone.csv')) as handle:
    EXAMPLE_FILE = handle.read()

EXAMPLE_REPORT = {"feed.name": "ShadowServer Drone",
                  "raw": utils.base64_encode(EXAMPLE_FILE),
                  "__type": "Report",
                  "time.observation": "2015-01-01T00:00:00+00:00",
                  }
EVENTS = [{'__type': 'Event',
           'classification.type': 'botnet drone',
           'destination.asn': 8560,
           'destination.geolocation.cc': 'US',
           'destination.ip': '74.208.164.166',
           'destination.port': 80,
           'extra': '{"os.name": "Windows", "connection_count": 1, "os.version'
           '": "2000 SP4, XP SP1+"}',
           'feed.name': 'ShadowServer Drone',
           'malware.name': 'sinkhole',
           'protocol.transport': 'tcp',
           'raw': 'Iih1J2NjJywgdSc3NC4yMDguMTY0LjE2NicpLCh1J2lwJywgdScyMTAuMjMuMTM5LjEzMCcpLCh1J2FnZW50JywgdScnKSwodSdwb3J0JywgdSczMjE4JyksKHUnY2l0eScsIHUnTUVMQk9VUk5FJyksKHUnaG9zdG5hbWUnLCB1JycpLCh1J3NpYycsIHUnMCcpLCh1J2FwcGxpY2F0aW9uJywgdScnKSwodSd0eXBlJywgdSd0Y3AnKSwodSdwMGZfZ2VucmUnLCB1J1dpbmRvd3MnKSwodSdjY19wb3J0JywgdSc4MCcpLCh1J3AwZl9kZXRhaWwnLCB1JzIwMDAgU1A0LCBYUCBTUDErJyksKHUndGltZXN0YW1wJywgdScyMDExLTA0LTIzIDAwOjAwOjA1JyksKHUnaW5mZWN0aW9uJywgdSdzaW5raG9sZScpLCh1J3Byb3h5JywgdScnKSwodSdjY19hc24nLCB1Jzg1NjAnKSwodSdnZW8nLCB1J0FVJyksKHUnYXNuJywgdSc3NTQzJyksKHUnY291bnQnLCB1JzEnKSwodSdjY19kbnMnLCB1JycpLCh1J25haWNzJywgdScwJyksKHUndXJsJywgdScnKSwodSdyZWdpb24nLCB1J1ZJQ1RPUklBJyksKHUnY2NfZ2VvJywgdSdVUycpIg==',
           'source.asn': 7543,
           'source.geolocation.cc': 'AU',
           'source.geolocation.city': 'MELBOURNE',
           'source.geolocation.region': 'VICTORIA',
           'source.ip': '210.23.139.130',
           'source.port': 3218,
           'time.observation': '2015-01-01T00:00:00+00:00',
           'time.source': '2011-04-23T00:00:05+00:00'},
          {'__type': 'Event',
           'classification.type': 'botnet drone',
           'destination.asn': 16265,
           'destination.geolocation.cc': 'NL',
           'destination.ip': '94.75.228.147',
           'destination.reverse_dns': '015.maxided.com',
           'extra': '{"os.name": "WINXP", "connection_count": 1, "os.version":'
           ' ""}',
           'feed.name': 'ShadowServer Drone',
           'malware.name': 'spyeye',
           'raw': 'Iih1J2NjJywgdSc5NC43NS4yMjguMTQ3JyksKHUnaXAnLCB1JzExNS4xNjYuNTQuNDQnKSwodSdhZ2VudCcsIHUnJyksKHUncG9ydCcsIHUnJyksKHUnY2l0eScsIHUnQURFTEFJREUnKSwodSdob3N0bmFtZScsIHUnMTE1LTE2Ni01NC00NC5pcC5hZGFtLmNvbS5hdScpLCh1J3NpYycsIHUnMCcpLCh1J2FwcGxpY2F0aW9uJywgdScnKSwodSd0eXBlJywgdScnKSwodSdwMGZfZ2VucmUnLCB1J1dJTlhQJyksKHUnY2NfcG9ydCcsIHUnJyksKHUncDBmX2RldGFpbCcsIHUnJyksKHUndGltZXN0YW1wJywgdScyMDExLTA0LTIzIDAwOjAwOjA4JyksKHUnaW5mZWN0aW9uJywgdSdzcHlleWUnKSwodSdwcm94eScsIHUnJyksKHUnY2NfYXNuJywgdScxNjI2NScpLCh1J2dlbycsIHUnQVUnKSwodSdhc24nLCB1Jzk1NTYnKSwodSdjb3VudCcsIHUnMScpLCh1J2NjX2RucycsIHUnMDE1Lm1heGlkZWQuY29tJyksKHUnbmFpY3MnLCB1JzAnKSwodSd1cmwnLCB1JycpLCh1J3JlZ2lvbicsIHUnU09VVEggQVVTVFJBTElBJyksKHUnY2NfZ2VvJywgdSdOTCcpIg==',
           'source.asn': 9556,
           'source.geolocation.cc': 'AU',
           'source.geolocation.city': 'ADELAIDE',
           'source.geolocation.region': 'SOUTH AUSTRALIA',
           'source.ip': '115.166.54.44',
           'source.reverse_dns': '115-166-54-44.ip.adam.com.au',
           'time.observation': '2015-01-01T00:00:00+00:00',
           'time.source': '2011-04-23T00:00:08+00:00'},
          {'__type': 'Event',
           'classification.type': 'botnet drone',
           'destination.asn': 8560,
           'destination.geolocation.cc': 'DE',
           'destination.ip': '87.106.24.200',
           'destination.port': 80,
           'extra': '{"os.name": "Windows", "connection_count": 1, "os.version'
           '": "XP SP1+, 2000 SP3 (2)"}',
           'feed.name': 'ShadowServer Drone',
           'malware.name': 'sinkhole',
           'protocol.transport': 'tcp',
           'raw': 'Iih1J2NjJywgdSc4Ny4xMDYuMjQuMjAwJyksKHUnaXAnLCB1JzExNi4yMTIuMjA1Ljc0JyksKHUnYWdlbnQnLCB1JycpLCh1J3BvcnQnLCB1JzQ4OTg2JyksKHUnY2l0eScsIHUnUEVSVEgnKSwodSdob3N0bmFtZScsIHUnJyksKHUnc2ljJywgdScwJyksKHUnYXBwbGljYXRpb24nLCB1JycpLCh1J3R5cGUnLCB1J3RjcCcpLCh1J3AwZl9nZW5yZScsIHUnV2luZG93cycpLCh1J2NjX3BvcnQnLCB1JzgwJyksKHUncDBmX2RldGFpbCcsIHUnWFAgU1AxKywgMjAwMCBTUDMgKDIpJyksKHUndGltZXN0YW1wJywgdScyMDExLTA0LTIzIDAwOjAwOjEwJyksKHUnaW5mZWN0aW9uJywgdSdzaW5raG9sZScpLCh1J3Byb3h5JywgdScnKSwodSdjY19hc24nLCB1Jzg1NjAnKSwodSdnZW8nLCB1J0FVJyksKHUnYXNuJywgdSc5ODIyJyksKHUnY291bnQnLCB1JzEnKSwodSdjY19kbnMnLCB1JycpLCh1J25haWNzJywgdScwJyksKHUndXJsJywgdScnKSwodSdyZWdpb24nLCB1J1dFU1RFUk4gQVVTVFJBTElBJyksKHUnY2NfZ2VvJywgdSdERScpIg==',
           'source.asn': 9822,
           'source.geolocation.cc': 'AU',
           'source.geolocation.city': 'PERTH',
           'source.geolocation.region': 'WESTERN AUSTRALIA',
           'source.ip': '116.212.205.74',
           'source.port': 48986,
           'time.observation': '2015-01-01T00:00:00+00:00',
           'time.source': '2011-04-23T00:00:10+00:00'},
          {'__type': 'Event',
           'classification.type': 'botnet drone',
           'destination.asn': 8560,
           'destination.geolocation.cc': 'DE',
           'destination.ip': '87.106.24.200',
           'destination.port': 443,
           'extra': '{"os.name": "Windows", "connection_count": 1, "os.version'
           '": "2000 SP4, XP SP1+"}',
           'feed.name': 'ShadowServer Drone',
           'malware.name': 'sinkhole',
           'protocol.transport': 'tcp',
           'raw': 'Iih1J2NjJywgdSc4Ny4xMDYuMjQuMjAwJyksKHUnaXAnLCB1JzU4LjE2OS44Mi4xMTMnKSwodSdhZ2VudCcsIHUnJyksKHUncG9ydCcsIHUnMjQyMycpLCh1J2NpdHknLCB1J0RFVk9OUE9SVCcpLCh1J2hvc3RuYW1lJywgdScnKSwodSdzaWMnLCB1JzAnKSwodSdhcHBsaWNhdGlvbicsIHUnJyksKHUndHlwZScsIHUndGNwJyksKHUncDBmX2dlbnJlJywgdSdXaW5kb3dzJyksKHUnY2NfcG9ydCcsIHUnNDQzJyksKHUncDBmX2RldGFpbCcsIHUnMjAwMCBTUDQsIFhQIFNQMSsnKSwodSd0aW1lc3RhbXAnLCB1JzIwMTEtMDQtMjMgMDA6MDA6MTUnKSwodSdpbmZlY3Rpb24nLCB1J3Npbmtob2xlJyksKHUncHJveHknLCB1JycpLCh1J2NjX2FzbicsIHUnODU2MCcpLCh1J2dlbycsIHUnQVUnKSwodSdhc24nLCB1JzEyMjEnKSwodSdjb3VudCcsIHUnMScpLCh1J2NjX2RucycsIHUnJyksKHUnbmFpY3MnLCB1JzAnKSwodSd1cmwnLCB1JycpLCh1J3JlZ2lvbicsIHUnVEFTTUFOSUEnKSwodSdjY19nZW8nLCB1J0RFJyki',
           'source.asn': 1221,
           'source.geolocation.cc': 'AU',
           'source.geolocation.city': 'DEVONPORT',
           'source.geolocation.region': 'TASMANIA',
           'source.ip': '58.169.82.113',
           'source.port': 2423,
           'time.observation': '2015-01-01T00:00:00+00:00',
           'time.source': '2011-04-23T00:00:15+00:00'},
          {'__type': 'Event',
           'classification.type': 'botnet drone',
           'destination.asn': 8560,
           'destination.geolocation.cc': 'US',
           'destination.ip': '74.208.164.166',
           'destination.port': 443,
           'extra': '{"os.name": "Windows", "connection_count": 1, "os.version'
           '": "2000 SP4, XP SP1+"}',
           'feed.name': 'ShadowServer Drone',
           'malware.name': 'sinkhole',
           'protocol.transport': 'tcp',
           'raw': 'Iih1J2NjJywgdSc3NC4yMDguMTY0LjE2NicpLCh1J2lwJywgdScxMTQuNzguMTcuNDgnKSwodSdhZ2VudCcsIHUnJyksKHUncG9ydCcsIHUnMjc2OScpLCh1J2NpdHknLCB1J0JSSVNCQU5FJyksKHUnaG9zdG5hbWUnLCB1JycpLCh1J3NpYycsIHUnMCcpLCh1J2FwcGxpY2F0aW9uJywgdScnKSwodSd0eXBlJywgdSd0Y3AnKSwodSdwMGZfZ2VucmUnLCB1J1dpbmRvd3MnKSwodSdjY19wb3J0JywgdSc0NDMnKSwodSdwMGZfZGV0YWlsJywgdScyMDAwIFNQNCwgWFAgU1AxKycpLCh1J3RpbWVzdGFtcCcsIHUnMjAxMS0wNC0yMyAwMDowMDoyNicpLCh1J2luZmVjdGlvbicsIHUnc2lua2hvbGUnKSwodSdwcm94eScsIHUnJyksKHUnY2NfYXNuJywgdSc4NTYwJyksKHUnZ2VvJywgdSdBVScpLCh1J2FzbicsIHUnNDgwNCcpLCh1J2NvdW50JywgdScxJyksKHUnY2NfZG5zJywgdScnKSwodSduYWljcycsIHUnMCcpLCh1J3VybCcsIHUnJyksKHUncmVnaW9uJywgdSdRVUVFTlNMQU5EJyksKHUnY2NfZ2VvJywgdSdVUycpIg==',
           'source.asn': 4804,
           'source.geolocation.cc': 'AU',
           'source.geolocation.city': 'BRISBANE',
           'source.geolocation.region': 'QUEENSLAND',
           'source.ip': '114.78.17.48',
           'source.port': 2769,
           'time.observation': '2015-01-01T00:00:00+00:00',
           'time.source': '2011-04-23T00:00:26+00:00'},
          {'__type': 'Event',
           'classification.type': 'botnet drone',
           'destination.asn': 8560,
           'destination.geolocation.cc': 'DE',
           'destination.ip': '87.106.24.200',
           'destination.port': 443,
           'extra': '{"os.name": "Windows", "connection_count": 1, "os.version'
           '": "2000 SP4, XP SP1+"}',
           'feed.name': 'ShadowServer Drone',
           'malware.name': 'sinkhole',
           'protocol.transport': 'tcp',
           'raw': 'Iih1J2NjJywgdSc4Ny4xMDYuMjQuMjAwJyksKHUnaXAnLCB1JzEyNC4xOTAuMTYuMTEnKSwodSdhZ2VudCcsIHUnJyksKHUncG9ydCcsIHUnNDA5NScpLCh1J2NpdHknLCB1J01FTEJPVVJORScpLCh1J2hvc3RuYW1lJywgdScnKSwodSdzaWMnLCB1JzAnKSwodSdhcHBsaWNhdGlvbicsIHUnJyksKHUndHlwZScsIHUndGNwJyksKHUncDBmX2dlbnJlJywgdSdXaW5kb3dzJyksKHUnY2NfcG9ydCcsIHUnNDQzJyksKHUncDBmX2RldGFpbCcsIHUnMjAwMCBTUDQsIFhQIFNQMSsnKSwodSd0aW1lc3RhbXAnLCB1JzIwMTEtMDQtMjMgMDA6MDA6MjgnKSwodSdpbmZlY3Rpb24nLCB1J3Npbmtob2xlJyksKHUncHJveHknLCB1JycpLCh1J2NjX2FzbicsIHUnODU2MCcpLCh1J2dlbycsIHUnQVUnKSwodSdhc24nLCB1JzEyMjEnKSwodSdjb3VudCcsIHUnMScpLCh1J2NjX2RucycsIHUnJyksKHUnbmFpY3MnLCB1JzAnKSwodSd1cmwnLCB1JycpLCh1J3JlZ2lvbicsIHUnVklDVE9SSUEnKSwodSdjY19nZW8nLCB1J0RFJyki',
           'source.asn': 1221,
           'source.geolocation.cc': 'AU',
           'source.geolocation.city': 'MELBOURNE',
           'source.geolocation.region': 'VICTORIA',
           'source.ip': '124.190.16.11',
           'source.port': 4095,
           'time.observation': '2015-01-01T00:00:00+00:00',
           'time.source': '2011-04-23T00:00:28+00:00'},
          {'__type': 'Event',
           'classification.type': 'botnet drone',
           'destination.asn': 8560,
           'destination.geolocation.cc': 'DE',
           'destination.ip': '87.106.24.200',
           'destination.port': 443,
           'extra': '{"os.name": "Windows", "connection_count": 1, "os.version'
           '": "XP/2000 (RFC1323+, w+, tstamp+)"}',
           'feed.name': 'ShadowServer Drone',
           'malware.name': 'sinkhole',
           'protocol.transport': 'tcp',
           'raw': 'Iih1J2NjJywgdSc4Ny4xMDYuMjQuMjAwJyksKHUnaXAnLCB1JzEyNC4xODIuMzYuMzMnKSwodSdhZ2VudCcsIHUnJyksKHUncG9ydCcsIHUnNjA4MzcnKSwodSdjaXR5JywgdSdQRVJUSCcpLCh1J2hvc3RuYW1lJywgdScnKSwodSdzaWMnLCB1JzAnKSwodSdhcHBsaWNhdGlvbicsIHUnJyksKHUndHlwZScsIHUndGNwJyksKHUncDBmX2dlbnJlJywgdSdXaW5kb3dzJyksKHUnY2NfcG9ydCcsIHUnNDQzJyksKHUncDBmX2RldGFpbCcsIHUnWFAvMjAwMCAoUkZDMTMyMyssIHcrLCB0c3RhbXArKScpLCh1J3RpbWVzdGFtcCcsIHUnMjAxMS0wNC0yMyAwMDowMDoyOScpLCh1J2luZmVjdGlvbicsIHUnc2lua2hvbGUnKSwodSdwcm94eScsIHUnJyksKHUnY2NfYXNuJywgdSc4NTYwJyksKHUnZ2VvJywgdSdBVScpLCh1J2FzbicsIHUnMTIyMScpLCh1J2NvdW50JywgdScxJyksKHUnY2NfZG5zJywgdScnKSwodSduYWljcycsIHUnMCcpLCh1J3VybCcsIHUnJyksKHUncmVnaW9uJywgdSdXRVNURVJOIEFVU1RSQUxJQScpLCh1J2NjX2dlbycsIHUnREUnKSI=',
           'source.asn': 1221,
           'source.geolocation.cc': 'AU',
           'source.geolocation.city': 'PERTH',
           'source.geolocation.region': 'WESTERN AUSTRALIA',
           'source.ip': '124.182.36.33',
           'source.port': 60837,
           'time.observation': '2015-01-01T00:00:00+00:00',
           'time.source': '2011-04-23T00:00:29+00:00'},
          {'__type': 'Event',
           'classification.type': 'botnet drone',
           'destination.asn': 8560,
           'destination.geolocation.cc': 'US',
           'destination.ip': '74.208.164.166',
           'destination.port': 80,
           'extra': '{"os.name": "Windows", "connection_count": 1, "os.version'
           '": "XP SP1+, 2000 SP3 (2)"}',
           'feed.name': 'ShadowServer Drone',
           'malware.name': 'sinkhole',
           'protocol.transport': 'tcp',
           'raw': 'Iih1J2NjJywgdSc3NC4yMDguMTY0LjE2NicpLCh1J2lwJywgdScxMTYuMjEyLjIwNS43NCcpLCh1J2FnZW50JywgdScnKSwodSdwb3J0JywgdScyMzMyMScpLCh1J2NpdHknLCB1J1BFUlRIJyksKHUnaG9zdG5hbWUnLCB1JycpLCh1J3NpYycsIHUnMCcpLCh1J2FwcGxpY2F0aW9uJywgdScnKSwodSd0eXBlJywgdSd0Y3AnKSwodSdwMGZfZ2VucmUnLCB1J1dpbmRvd3MnKSwodSdjY19wb3J0JywgdSc4MCcpLCh1J3AwZl9kZXRhaWwnLCB1J1hQIFNQMSssIDIwMDAgU1AzICgyKScpLCh1J3RpbWVzdGFtcCcsIHUnMjAxMS0wNC0yMyAwMDowMDozMycpLCh1J2luZmVjdGlvbicsIHUnc2lua2hvbGUnKSwodSdwcm94eScsIHUnJyksKHUnY2NfYXNuJywgdSc4NTYwJyksKHUnZ2VvJywgdSdBVScpLCh1J2FzbicsIHUnOTgyMicpLCh1J2NvdW50JywgdScxJyksKHUnY2NfZG5zJywgdScnKSwodSduYWljcycsIHUnMCcpLCh1J3VybCcsIHUnJyksKHUncmVnaW9uJywgdSdXRVNURVJOIEFVU1RSQUxJQScpLCh1J2NjX2dlbycsIHUnVVMnKSI=',
           'source.asn': 9822,
           'source.geolocation.cc': 'AU',
           'source.geolocation.city': 'PERTH',
           'source.geolocation.region': 'WESTERN AUSTRALIA',
           'source.ip': '116.212.205.74',
           'source.port': 23321,
           'time.observation': '2015-01-01T00:00:00+00:00',
           'time.source': '2011-04-23T00:00:33+00:00'},
          {'__type': 'Event',
           'classification.type': 'botnet drone',
           'destination.asn': 8560,
           'destination.geolocation.cc': 'US',
           'destination.ip': '74.208.164.166',
           'destination.port': 443,
           'extra': '{"os.name": "Windows", "connection_count": 1, "os.version'
           '": "2000 SP4, XP SP1+"}',
           'feed.name': 'ShadowServer Drone',
           'malware.name': 'sinkhole',
           'protocol.transport': 'tcp',
           'raw': 'Iih1J2NjJywgdSc3NC4yMDguMTY0LjE2NicpLCh1J2lwJywgdScxMjQuMTkwLjE2LjExJyksKHUnYWdlbnQnLCB1JycpLCh1J3BvcnQnLCB1JzQwODknKSwodSdjaXR5JywgdSdNRUxCT1VSTkUnKSwodSdob3N0bmFtZScsIHUnJyksKHUnc2ljJywgdScwJyksKHUnYXBwbGljYXRpb24nLCB1JycpLCh1J3R5cGUnLCB1J3RjcCcpLCh1J3AwZl9nZW5yZScsIHUnV2luZG93cycpLCh1J2NjX3BvcnQnLCB1JzQ0MycpLCh1J3AwZl9kZXRhaWwnLCB1JzIwMDAgU1A0LCBYUCBTUDErJyksKHUndGltZXN0YW1wJywgdScyMDExLTA0LTIzIDAwOjAwOjM2JyksKHUnaW5mZWN0aW9uJywgdSdzaW5raG9sZScpLCh1J3Byb3h5JywgdScnKSwodSdjY19hc24nLCB1Jzg1NjAnKSwodSdnZW8nLCB1J0FVJyksKHUnYXNuJywgdScxMjIxJyksKHUnY291bnQnLCB1JzEnKSwodSdjY19kbnMnLCB1JycpLCh1J25haWNzJywgdScwJyksKHUndXJsJywgdScnKSwodSdyZWdpb24nLCB1J1ZJQ1RPUklBJyksKHUnY2NfZ2VvJywgdSdVUycpIg==',
           'source.asn': 1221,
           'source.geolocation.cc': 'AU',
           'source.geolocation.city': 'MELBOURNE',
           'source.geolocation.region': 'VICTORIA',
           'source.ip': '124.190.16.11',
           'source.port': 4089,
           'time.observation': '2015-01-01T00:00:00+00:00',
           'time.source': '2011-04-23T00:00:36+00:00'},
          {'__type': 'Event',
           'classification.type': 'botnet drone',
           'destination.asn': 8560,
           'destination.geolocation.cc': 'DE',
           'destination.ip': '87.106.24.200',
           'destination.port': 443,
           'extra': '{"os.name": "Windows", "connection_count": 1, "os.version'
           '": "2000 SP4, XP SP1+"}',
           'feed.name': 'ShadowServer Drone',
           'malware.name': 'sinkhole',
           'protocol.transport': 'tcp',
           'raw': 'Iih1J2NjJywgdSc4Ny4xMDYuMjQuMjAwJyksKHUnaXAnLCB1JzE2NS4yMjguOTMuMjA3JyksKHUnYWdlbnQnLCB1JycpLCh1J3BvcnQnLCB1JzI3MTA1JyksKHUnY2l0eScsIHUnU1lETkVZJyksKHUnaG9zdG5hbWUnLCB1JycpLCh1J3NpYycsIHUnMCcpLCh1J2FwcGxpY2F0aW9uJywgdScnKSwodSd0eXBlJywgdSd0Y3AnKSwodSdwMGZfZ2VucmUnLCB1J1dpbmRvd3MnKSwodSdjY19wb3J0JywgdSc0NDMnKSwodSdwMGZfZGV0YWlsJywgdScyMDAwIFNQNCwgWFAgU1AxKycpLCh1J3RpbWVzdGFtcCcsIHUnMjAxMS0wNC0yMyAwMDowMDozNycpLCh1J2luZmVjdGlvbicsIHUnc2lua2hvbGUnKSwodSdwcm94eScsIHUnJyksKHUnY2NfYXNuJywgdSc4NTYwJyksKHUnZ2VvJywgdSdBVScpLCh1J2FzbicsIHUnMTIyMScpLCh1J2NvdW50JywgdScxJyksKHUnY2NfZG5zJywgdScnKSwodSduYWljcycsIHUnMCcpLCh1J3VybCcsIHUnJyksKHUncmVnaW9uJywgdSdORVcgU09VVEggV0FMRVMnKSwodSdjY19nZW8nLCB1J0RFJyki',
           'source.asn': 1221,
           'source.geolocation.cc': 'AU',
           'source.geolocation.city': 'SYDNEY',
           'source.geolocation.region': 'NEW SOUTH WALES',
           'source.ip': '165.228.93.207',
           'source.port': 27105,
           'time.observation': '2015-01-01T00:00:00+00:00',
           'time.source': '2011-04-23T00:00:37+00:00'}]


class TestShadowServerDroneParserBot(test.BotTestCase, unittest.TestCase):
    """
    A TestCase for a ShadowServerDroneParserBot.
    """

    @classmethod
    def set_bot(cls):
        cls.bot_reference = ShadowServerDroneParserBot
        cls.default_input_message = EXAMPLE_REPORT

    def test_event(self):
        """ Test if correct Event has been produced. """
        self.run_bot()
        for i, EVENT in enumerate(EVENTS):
            self.assertMessageEqual(i, EVENT)


if __name__ == '__main__':
    unittest.main()

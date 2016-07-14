# -*- coding: utf-8 -*-

import os
import unittest

import intelmq.lib.test as test
import intelmq.lib.utils as utils
from intelmq.bots.parsers.shadowserver.snmp_parser import \
    ShadowServerSNMPParserBot

with open(os.path.join(os.path.dirname(__file__), 'snmp.csv')) as handle:
    EXAMPLE_FILE = handle.read()

EXAMPLE_REPORT = {"feed.name": "ShadowServer QOTD",
                  "raw": utils.base64_encode(EXAMPLE_FILE),
                  "__type": "Report",
                  "time.observation": "2015-01-01T00:00:00+00:00",
                  }
EVENTS = [{'__type': 'Event',
           'classification.identifier': 'snmp',
           'classification.type': 'vulnerable service',
           'extra': '{"sysname": "ORSONKA", "sysdesc": "Hardware: x86 Family 6 Model 8 Stepping 6 AT/AT COMPATIBLE - Software: Windows 2000 Version 5.0 (Build 2195 Uniprocessor Free)"}',
           'feed.name': 'ShadowServer QOTD',
           'protocol.application': 'snmp',
           'protocol.transport': 'udp',
           'raw': 'Iih1J3NlY3RvcicsIHUnJyksKHUnc3lzbmFtZScsIHUnT1JTT05LQScpLCh1J2hvc3RuYW1lJywgdSdkb2Vzbm90ZXhpc3QudXRwYS5lZHUnKSwodSdwcm90b2NvbCcsIHUndWRwJyksKHUnY2l0eScsIHUnRURJTkJVUkcnKSwodSd0aW1lc3RhbXAnLCB1JzIwMTQtMDMtMTYgMDM6NDU6NTAnKSwodSdyZWdpb24nLCB1J1RFWEFTJyksKHUnc3lzZGVzYycsIHUnSGFyZHdhcmU6IHg4NiBGYW1pbHkgNiBNb2RlbCA4IFN0ZXBwaW5nIDYgQVQvQVQgQ09NUEFUSUJMRSAtIFNvZnR3YXJlOiBXaW5kb3dzIDIwMDAgVmVyc2lvbiA1LjAgKEJ1aWxkIDIxOTUgVW5pcHJvY2Vzc29yIEZyZWUpJyksKHUnYXNuJywgdScyMjg2NCcpLCh1J3NpYycsIHUnMCcpLCh1J3ZlcnNpb24nLCB1JzInKSwodSdpcCcsIHUnMTI5LjExMy4yMS45MycpLCh1J25haWNzJywgdScwJyksKHUnZ2VvJywgdSdVUycpLCh1J3BvcnQnLCB1JzE2MScpIg==',
           'source.asn': 22864,
           'source.geolocation.cc': 'US',
           'source.geolocation.city': 'EDINBURG',
           'source.geolocation.region': 'TEXAS',
           'source.ip': '129.113.21.93',
           'source.port': 161,
           'source.reverse_dns': 'doesnotexist.utpa.edu',
           'time.observation': '2015-01-01T00:00:00+00:00',
           'time.source': '2014-03-16T03:45:50+00:00'},
          {'__type': 'Event',
           'classification.identifier': 'snmp',
           'classification.type': 'vulnerable service',
           'extra': '{"sysname": "tc", "sysdesc": "ADSL Modem"}',
           'feed.name': 'ShadowServer QOTD',
           'protocol.application': 'snmp',
           'protocol.transport': 'udp',
           'raw': 'Iih1J3NlY3RvcicsIHUnJyksKHUnc3lzbmFtZScsIHUndGMnKSwodSdob3N0bmFtZScsIHUnaG9zdDE2LTI0Mi1keW5hbWljLjItNzktci5yZXRhaWwudGVsZWNvbWl0YWxpYS5pdCcpLCh1J3Byb3RvY29sJywgdSd1ZHAnKSwodSdjaXR5JywgdSdSQVZFTk5BJyksKHUndGltZXN0YW1wJywgdScyMDE0LTAzLTE2IDAzOjQ1OjUxJyksKHUncmVnaW9uJywgdSdFTUlMSUEtUk9NQUdOQScpLCh1J3N5c2Rlc2MnLCB1J0FEU0wgTW9kZW0nKSwodSdhc24nLCB1JzMyNjknKSwodSdzaWMnLCB1JzAnKSwodSd2ZXJzaW9uJywgdScyJyksKHUnaXAnLCB1Jzc5LjIuMjQyLjE2JyksKHUnbmFpY3MnLCB1JzAnKSwodSdnZW8nLCB1J0lUJyksKHUncG9ydCcsIHUnMTcwODAnKSI=',
           'source.asn': 3269,
           'source.geolocation.cc': 'IT',
           'source.geolocation.city': 'RAVENNA',
           'source.geolocation.region': 'EMILIA-ROMAGNA',
           'source.ip': '79.2.242.16',
           'source.port': 17080,
           'source.reverse_dns': 'host16-242-dynamic.2-79-r.retail.telecomitalia.it',
           'time.observation': '2015-01-01T00:00:00+00:00',
           'time.source': '2014-03-16T03:45:51+00:00'},
          {'__type': 'Event',
           'classification.identifier': 'snmp',
           'classification.type': 'vulnerable service',
           'extra': '{"sysname": "", "sysdesc": ""}',
           'feed.name': 'ShadowServer QOTD',
           'protocol.application': 'snmp',
           'protocol.transport': 'udp',
           'raw': 'Iih1J3NlY3RvcicsIHUnJyksKHUnc3lzbmFtZScsIHUnJyksKHUnaG9zdG5hbWUnLCB1J2lwNi0xMjcuc2tla3JhZnQucmlrc25ldC5zZScpLCh1J3Byb3RvY29sJywgdSd1ZHAnKSwodSdjaXR5JywgdSdVTUVBJyksKHUndGltZXN0YW1wJywgdScyMDE0LTAzLTE2IDAzOjQ1OjUxJyksKHUncmVnaW9uJywgdSdWQVNURVJCT1RURU5TIExBTicpLCh1J3N5c2Rlc2MnLCB1JycpLCh1J2FzbicsIHUnMzQ2MTAnKSwodSdzaWMnLCB1JzAnKSwodSd2ZXJzaW9uJywgdScyJyksKHUnaXAnLCB1Jzk1LjEwOS4yMS4xMjcnKSwodSduYWljcycsIHUnMCcpLCh1J2dlbycsIHUnU0UnKSwodSdwb3J0JywgdScxNjEnKSI=',
           'source.asn': 34610,
           'source.geolocation.cc': 'SE',
           'source.geolocation.city': 'UMEA',
           'source.geolocation.region': 'VASTERBOTTENS LAN',
           'source.ip': '95.109.21.127',
           'source.port': 161,
           'source.reverse_dns': 'ip6-127.skekraft.riksnet.se',
           'time.observation': '2015-01-01T00:00:00+00:00',
           'time.source': '2014-03-16T03:45:51+00:00'},
          {'__type': 'Event',
           'classification.identifier': 'snmp',
           'classification.type': 'vulnerable service',
           'extra': '{"sysname": "TD5130", "sysdesc": "Linux ADSL2PlusRouter 2.6.19 #7 Tue Apr 9 17:06:16 CST 2013 mips"}',
           'feed.name': 'ShadowServer QOTD',
           'protocol.application': 'snmp',
           'protocol.transport': 'udp',
           'raw': 'Iih1J3NlY3RvcicsIHUnJyksKHUnc3lzbmFtZScsIHUnVEQ1MTMwJyksKHUnaG9zdG5hbWUnLCB1JzIwMS04LTQtNTcudXNlci52ZWxveHpvbmUuY29tLmJyJyksKHUncHJvdG9jb2wnLCB1J3VkcCcpLCh1J2NpdHknLCB1J1JJTyBERSBKQU5FSVJPJyksKHUndGltZXN0YW1wJywgdScyMDE0LTAzLTE2IDAzOjQ1OjUxJyksKHUncmVnaW9uJywgdSdSSU8gREUgSkFORUlSTycpLCh1J3N5c2Rlc2MnLCB1J0xpbnV4IEFEU0wyUGx1c1JvdXRlciAyLjYuMTkgIzcgVHVlIEFwciA5IDE3OjA2OjE2IENTVCAyMDEzIG1pcHMnKSwodSdhc24nLCB1Jzc3MzgnKSwodSdzaWMnLCB1JzAnKSwodSd2ZXJzaW9uJywgdScyJyksKHUnaXAnLCB1JzIwMS44LjQuNTcnKSwodSduYWljcycsIHUnMCcpLCh1J2dlbycsIHUnQlInKSwodSdwb3J0JywgdScxNjEnKSI=',
           'source.asn': 7738,
           'source.geolocation.cc': 'BR',
           'source.geolocation.city': 'RIO DE JANEIRO',
           'source.geolocation.region': 'RIO DE JANEIRO',
           'source.ip': '201.8.4.57',
           'source.port': 161,
           'source.reverse_dns': '201-8-4-57.user.veloxzone.com.br',
           'time.observation': '2015-01-01T00:00:00+00:00',
           'time.source': '2014-03-16T03:45:51+00:00'},
          {'__type': 'Event',
           'classification.identifier': 'snmp',
           'classification.type': 'vulnerable service',
           'extra': '{"sysname": "Unknow", "sysdesc": "Linux R6100 2.6.31 #1 Tue Jun 4 06:50:58 EDT 2013 mips MIB=01a01"}',
           'feed.name': 'ShadowServer QOTD',
           'protocol.application': 'snmp',
           'protocol.transport': 'udp',
           'raw': 'Iih1J3NlY3RvcicsIHUnJyksKHUnc3lzbmFtZScsIHUnVW5rbm93JyksKHUnaG9zdG5hbWUnLCB1J2NwZS03Ni0xODYtMTA2LTIyMy50eC5yZXMucnIuY29tJyksKHUncHJvdG9jb2wnLCB1J3VkcCcpLCh1J2NpdHknLCB1J0RBTExBUycpLCh1J3RpbWVzdGFtcCcsIHUnMjAxNC0wMy0xNiAwMzo0NTo1MScpLCh1J3JlZ2lvbicsIHUnVEVYQVMnKSwodSdzeXNkZXNjJywgdSdMaW51eCBSNjEwMCAyLjYuMzEgIzEgVHVlIEp1biA0IDA2OjUwOjU4IEVEVCAyMDEzIG1pcHMgTUlCPTAxYTAxJyksKHUnYXNuJywgdScxMTQyNycpLCh1J3NpYycsIHUnMCcpLCh1J3ZlcnNpb24nLCB1JzInKSwodSdpcCcsIHUnNzYuMTg2LjEwNi4yMjMnKSwodSduYWljcycsIHUnMCcpLCh1J2dlbycsIHUnVVMnKSwodSdwb3J0JywgdScxNjEnKSI=',
           'source.asn': 11427,
           'source.geolocation.cc': 'US',
           'source.geolocation.city': 'DALLAS',
           'source.geolocation.region': 'TEXAS',
           'source.ip': '76.186.106.223',
           'source.port': 161,
           'source.reverse_dns': 'cpe-76-186-106-223.tx.res.rr.com',
           'time.observation': '2015-01-01T00:00:00+00:00',
           'time.source': '2014-03-16T03:45:51+00:00'},
          {'__type': 'Event',
           'classification.identifier': 'snmp',
           'classification.type': 'vulnerable service',
           'extra': '{"sysname": "Beetel", "sysdesc": "110TC1"}',
           'feed.name': 'ShadowServer QOTD',
           'protocol.application': 'snmp',
           'protocol.transport': 'udp',
           'raw': 'Iih1J3NlY3RvcicsIHUnJyksKHUnc3lzbmFtZScsIHUnQmVldGVsJyksKHUnaG9zdG5hbWUnLCB1J2FidHMtbm9ydGgtZHluYW1pYy0xMTkuMTExLjY4LjE4Mi5haXJ0ZWxicm9hZGJhbmQuaW4nKSwodSdwcm90b2NvbCcsIHUndWRwJyksKHUnY2l0eScsIHUnR1VSR0FPTicpLCh1J3RpbWVzdGFtcCcsIHUnMjAxNC0wMy0xNiAwMzo0NTo1MScpLCh1J3JlZ2lvbicsIHUnSEFSWUFOQScpLCh1J3N5c2Rlc2MnLCB1JzExMFRDMScpLCh1J2FzbicsIHUnMjQ1NjAnKSwodSdzaWMnLCB1JzAnKSwodSd2ZXJzaW9uJywgdScyJyksKHUnaXAnLCB1JzE4Mi42OC4xMTEuMTE5JyksKHUnbmFpY3MnLCB1JzAnKSwodSdnZW8nLCB1J0lOJyksKHUncG9ydCcsIHUnMTAyMTQnKSI=',
           'source.asn': 24560,
           'source.geolocation.cc': 'IN',
           'source.geolocation.city': 'GURGAON',
           'source.geolocation.region': 'HARYANA',
           'source.ip': '182.68.111.119',
           'source.port': 10214,
           'source.reverse_dns': 'abts-north-dynamic-119.111.68.182.airtelbroadband.in',
           'time.observation': '2015-01-01T00:00:00+00:00',
           'time.source': '2014-03-16T03:45:51+00:00'},
          {'__type': 'Event',
           'classification.identifier': 'snmp',
           'classification.type': 'vulnerable service',
           'extra': '{"sysname": "CableHome", "sysdesc": "BCW710J <<HW_REV: 1.01; VENDOR: Bnmux; BOOTR: 2.4.0alpha14; SW_REV: 5.30.5; MODEL: BCW710J>>"}',
           'feed.name': 'ShadowServer QOTD',
           'protocol.application': 'snmp',
           'protocol.transport': 'udp',
           'raw': 'Iih1J3NlY3RvcicsIHUnJyksKHUnc3lzbmFtZScsIHUnQ2FibGVIb21lJyksKHUnaG9zdG5hbWUnLCB1J2p3YXktMTI1LTIxNC0xNTgtMDMyLmp3YXkubmUuanAnKSwodSdwcm90b2NvbCcsIHUndWRwJyksKHUnY2l0eScsIHUnVE9LWU8nKSwodSd0aW1lc3RhbXAnLCB1JzIwMTQtMDMtMTYgMDM6NDU6NTEnKSwodSdyZWdpb24nLCB1J1RPS1lPJyksKHUnc3lzZGVzYycsIHUnQkNXNzEwSiA8PEhXX1JFVjogMS4wMTsgVkVORE9SOiBCbm11eDsgQk9PVFI6IDIuNC4wYWxwaGExNDsgU1dfUkVWOiA1LjMwLjU7IE1PREVMOiBCQ1c3MTBKPj4nKSwodSdhc24nLCB1JzI0MjQ5JyksKHUnc2ljJywgdScwJyksKHUndmVyc2lvbicsIHUnMicpLCh1J2lwJywgdScxMjUuMjE0LjE1OC4zMicpLCh1J25haWNzJywgdScwJyksKHUnZ2VvJywgdSdKUCcpLCh1J3BvcnQnLCB1JzE2MScpIg==',
           'source.asn': 24249,
           'source.geolocation.cc': 'JP',
           'source.geolocation.city': 'TOKYO',
           'source.geolocation.region': 'TOKYO',
           'source.ip': '125.214.158.32',
           'source.port': 161,
           'source.reverse_dns': 'jway-125-214-158-032.jway.ne.jp',
           'time.observation': '2015-01-01T00:00:00+00:00',
           'time.source': '2014-03-16T03:45:51+00:00'},
          {'__type': 'Event',
           'classification.identifier': 'snmp',
           'classification.type': 'vulnerable service',
           'extra': '{"sysname": "Unknow", "sysdesc": "Linux WNR1000v2 2.6.15 #199 Thu Jan 28 09:49:57 CST 2010 mips MIB=01a01"}',
           'feed.name': 'ShadowServer QOTD',
           'protocol.application': 'snmp',
           'protocol.transport': 'udp',
           'raw': 'Iih1J3NlY3RvcicsIHUnJyksKHUnc3lzbmFtZScsIHUnVW5rbm93JyksKHUnaG9zdG5hbWUnLCB1Jzc0LTEzOC0xNDgtOC5kaGNwLmluc2lnaHRiYi5jb20nKSwodSdwcm90b2NvbCcsIHUndWRwJyksKHUnY2l0eScsIHUnTE9VSVNWSUxMRScpLCh1J3RpbWVzdGFtcCcsIHUnMjAxNC0wMy0xNiAwMzo0NTo1MScpLCh1J3JlZ2lvbicsIHUnS0VOVFVDS1knKSwodSdzeXNkZXNjJywgdSdMaW51eCBXTlIxMDAwdjIgMi42LjE1ICMxOTkgVGh1IEphbiAyOCAwOTo0OTo1NyBDU1QgMjAxMCBtaXBzIE1JQj0wMWEwMScpLCh1J2FzbicsIHUnMTA3OTYnKSwodSdzaWMnLCB1JzAnKSwodSd2ZXJzaW9uJywgdScyJyksKHUnaXAnLCB1Jzc0LjEzOC4xNDguOCcpLCh1J25haWNzJywgdScwJyksKHUnZ2VvJywgdSdVUycpLCh1J3BvcnQnLCB1JzE2MScpIg==',
           'source.asn': 10796,
           'source.geolocation.cc': 'US',
           'source.geolocation.city': 'LOUISVILLE',
           'source.geolocation.region': 'KENTUCKY',
           'source.ip': '74.138.148.8',
           'source.port': 161,
           'source.reverse_dns': '74-138-148-8.dhcp.insightbb.com',
           'time.observation': '2015-01-01T00:00:00+00:00',
           'time.source': '2014-03-16T03:45:51+00:00'},
          {'__type': 'Event',
           'classification.identifier': 'snmp',
           'classification.type': 'vulnerable service',
           'extra': '{"sysname": "", "sysdesc": ""}',
           'feed.name': 'ShadowServer QOTD',
           'protocol.application': 'snmp',
           'protocol.transport': 'udp',
           'raw': 'Iih1J3NlY3RvcicsIHUnJyksKHUnc3lzbmFtZScsIHUnJyksKHUnaG9zdG5hbWUnLCB1JycpLCh1J3Byb3RvY29sJywgdSd1ZHAnKSwodSdjaXR5JywgdSdTRU9VTCcpLCh1J3RpbWVzdGFtcCcsIHUnMjAxNC0wMy0xNiAwMzo0NTo1MScpLCh1J3JlZ2lvbicsIHUiU0VPVUwtVCdVS1BZT0xTSSIpLCh1J3N5c2Rlc2MnLCB1JycpLCh1J2FzbicsIHUnOTMxOCcpLCh1J3NpYycsIHUnMCcpLCh1J3ZlcnNpb24nLCB1JzInKSwodSdpcCcsIHUnMjIyLjIzMy4yMjUuMTk2JyksKHUnbmFpY3MnLCB1JzAnKSwodSdnZW8nLCB1J0tSJyksKHUncG9ydCcsIHUnMTYxJyki',
           'source.asn': 9318,
           'source.geolocation.cc': 'KR',
           'source.geolocation.city': 'SEOUL',
           'source.geolocation.region': "SEOUL-T'UKPYOLSI",
           'source.ip': '222.233.225.196',
           'source.port': 161,
           'time.observation': '2015-01-01T00:00:00+00:00',
           'time.source': '2014-03-16T03:45:51+00:00'},
          {'__type': 'Event',
           'classification.identifier': 'snmp',
           'classification.type': 'vulnerable service',
           'extra': '{"sysname": "CableHome", "sysdesc": "D-Link Wireless Voice Gateway <<HW_REV: B4; VENDOR: D-Link; BOOTR: 2.4.0beta1; SW_REV: 1.1.0.4; MODEL: DCM-704>>"}',
           'feed.name': 'ShadowServer QOTD',
           'protocol.application': 'snmp',
           'protocol.transport': 'udp',
           'raw': 'Iih1J3NlY3RvcicsIHUnJyksKHUnc3lzbmFtZScsIHUnQ2FibGVIb21lJyksKHUnaG9zdG5hbWUnLCB1JzU0MDM1YjU4LmNhdHYucG9vbC50ZWxla29tLmh1JyksKHUncHJvdG9jb2wnLCB1J3VkcCcpLCh1J2NpdHknLCB1J0JVREFQRVNUJyksKHUndGltZXN0YW1wJywgdScyMDE0LTAzLTE2IDAzOjQ1OjUxJyksKHUncmVnaW9uJywgdSdCVURBUEVTVCcpLCh1J3N5c2Rlc2MnLCB1J0QtTGluayBXaXJlbGVzcyBWb2ljZSBHYXRld2F5IDw8SFdfUkVWOiBCNDsgVkVORE9SOiBELUxpbms7IEJPT1RSOiAyLjQuMGJldGExOyBTV19SRVY6IDEuMS4wLjQ7IE1PREVMOiBEQ00tNzA0Pj4nKSwodSdhc24nLCB1JzU0ODMnKSwodSdzaWMnLCB1JzAnKSwodSd2ZXJzaW9uJywgdScyJyksKHUnaXAnLCB1Jzg0LjMuOTEuODgnKSwodSduYWljcycsIHUnMCcpLCh1J2dlbycsIHUnSFUnKSwodSdwb3J0JywgdScxNjEnKSI=',
           'source.asn': 5483,
           'source.geolocation.cc': 'HU',
           'source.geolocation.city': 'BUDAPEST',
           'source.geolocation.region': 'BUDAPEST',
           'source.ip': '84.3.91.88',
           'source.port': 161,
           'source.reverse_dns': '54035b58.catv.pool.telekom.hu',
           'time.observation': '2015-01-01T00:00:00+00:00',
           'time.source': '2014-03-16T03:45:51+00:00'}]


class TestShadowServerSNMPParserBot(test.BotTestCase, unittest.TestCase):
    """
    A TestCase for a ShadowServerSNMPParserBot.
    """

    @classmethod
    def set_bot(cls):
        cls.bot_reference = ShadowServerSNMPParserBot
        cls.default_input_message = EXAMPLE_REPORT

    def test_event(self):
        """ Test if correct Event has been produced. """
        self.run_bot()
        for i, EVENT in enumerate(EVENTS):
            self.assertMessageEqual(i, EVENT)


if __name__ == '__main__':
    unittest.main()

# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import pkg_resources
import unittest
import os

import intelmq.lib.test as test
from intelmq.bots.experts.squelcher.expert import SquelcherExpertBot

if os.environ.get('INTELMQ_TEST_DATABASES'):
    import psycopg2


INSERT_QUERY = '''
INSERT INTO {table}(
    "classification.identifier", "classification.type", notify, "source.asn",
    "source.ip", "time.source", "sent_at"
) VALUES (%s, %s, %s, %s, %s,
    LOCALTIMESTAMP + INTERVAL %s second,
    LOCALTIMESTAMP + INTERVAL %s second);
'''
INPUT1 = {"__type": "Event",
          "classification.identifier": "zeus",
          "classification.type": "botnet drone",
          "notify": False,
          "source.asn": 1,
          "source.ip": "192.0.2.1",
          "feed.name": "Example Feed",
          }

INPUT2 = INPUT1.copy()
INPUT2["classification.identifier"] = "https"
INPUT2["classification.type"] = "vulnerable service"
OUTPUT2 = INPUT2.copy()
OUTPUT2["notify"] = True

INPUT3 = INPUT1.copy()
INPUT3["classification.identifier"] = "https"
INPUT3["classification.type"] = "vulnerable service"
INPUT3["source.ip"] = "192.0.2.4"

INPUT4 = INPUT3.copy()
INPUT4["classification.identifier"] = "openresolver"
INPUT4["notify"] = True

INPUT5 = INPUT4.copy()
INPUT5["source.ip"] = "198.51.100.5"
OUTPUT5 = INPUT5.copy()
OUTPUT5["notify"] = False

INPUT6 = INPUT4.copy()
INPUT6["source.ip"] = "198.51.100.45"
OUTPUT6 = INPUT6.copy()
OUTPUT6["notify"] = False

INPUT7 = INPUT1.copy()
INPUT7['notify'] = True
INPUT7['source.fqdn'] = 'example.com'
del INPUT7['source.ip']
OUTPUT7 = INPUT7.copy()

INPUT8 = INPUT1.copy()
del INPUT8['notify']
del INPUT8['source.asn']
OUTPUT8 = INPUT8.copy()
OUTPUT8['notify'] = False

INPUT9 = {"__type": "Event",
          "notify": False,
          "extra": '{ "_origin": "dnsmalware" }'
          }

INPUT_INFINITE = {"__type": "Event",
                  "classification.identifier": "zeus",
                  "classification.type": "botnet drone",
                  "source.asn": 12312,
                  "source.ip": "192.0.2.1",
                  }
OUTPUT_INFINITE = INPUT_INFINITE.copy()
OUTPUT_INFINITE['notify'] = False

INPUT_RANGE = {"__type": "Event",
               "classification.identifier": "zeus",
               "classification.type": "botnet drone",
               "source.asn": 789,
               "source.ip": "10.0.0.10",
               }


@test.skip_database()
@test.skip_exotic()
class TestSquelcherExpertBot(test.BotTestCase, unittest.TestCase):
    """
    A TestCase for SquelcherExpertBot.
    """

    @classmethod
    def set_bot(cls):
        cls.bot_reference = SquelcherExpertBot
        cls.default_input_message = INPUT1
        if not os.environ.get('INTELMQ_TEST_DATABASES'):
            return
        cls.sysconfig = {"configuration_path": pkg_resources.resource_filename('intelmq',
                                                                               'etc/squelcher.conf'),
                         "host": "localhost",
                         "port": 5432,
                         "database": "intelmq",
                         "user": "intelmq",
                         "password": "intelmq",
                         "sending_time_interval": "2 years",
                         "sslmode": "allow",
                         "table": "tests",
                         "logging_level": "DEBUG",
                         }
        cls.con = psycopg2.connect(database=cls.sysconfig['database'],
                                   user=cls.sysconfig['user'],
                                   password=cls.sysconfig['password'],
                                   host=cls.sysconfig['host'],
                                   port=cls.sysconfig['port'],
                                   sslmode=cls.sysconfig['sslmode'],
                                   )
        cls.con.autocommit = True
        cls.cur = cls.con.cursor()
        cls.truncate(cls)

    def truncate(self):
        self.cur.execute("TRUNCATE TABLE {}".format(self.sysconfig['table']))

    def insert(self, classification_identifier, classification_type, notify, source_asn, source_ip,
               time_source, sent_at=None):
        if sent_at is not None:
            append = 'LOCALTIMESTAMP + INTERVAL %s second'
        else:
            append = '%s'
        query = '''
INSERT INTO {table}(
    "classification.identifier", "classification.type", notify, "source.asn",
    "source.ip", "time.source", "sent_at"
) VALUES (%s, %s, %s, %s, %s,
    LOCALTIMESTAMP + INTERVAL %s second,
    {append})
'''.format(table=self.sysconfig['table'], append=append)
        self.cur.execute(query, (classification_identifier, classification_type, notify,
                                 source_asn, source_ip, time_source, sent_at))

    def test_ttl_1(self):
        "event exists in db -> squelch"
        self.insert('zeus', 'botnet drone', True, 1, '192.0.2.1', '0')
        self.input_message = INPUT1
        self.run_bot()
        self.truncate()
        self.assertLogMatches('Found TTL 604800 for', levelname='DEBUG')
        self.assertMessageEqual(0, INPUT1)

    def test_ttl_2(self):
        "event in db is too old -> notify"
        self.insert('https', 'vulnerable service', True, 1, '192.0.2.1',
                    '- 01:45')
        self.input_message = INPUT2
        self.run_bot()
        self.truncate()
        self.assertLogMatches('Found TTL 3600 for', levelname='DEBUG')
        self.assertMessageEqual(0, OUTPUT2)

    def test_ttl_2h_squelch(self):
        "event is in db -> squelch"
        self.insert('https', 'vulnerable service', True, 1, '192.0.2.4',
                    '- 01:45')
        self.input_message = INPUT3
        self.run_bot()
        self.truncate()
        self.assertLogMatches('Found TTL 7200 for', levelname='DEBUG')
        self.assertMessageEqual(0, INPUT3)

    def test_network_match(self):
        """event is in db without notify -> notify
        find ttl based on network test"""
        self.insert('openresolver', 'vulnerable service', False, 1,
                    '198.51.100.5', '- 20:00')
        self.input_message = INPUT5
        self.run_bot()
        self.truncate()
        self.assertLogMatches('Found TTL 115200 for', levelname='DEBUG')
        self.assertMessageEqual(0, INPUT5)

    def test_network_match3(self):
        """event is in db -> squelch
        find ttl based on network test"""
        self.insert('openresolver', 'vulnerable service', True, 1,
                    '198.51.100.5', '- 25:00', '- 25:00')
        self.input_message = INPUT5
        self.run_bot()
        self.truncate()
        self.assertLogMatches('Found TTL 115200 for', levelname='DEBUG')
        self.assertMessageEqual(0, OUTPUT5)

    def test_address_match1(self):
        "event in db is too old -> notify"
        self.insert('openresolver', 'vulnerable service', True, 1,
                    '198.51.100.45', '- 25:00', '- 25:00')
        self.input_message = INPUT6
        self.run_bot()
        self.truncate()
        self.assertLogMatches('Found TTL 86400 for', levelname='DEBUG')
        self.assertMessageEqual(0, INPUT6)

    def test_address_match2(self):
        "event is in db -> squelch"
        self.insert('openresolver', 'vulnerable service', True, 1,
                    '198.51.100.45', '- 20:00', '- 20:00')
        self.input_message = INPUT6
        self.run_bot()
        self.truncate()
        self.assertLogMatches('Found TTL 86400 for', levelname='DEBUG')
        self.assertMessageEqual(0, OUTPUT6)

    def test_ttl_other_ident(self):
        "other event in db -> notify"
        self.insert('https', 'vulnerable service', True, 1, '198.51.100.5',
                    '- 01:45', '- 01:45')
        self.input_message = INPUT4
        self.run_bot()
        self.truncate()
        self.assertLogMatches('Found TTL 7200 for', levelname='DEBUG')
        self.assertMessageEqual(0, INPUT4)

    def test_domain(self):
        "only domain -> notify"
        self.input_message = INPUT7
        self.run_bot()
        self.truncate()
        self.assertNotRegexpMatchesLog("Found TTL")
        self.assertMessageEqual(0, OUTPUT7)

    def test_missing_asn(self):
        "no asn -> notify"
        self.input_message = INPUT8
        self.run_bot()
        self.truncate()
        self.assertNotRegexpMatchesLog("Found TTL")
        self.assertMessageEqual(0, OUTPUT8)

    def test_origin_dnsmalware(self):
        self.input_message = INPUT9
        self.run_bot()
        self.assertMessageEqual(0, INPUT9)

    def test_infinite(self):
        "never notify with ttl -1"
        self.input_message = INPUT_INFINITE
        self.run_bot()
        self.truncate()
        self.assertLogMatches('Found TTL -1 for', levelname='DEBUG')
        self.assertMessageEqual(0, OUTPUT_INFINITE)

    def test_iprange(self):
        "test if mechanism checking IP ranges"
        self.input_message = INPUT_RANGE
        self.run_bot()
        self.truncate()
        self.assertLogMatches('Found TTL 72643 for', levelname='DEBUG')

    def test_unsent_notify(self):
        """event exists, but is older than 1 day and has not been sent -> notify """
        self.insert('openresolver', 'vulnerable service', True, 1, '198.51.100.5', str(-25*3600))
        self.sysconfig['sending_time_interval'] = '1 day'
        self.input_message = INPUT5
        self.run_bot()
        self.sysconfig['sending_time_interval'] = '2 days'
        self.truncate()
        self.assertLogMatches('Found TTL 115200 for', levelname='DEBUG')
        self.assertMessageEqual(0, INPUT5)

    def test_unsent_squelch(self):
        """event exists, is younger than 2 days and has not been sent -> squelch """
        self.insert('openresolver', 'vulnerable service', True, 1, '198.51.100.5', '- 86400')
        self.input_message = INPUT5
        self.run_bot()
        self.truncate()
        self.assertLogMatches('Found TTL 115200 for', levelname='DEBUG')
        self.assertMessageEqual(0, OUTPUT5)

    @classmethod
    def tearDownClass(cls):
        if not os.environ.get('INTELMQ_TEST_DATABASES'):
            return
        cls.truncate(cls)
        cls.cur.close()
        cls.con.close()


if __name__ == '__main__':
    unittest.main()

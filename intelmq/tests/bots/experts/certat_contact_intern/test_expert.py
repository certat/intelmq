# -*- coding: utf-8 -*-
"""
Testing certat_contact
"""
import unittest
import os

import intelmq.lib.test as test
from intelmq.bots.experts.certat_contact_intern.expert import CERTatContactExpertBot

if os.environ.get('INTELMQ_TEST_DATABASES'):
    import psycopg2

INPUT1 = {"__type": "Event",
          "source.asn": 64496,
          "time.observation": "2015-01-01T00:00:00+00:00",
          "feed.code": "another-feed-code",
          }
OUTPUT1 = {"__type": "Event",
           "source.asn": 64496,
           "source.abuse_contact": "cert@example.com",
           "feed.code": "another-feed-code",
           "time.observation": "2015-01-01T00:00:00+00:00",
           "destination_visible": True,
           }
INPUT2 = {"__type": "Event",
          "source.asn": 64496,
          "time.observation": "2015-01-01T00:00:00+00:00",
          "feed.code": "example-feed",
          }
OUTPUT2 = {"__type": "Event",
           "source.asn": 64496,
           "source.abuse_contact": "cert@example.com",
           "time.observation": "2015-01-01T00:00:00+00:00",
           "feed.code": "example-feed",
           "destination_visible": False,
           }
OUTPUT3 = {"__type": "Event",
           "source.asn": 64496,
           "source.abuse_contact": "cert@example.com",
           "time.observation": "2015-01-01T00:00:00+00:00",
           "feed.code": "example-feed",
           "destination_visible": True,
           }


@test.skip_database()
class TestCERTatContactExpertBot(test.BotTestCase, unittest.TestCase):
    """
    A TestCase for CERTatContactExpertBot.
    """

    @classmethod
    def set_bot(cls):
        cls.bot_reference = CERTatContactExpertBot
        cls.default_input_message = INPUT1
        if not os.environ.get('INTELMQ_TEST_DATABASES'):
            return
        cls.sysconfig = {"autocommit": True,
                         "ascolumn": "asn",
                         "column": "contact",
                         "feed_code": "example-feed",
                         "host": "localhost",
                         "port": 5432,
                         "database": "intelmq",
                         "user": "intelmq",
                         "password": "intelmq",
                         "sslmode": "allow",
                         "table": "test_contacts",
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

    def insert(self, asn, contact, tlp_amber):
        query = '''
INSERT INTO {table}(
    "{ascolumn}", "{column}", "tlp-amber_{feed_code}"
) VALUES (%s, %s, %s)
'''.format(table=self.sysconfig['table'], column=self.sysconfig['column'], feed_code=self.sysconfig['feed_code'], ascolumn=self.sysconfig['ascolumn'])
        self.cur.execute(query, (asn, contact, tlp_amber))

    def test_simple(self):
        "simple query"
        self.insert(64496, "cert@example.com", False)
        self.input_message = INPUT1
        self.run_bot()
        self.truncate()
        self.assertMessageEqual(0, OUTPUT1)

    def test_special_feed(self):
        "query with special feed code"
        self.insert(64496, "cert@example.com", False)
        self.input_message = INPUT2
        self.run_bot()
        self.truncate()
        self.assertMessageEqual(0, OUTPUT2)

    def test_special_feed_amber(self):
        "query with special feed code"
        self.insert(64496, "cert@example.com", True)
        self.input_message = INPUT2
        self.run_bot()
        self.truncate()
        self.assertMessageEqual(0, OUTPUT3)

    @classmethod
    def tearDownClass(cls):
        if not os.environ.get('INTELMQ_TEST_DATABASES'):
            return
        cls.truncate(cls)
        cls.cur.close()
        cls.con.close()


if __name__ == '__main__':  # pragma: no cover
    unittest.main()

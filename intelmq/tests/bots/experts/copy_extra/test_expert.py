# -*- coding: utf-8 -*-
"""
Testing Copy Extra expert bot.
"""

import unittest

import intelmq.lib.test as test
from intelmq.bots.experts.copy_extra.expert import CopyExtraExpertBot

INPUT = {"__type": "Event",
         "time.observation": "2015-01-01T00:00:00+00:00",
         "extra.deviceid": "foo",
         "extra.devicerev": "bar",
         "extra.firmwarerev": 1}
OUTPUT = INPUT.copy()
OUTPUT["shareable_extra_info.deviceid"] = "foo"
OUTPUT["shareable_extra_info.firmwarerev"] = 1
INPUT_NO_EXTRA = {"__type": "Event",
                  "time.observation": "2015-01-01T00:00:00+00:00"}


class TestCopyExtraExpertBot(test.BotTestCase, unittest.TestCase):
    """
    A TestCase for CopyExtraExpertBot.
    """

    @classmethod
    def set_bot(cls):
        cls.bot_reference = CopyExtraExpertBot
        cls.sysconfig = {'keys': ['deviceid', 'firmwarerev']}
        cls.default_input_message = {'__type': 'Event'}

    def test_events(self):
        """ Test if correct Events have been produced. """
        self.input_message = INPUT
        self.run_bot()
        self.assertMessageEqual(0, OUTPUT)

    def test_no_extra(self):
        """ Test for no extra field """
        self.input_message = INPUT_NO_EXTRA
        self.run_bot()
        self.assertMessageEqual(0, INPUT_NO_EXTRA)


if __name__ == '__main__':
    unittest.main()

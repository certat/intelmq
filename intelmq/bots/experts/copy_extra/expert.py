# -*- coding: utf-8 -*-
"""
Modify Expert bot let's you manipulate all fields with a config file.
"""
from intelmq.lib.bot import Bot


class CopyExtraExpertBot(Bot):
    def process(self):
        event = self.receive_message()

        for extrakey, extravalue in event.to_dict(hierarchical=True).get('extra', {}).items():
            if extrakey in self.parameters.keys:
                event['shareable_extra_info.%s' % extrakey] = extravalue

        self.send_message(event)
        self.acknowledge_message()


BOT = CopyExtraExpertBot

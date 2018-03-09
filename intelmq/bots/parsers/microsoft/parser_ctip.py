# -*- coding: utf-8 -*-
"""
Parses CTIP data in JSON format.

Key indicatorexpirationdatetime is ignored, meaning is unknown.
"""
import json

from intelmq.lib.bot import ParserBot


MAPPING = {"description": "event_description.text",
           "externalid": "malware.name",
           "firstreporteddatetime": "time.source",
           "networksourceipv4": "source.ip",
           "networksourceport": "source.port",
           "networkdestinationipv4": "destination.ip",
           "networkdestinationport": "destination.port",
           "networksourceasn": "source.asn",
           "hostname": "destination.fqdn",
           }
EXTRA = {"additionalmetadata": "additionalmetadata",
         "tlplevel": "tlp",
         "isproductlicensed": "isproductlicensed",
         "ispartnershareable": "ispartnershareable",
         "useragent": "user_agent",
         "severity": "severity",
         "tags": "tags",
         }


class MicrosoftCTIPParserBot(ParserBot):

    parse = ParserBot.parse_json
    recover_line = ParserBot.recover_line_json

    def parse_line(self, line, report):
        raw = json.dumps(line, sort_keys=True)  # not applying formatting here
        if line['version'] != 1.5:
            raise ValueError('Data is in unknown format %r, only version 1.5 is supported.' % line['version'])
        if line['indicatorthreattype'] != 'Botnet':
            raise ValueError('Unknown indicatorthreattype %r, only Botnet is supported.' % line['indicatorthreattype'])
        if 'additionalmetadata' in line and line['additionalmetadata'] in [[], [''], ['null'], [None]]:
            del line['additionalmetadata']
        event = self.new_event(report)
        extra = {}
        for key, value in line.items():
            if key in ['version', 'indicatorthreattype', 'confidence', 'indicatorexpirationdatetime']:
                continue
            if value in ['', None]:
                continue
            if key == "firstreporteddatetime":
                value += ' UTC'
            if key == "hostname" and value == line["networkdestinationipv4"]:  # ignore IP in FQDN field
                continue
            if key in MAPPING:
                event[MAPPING[key]] = value
            else:
                extra[EXTRA[key]] = value
        if extra:
            event.add('extra', extra)
        event.add('feed.accuracy',
                  event.get('feed.accuracy', 100) * line['confidence'] / 100,
                  overwrite=True)
        event.add('classification.type', 'botnet drone')
        event.add('raw', raw)
        yield event


BOT = MicrosoftCTIPParserBot
# -*- coding: utf-8 -*-
"""
Parses BingMURLs data in JSON format.
"""
import json

from intelmq.lib.bot import ParserBot


MAPPING = {"Description": "event_description.text",
           "IndicatorThreatType": "classification.identifier",  # MaliciousUrl
           "TLPLevel": "tlp",
           "FirstReportedDateTime": "time.source",
           "NetworkDestinationAsn": "source.asn",
           "NetworkDestinationIPv4": "source.ip",
           "NetworkDestinationPort": "source.port",
           "Url": "source.url",
           }
EXTRA = {"Attributable": "attributable",
         "IsProductLicensed": "isproductlicensed",
         "IsPartnerShareable": "ispartnershareable",
         "IndicatorProvider": "indicator_provider",
         "IndicatorExpirationDateTime": "indicator_expiration_date_time",
         "ThreatDetectionProduct": "threat_detection_product",
         "Tags": "tags",
         }


class MicrosoftCTIPParserBot(ParserBot):

    parse = ParserBot.parse_json

    def recover_line(self, line: dict):
        return json.dumps([line], sort_keys=True)  # not applying formatting here

    def parse_line(self, line, report):
        raw = self.recover_line(line)
        if line['Version'] != 1.5:
            raise ValueError('Data is in unknown format %r, only version 1.5 is supported.' % line['version'])
        if line['IndicatorThreatType'] != 'MaliciousUrl':
            raise ValueError('Unknown indicatorthreattype %r, only MaliciousUrl is supported.' % line['indicatorthreattype'])
        event = self.new_event(report)
        extra = {}
        for key, value in line.items():
            if key == "LastReportedDateTime" and value != line["FirstReportedDateTime"]:
                raise ValueError("Unexpectedly seen different values in 'FirstReportedDateTime' and "
                                 "'LastReportedDateTime', please open a bug report with example data.")
            elif key == "LastReportedDateTime":
                continue
            if key == 'Version':
                continue
            if key == 'NetworkDestinationIPv4' and value in ['0.0.0.0', '255.255.255.255']:
                continue
            if key == 'NetworkDestinationAsn' and value == 0:
                continue
            if key in MAPPING:
                event[MAPPING[key]] = value
            else:
                extra[EXTRA[key]] = value
        if extra:
            event.add('extra', extra)
        event.add('classification.type', 'blacklist')
        event.add('raw', raw)
        yield event


BOT = MicrosoftCTIPParserBot

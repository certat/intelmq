"""
CERT-EU parser
"""
from intelmq.lib.bot import ParserBot
from collections import defaultdict
from intelmq.lib.harmonization import DateTime


class CertEUCSVParserBot(ParserBot):

    abuse_to_intelmq = defaultdict(lambda: "unknown", {
        "backdoor": "backdoor",
        "blacklist": "blacklist",
        "botnet drone": "botnet drone",
        "brute-force": "brute-force",
        "c&c": "c&c",
        "compromised server": "compromised",
        "ddos infrastructure": "ddos",
        "ddos target": "ddos",
        "defacement": "defacement",
        "dropzone": "dropzone",
        "exploit url": "exploit",
        "ids alert": "ids alert",
        "malware configuration": "malware configuration",
        "malware url": "malware",
        "phishing": "phishing",
        "ransomware": "ransomware",
        "scanner": "scanner",
        "spam infrastructure": "spam",
        "test": "test",
        "vulnerable service": "vulnerable service"
    })

#    csv_fieldnames = [
#        "feed code", "source ip", "source time", "observation time", "tlp",
#        "description",
#        "type", "protocol", "destination port", "first_seen", "last_seen",
#        "count", "source cc", "source country", "source city",
#        "source longitude", "source latitude",
#        "city",  # empty
#        "threat type",
#        "source location",  # just a combination of long and lat
#        "source as name", "source bgp prefix", "source geohash", "confidence level",
#        "source asn",
#        "reported asn",
#        "target", "url", "domain name",
#        "version", "expiration date", "source port", "status", "source",
#        "scanner", "abuse_contact", "ns1", "ns2",
#        "response", "recent", "country",  # empty
#        "as name",  # empty
#        "reported cc",
#        "reported as name",
#        ]
    unknown_fields = ["threat type", "ns1", "ns2", "response", "recent"]
    ignore_lines_starting = ["#"]

    def parse_line(self, line, report):
        event = self.new_event(report)
        if line["version"] != "1.5":
            raise ValueError("Unknown version %r. Please report this with an example."
                             "" % line["version"])
        for unknown in self.unknown_fields:
            if line[unknown]:
                raise ValueError("Unable to parse field %r. Please report this with an example"
                                 "" % unknown)

        if "feed code" in line:
            event["extra.datasource"] = line["feed code"]
        event.add("source.ip", line["source ip"])
        event.add("source.network", line["source bgp prefix"])
        event.add("extra.cert_eu_time_observation",
                  DateTime.sanitize(line["observation time"]))
        event.add("tlp", line["tlp"])
        event.add("event_description.text", line["description"])
        event.add("classification.type", self.abuse_to_intelmq[line["type"]])
        if "count" in line:
            event["extra.count"] = int(line["count"]) if line["count"] else None
        event.add("time.source", line["source time"])
        event.add("source.geolocation.country", line["source country"])
        event.add("protocol.application", line["protocol"])
        event.add("destination.port", line["destination port"])
        event.add("source.geolocation.latitude", line["source latitude"])
        event.add("source.geolocation.city", line["source city"])
        event.add("source.geolocation.geoip_cc", line["source cc"])
        event.add("source.geolocation.longitude", line["source longitude"])
        event.add("extra.source.geolocation.geohash", line["source geohash"])
        if "first_seen" in line:
            event["extra.first_seen"] = line["first_seen"]
        if "num_sensors" in line:
            event["extra.num_sensors"] = line["num_sensors"]
        if line["confidence level"] != '':
            event.add('feed.accuracy',
                      event.get('feed.accuracy', 100) * int(line["confidence level"]) / 100,
                      overwrite=True)
        if "last_seen" in line:
            event["extra.last_seen"] = line["last_seen"]
        if "expiration date" in line:
            event["extra.expiration_date"] = line["expiration date"]
        if "status" in line:
            event["status"] = line["status"]
        event.add("event_description.target", line["target"])
        event.add("source.url", line["url"])
        event.add("source.port", line["port"])
        event.add("source.abuse_contact", line["abuse contact"])
        event.add("source.asn", line["source asn"])
        event.add("source.as_name", line["source as name"])
        event.add("source.fqdn", line["domain name"])

        event.add("raw", self.recover_line(line))
        yield event

    parse = ParserBot.parse_csv_dict
    recover_line = ParserBot.recover_line_csv_dict


BOT = CertEUCSVParserBot

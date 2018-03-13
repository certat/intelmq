# -*- coding: utf-8 -*-
"""
Utilities for intelmqcli.

Static data (queries)
"""
import argparse
import json
import os
import rt
import subprocess
import pkg_resources
import sys

import intelmq.lib.utils as utils

import psycopg2
import psycopg2.extras


__all__ = ['BASE_WHERE', 'CSV_FIELDS', 'EPILOG',
           'QUERY_DISTINCT_CONTACTS_BY_INCIDENT', 'QUERY_EVENTS_BY_ASCONTACT_INCIDENT',
           'QUERY_FEED_NAMES', 'QUERY_GET_TEXT', 'QUERY_IDENTIFIER_NAMES',
           'QUERY_INSERT_CONTACT', 'QUERY_OPEN_EVENTS_BY_FEEDNAME', 'QUERY_HALF_PROC_INCIDENTS',
           'QUERY_OPEN_EVENT_IDS_BY_TAXONOMY', 'QUERY_OPEN_EVENT_REPORTS_BY_TAXONOMY',
           'QUERY_OPEN_FEEDNAMES', 'QUERY_OPEN_TAXONOMIES', 'QUERY_TAXONOMY_NAMES',
           'QUERY_TEXT_NAMES', 'QUERY_TYPE_NAMES', 'QUERY_UPDATE_CONTACT', 'USAGE',
           'getTerminalHeight', 'IntelMQCLIContollerTemplate'
           ]

EPILOG = """
Searches for all unprocessed incidents. Incidents will be filtered by country
code and the TLD of a domain according to configuration.
The search can be restricted to one source feed.

After the start, intelmqcli will immediately connect to RT with the given
credentials. The incidents will be shown grouped by the contact address if
known or the ASN otherwise.

You have 3 options here:
* Select one group by giving the id (number in first column) and show the email
and all events in detail
* Automatic sending of all incidents with 'a'
* Quit with 'q'

For the detailed view, the recipient, the subject and the mail text will be
shown, and below the technical data as csv. If the terminal is not big enough,
the data will not be shown in full. In this case, you can press 't' for the
table mode. less will be opened with the full text and data, whereas the data
will be formated as table, which is much easier to read and interpret.
The requestor (recipient of the mail) can be changed manually by pressing 'r'
and in the following prompt the address is asked. After sending, you can
optionally save the (new) address to the database linked to the ASNs.
If you are ready to submit the incidents to RT and send the mails out, press
's'.
'b' for back jumps to the incident overview and 'q' quits.

Exit codes:
 0 if no errors happend or only errors which could be handled. Check the
   output if recoverable errors happened.
 1 if unrecoverable errors happened
 2 if user input or configuration is faulty
"""
USAGE = '''
    intelmqcli
    intelmqcli --dry-run
    intelmqcli --verbose
    intelmqcli --batch
    intelmqcli --quiet
    intelmqcli --compress-csv
    intelmqcli --list-feeds
    intelmqcli --list-identifiers
    intelmqcli --list-taxonomies
    intelmqcli --taxonomy='taxonomy'
    intelmqcli --type='type'
    intelmqcli --identifier='identifier'
    intelmqcli --list-types
    intelmqcli --list-texts
    intelmqcli --text='boilerplate name'
    intelmqcli --feed='feedname' '''

SUBJECT = {"abusive content": "Abusive content (spam, ...)",
           "malicious code": "Malicious code (malware, botnet, ...)",
           "information gathering": "Information Gathering (scanning, ...)",
           "intrusion attempts": "Intrusion Attempt",
           "intrusions": "Network intrusion",
           "availability": "Availability (DDOS, ...)",
           "information content security": "Information Content Security (dropzone,...)",
           "fraud": "Fraud",
           "vulnerable": "Vulnerable device",
           "other": "Other",
           "test": "Test"
           }

QUERY_FEED_NAMES = "SELECT DISTINCT \"feed.name\" from events"

QUERY_IDENTIFIER_NAMES = "SELECT DISTINCT \"classification.identifier\" from events"

QUERY_TAXONOMY_NAMES = "SELECT DISTINCT \"classification.taxonomy\" from events"

QUERY_TYPE_NAMES = "SELECT DISTINCT \"classification.type\" from events"

QUERY_TEXT_NAMES = "SELECT DISTINCT \"key\" from boilerplates"

""" This is the list of fields (and their respective order) which we intend to
send out.  This is based on the order and fields of shadowserver.

Shadowserver format:
    timestamp,"ip","protocol","port","hostname","packets","size","asn","geo","region","city","naics","sic","sector"
"""
CSV_FIELDS = ["time.source", "source.ip", "protocol.transport", "source.port", "protocol.application",
              "source.fqdn", "source.local_hostname", "source.local_ip", "source.url",
              "source.asn", "source.geolocation.cc",
              "source.geolocation.city",
              "classification.taxonomy", "classification.type", "classification.identifier",
              "destination.ip", "destination.port", "destination.fqdn", "destination.url",
              "feed", "event_description.text", "event_description.url", "malware.name", "extra",
              "comment", "additional_field_freetext", "feed.documentation", "version: 1.2"
              ]

QUERY_UPDATE_CONTACT = """
UPDATE as_contacts SET
    contacts = %s
WHERE
    asnum = %s
"""

QUERY_INSERT_CONTACT = """
INSERT INTO as_contacts (
    asnum, contacts, comment, unreliable
) VALUES (
    %s, %s, %s, FALSE
)
"""

QUERY_GET_TEXT = """
SELECT
    body
FROM {texttab}
WHERE
    key = %s
"""

BASE_WHERE = """
"notify" = TRUE AND
"time.source" >= now() - interval %s AND
"sent_at" IS NULL AND
"feed.name" IS NOT NULL AND
"classification.taxonomy" IS NOT NULL AND
"source.abuse_contact" IS NOT NULL AND
(UPPER("source.geolocation.cc") = %s OR SUBSTRING("source.fqdn" from %s) = %s)
"""
# PART 1: CREATE REPORTS
QUERY_OPEN_FEEDNAMES = """
SELECT
    DISTINCT "feed.name"
FROM "events"
WHERE
    "rtir_report_id" IS NULL AND
""" + BASE_WHERE
QUERY_OPEN_EVENTS_BY_FEEDNAME = """
SELECT *
FROM "events"
WHERE
    "feed.name" = %s AND
    "rtir_report_id" IS NULL AND
""" + BASE_WHERE
# PART 2: INCIDENTS
QUERY_OPEN_TAXONOMIES = """
SELECT
    DISTINCT "classification.taxonomy"
FROM "events"
WHERE
    "rtir_report_id" IS NOT NULL AND
    "rtir_incident_id" IS NULL AND
""" + BASE_WHERE
QUERY_OPEN_EVENT_REPORTS_BY_TAXONOMY = """
SELECT
    DISTINCT "rtir_report_id"
FROM "events"
WHERE
    "rtir_report_id" IS NOT NULL AND
    "rtir_incident_id" IS NULL AND
    "classification.taxonomy" = %s AND
""" + BASE_WHERE
QUERY_OPEN_EVENT_IDS_BY_TAXONOMY = """
SELECT
    "id"
FROM "events"
WHERE
    "rtir_report_id" IS NOT NULL AND
    "rtir_incident_id" IS NULL AND
    "classification.taxonomy" = %s AND
""" + BASE_WHERE
QUERY_HALF_PROC_INCIDENTS = """
SELECT
    DISTINCT "rtir_incident_id",
    "classification.taxonomy"
FROM "events"
WHERE
    "rtir_report_id" IS NOT NULL AND
    "rtir_incident_id" IS NOT NULL AND
    rtir_investigation_id IS NULL AND
""" + BASE_WHERE
# PART 3: INVESTIGATIONS
QUERY_DISTINCT_CONTACTS_BY_INCIDENT = """
SELECT
DISTINCT "source.abuse_contact"
FROM events
WHERE
    rtir_report_id IS NOT NULL AND
    rtir_incident_id = %s AND
    rtir_investigation_id IS NULL AND
""" + BASE_WHERE
DRY_QUERY_DISTINCT_CONTACTS_BY_TAXONOMY = """
SELECT
DISTINCT "source.abuse_contact"
FROM events
WHERE
    rtir_report_id IS NOT NULL AND
    "rtir_incident_id" IS NULL AND
    rtir_investigation_id IS NULL AND
    "classification.taxonomy" = %s AND
""" + BASE_WHERE
QUERY_EVENTS_BY_ASCONTACT_INCIDENT = """
SELECT
    to_char("time.source",
            'YYYY-MM-DD"T"HH24:MI:SSOF') as "time.source",
    id,
    "feed.code" as feed,
    "source.ip",
    "source.port",
    "source.asn",
    "source.geolocation.cc",
    "source.geolocation.city",
    "source.fqdn",
    "source.local_hostname",
    "source.local_ip",
    "classification.identifier",
    "classification.taxonomy",
    "classification.type",
    "comment",
    "destination.ip",
    "destination.port",
    "destination.fqdn",
    "destination.tor_node",
    "destination.url",
    "event_description.target",
    "shareable_extra_info" AS "extra",
    "feed.documentation",
    "malware.name",
    "protocol.application",
    "protocol.transport"
FROM v_events_filtered
WHERE
    rtir_report_id IS NOT NULL AND
    rtir_incident_id = %s AND
    rtir_investigation_id IS NULL AND
    "source.abuse_contact" = %s AND
""" + BASE_WHERE
DRY_QUERY_EVENTS_BY_ASCONTACT_TAXONOMY = QUERY_EVENTS_BY_ASCONTACT_INCIDENT[:QUERY_EVENTS_BY_ASCONTACT_INCIDENT.find('WHERE') + 6] + """
    rtir_report_id IS NOT NULL AND
    rtir_investigation_id IS NULL AND
    "classification.taxonomy" = %s AND
    "source.abuse_contact" = %s AND
""" + BASE_WHERE


def getTerminalHeight():
    return int(subprocess.check_output(['stty', 'size']).strip().split()[0])


class IntelMQCLIContollerTemplate():
    additional_where = ""
    usage = ''
    epilog = ''
    additional_params = ()
    dryrun = False
    quiet = False

    def __init__(self):

        self.parser = argparse.ArgumentParser(prog=self.appname,
                                              usage=self.usage,
                                              epilog=self.epilog,
                                              formatter_class=argparse.RawDescriptionHelpFormatter,
                                              )
        VERSION = pkg_resources.get_distribution("intelmq").version
        self.parser.add_argument('--version',
                                 action='version', version=VERSION)
        self.parser.add_argument('-v', '--verbose', action='store_true',
                                 help='Print verbose messages.')

        self.parser.add_argument('-f', '--feed', nargs='+',
                                 help='Show only incidents reported by one of the given feeds.')
        self.parser.add_argument('--skip-feed', nargs='+',
                                 help='Skip incidents reported by one of the given feeds.')
        self.parser.add_argument('--taxonomy', nargs='+',
                                 help='Select only events with given taxonomy.')
        self.parser.add_argument('--skip-taxonomy', nargs='+',
                                 help='Skip events with given taxonomy.')
        self.parser.add_argument('-a', '--asn', type=int, nargs='+',
                                 help='Specify one or more AS numbers (integers) to process.')
        self.parser.add_argument('--skip-asn', type=int, nargs='+',
                                 help='Specify one or more AS numbers (integers) to skip.')
        self.parser.add_argument('--type', nargs='+',
                                 help='Specify one or more classifications types to process.')
        self.parser.add_argument('--skip-type', nargs='+',
                                 help='Specify one or more classifications types to skip.')
        self.parser.add_argument('--identifier', nargs='+',
                                 help='Specify one or more classifications identifiers to process.')
        self.parser.add_argument('--skip-identifier', nargs='+',
                                 help='Specify one or more classifications identifiers to skip.')

        self.parser.add_argument('-b', '--batch', action='store_true',
                                 help='Run in batch mode (defaults to "yes" to all).')
        self.parser.add_argument('-q', '--quiet', action='store_true',
                                 help='Do not output anything, except for error messages. Useful in combination with --batch.')
        self.parser.add_argument('-n', '--dry-run', action='store_true',
                                 help='Do not store anything or change anything. Just simulate.')

        self.parser.add_argument('--time-interval', nargs='+', default='4 days',
                                 help='time interval, parseable by postgres.'
                                      'defaults to "4 days".')

    def setup(self):
        self.args = self.parser.parse_args()

        if self.args.verbose:
            self.verbose = True
        if self.args.dry_run:
            self.dryrun = True
        if self.args.batch:
            self.batch = True
        if self.args.quiet:
            self.quiet = True
        self.time_interval = '' .join(self.args.time_interval)

        if self.args.feed:
            self.additional_where += """ AND "feed.name" = ANY(%s::VARCHAR[]) """
            self.additional_params += ('{' + ','.join(self.args.feed) + '}', )
        if self.args.skip_feed:
            self.additional_where += """ AND "feed.name" != ANY(%s::VARCHAR[]) """
            self.additional_params += ('{' + ','.join(self.args.skip_feed) + '}', )
        if self.args.asn:
            self.additional_where += """ AND "source.asn" = ANY(%s::INT[]) """
            self.additional_params += ('{' + ','.join(map(str, self.args.asn)) + '}', )
        if self.args.skip_asn:
            self.additional_where += """ AND "source.asn" != ANY(%s::INT[]) """
            self.additional_params += ('{' + ','.join(map(str, self.args.skip_asn)) + '}', )
        if self.args.taxonomy:
            self.additional_where += """ AND "classification.taxonomy" = ANY(%s::VARCHAR[]) """
            self.additional_params += ('{' + ','.join(self.args.taxonomy) + '}', )
        if self.args.skip_taxonomy:
            self.additional_where += """ AND "classification.taxonomy" != ANY(%s::VARCHAR[]) """
            self.additional_params += ('{' + ','.join(self.args.skip_taxonomy) + '}', )
        if self.args.type:
            self.additional_where += """ AND "classification.type" = ANY(%s::VARCHAR[]) """
            self.additional_params += ('{' + ','.join(self.args.type) + '}', )
        if self.args.skip_type:
            self.additional_where += """ AND "classification.type" != ANY(%s::VARCHAR[]) """
            self.additional_params += ('{' + ','.join(self.args.skip_type) + '}', )
        if self.args.identifier:
            self.additional_where += """ AND "classification.identifier" = ANY(%s::VARCHAR[]) """
            self.additional_params += ('{' + ','.join(self.args.identifier) + '}', )
        if self.args.skip_identifier:
            self.additional_where += """ AND "classification.identifier" != ANY(%s::VARCHAR[]) """
            self.additional_params += ('{' + ','.join(self.args.skip_identifier) + '}', )

        with open('/etc/intelmq/intelmqcli.conf') as conf_handle:
            self.config = json.load(conf_handle)
        home = os.path.expanduser("~")
        with open(os.path.expanduser(home + '/.intelmq/intelmqcli.conf')) as conf_handle:
            user_config = json.load(conf_handle)

        for key, value in user_config.items():
            if key in self.config and isinstance(value, dict):
                self.config[key].update(value)
            else:
                self.config[key] = value

        if self.quiet:
            stream = None
        else:
            stream = sys.stderr
        self.logger = utils.log('intelmqcli', syslog='/dev/log',
                                log_level=self.config['log_level'].upper(),
                                stream=stream, log_format_stream='%(message)s')

        self.rt = rt.Rt(self.config['rt']['uri'], self.config['rt']['user'],
                        self.config['rt']['password'])

    def connect_database(self):
        self.con = psycopg2.connect(database=self.config['database']['database'],
                                    user=self.config['database']['user'],
                                    password=self.config['database']['password'],
                                    host=self.config['database']['host'],
                                    port=self.config['database']['port'],
                                    sslmode=self.config['database']['sslmode'],
                                    )
        self.con.autocommit = False  # Starts transaction in the beginning
        self.cur = self.con.cursor(cursor_factory=psycopg2.extras.RealDictCursor)

    def execute(self, query, parameters=(), extend=True):
        """
        Passes query to database.

        Parameters:
            extend:
                If True, the parameters for BASE_WHERE are added (time interval,
                country code, FQDN from config, and additional parameters)
                If False, parameters are used as given.
        """
        if extend:
            query = query + self.additional_where
            parameters = parameters + (self.time_interval, self.config['filter']['cc'],
                                       '.' * len(self.config['filter']['fqdn']) + '$',
                                       self.config['filter']['fqdn']) + self.additional_params
        self.logger.debug(self.cur.mogrify(query, parameters))
        if not self.dryrun or query.strip().upper().startswith('SELECT'):
            self.cur.execute(query, parameters)

    def executemany(self, query, parameters=(), extend=True):
        """ Passes query to database. """
        if extend:
            query = query + self.additional_where
            parameters = [param + (self.time_interval, ) + self.additional_params for param in parameters]
        if self.config['log_level'].upper() == 'DEBUG':  # on other log levels we can skip the iteration
            for param in parameters:
                self.logger.debug(self.cur.mogrify(query, param))
            if not parameters:
                self.logger.debug(self.cur.mogrify(query))
        if not self.dryrun or query.strip().upper().startswith('SELECT'):  # no update in dry run
            self.cur.executemany(query, parameters)

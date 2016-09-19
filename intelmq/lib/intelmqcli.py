# -*- coding: utf-8 -*-
"""
Utilities for intelmqcli.

Static data (queries)

TODO: Implement cc-filer
TODO: Implement fqdn-filter
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

# Use unicode for all input and output, needed for Py2
psycopg2.extensions.register_type(psycopg2.extensions.UNICODE)
psycopg2.extensions.register_type(psycopg2.extensions.UNICODEARRAY)

__all__ = ['BASE_WHERE', 'CSV_FIELDS', 'EPILOG',
           'QUERY_DISTINCT_CONTACTS_BY_INCIDENT', 'QUERY_EVENTS_BY_ASCONTACT_INCIDENT',
           'QUERY_FEED_NAMES', 'QUERY_GET_TEXT', 'QUERY_IDENTIFIER_NAMES',
           'QUERY_INSERT_CONTACT', 'QUERY_OPEN_EVENTS_BY_FEEDNAME',
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
    intelmqcli --list-types
    intelmqcli --list-texts
    intelmqcli --text='boilerplate name'
    intelmqcli --feed='feedname' '''
<<<<<<< HEAD
QUERY_COUNT_ASN = """
    SELECT
        COUNT(*) as count,
        COALESCE({conttab}.contacts, '') as contacts,
        string_agg(DISTINCT cast({evtab}."source.asn" as varchar), ', ') as asn,
        string_agg(DISTINCT {evtab}."classification.type", ', ') as classification,
        string_agg(DISTINCT {evtab}."classification.taxonomy", ', ') as taxonomy,
        string_agg(DISTINCT {evtab}."feed.code", ', ') as feeds,
        COALESCE({conttab}.contacts, cast({evtab}."source.asn" as varchar))
            as grouping
    FROM {evtab}
    LEFT OUTER JOIN as_contacts ON {evtab}."source.asn" = {conttab}.asnum
    WHERE
        notify = TRUE AND
        {evtab}.rtir_report_id IS NOT NULL AND
        (
            {evtab}.rtir_incident_id IS NULL OR
            {evtab}.rtir_investigation_id IS NULL
        )
        AND
        (
            {evtab}."source.geolocation.cc" LIKE '{cc}' OR
            {evtab}."source.fqdn" LIKE %s
        )
        AND {evtab}."feed.name" ILIKE %s AND
        {evtab}."time.source" IS NOT NULL AND
        {evtab}."time.source" >= now() - interval '1 month' AND
        {evtab}."classification.taxonomy" ILIKE %s
    GROUP BY {conttab}.contacts, grouping;
    """
=======

SUBJECT = {"Abusive Content": "Abusive content (spam, ...)",
           "Malicious Code": "Malicious code (malware, botnet, ...)",
           "Information Gathering": "Information Gathering (scanning, ...)",
           "Intrusion Attempts": "Intrusion Attempt",
           "Intrusions": "Network intrusion",
           "Availability": "Availability (DDOS, ...)",
           "Information Content Security": "Information Content Security (dropzone,...)",
           "Fraud": "Fraud",
           "Vulnerable": "Vulnerable device",
           "Other": "Other",
           "Test": "Test"
           }
>>>>>>> 544e5e8d61b164e38dd07308812c72736b4961d2

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
<<<<<<< HEAD
CSV_FIELDS=["time.source", "source.ip", "protocol.transport", "source.port", "protocol.application",
            "source.fqdn", "source.local_hostname", "source.local_ip", "source.url",
            "source.asn", "source.geolocation.cc",
            "source.geolocation.city",
            "classification.taxonomy", "classification.type", "classification.identifier",
            "destination.ip", "destination.port", "destination.fqdn", "destination.url",
            "feed", "event_description.text", "event_description.url", "malware.name", "extra", "comment", "additional_field_freetext", "version: 1.1"
            ]

QUERY_BY_ASCONTACT = """
SELECT
    to_char({evtab}."time.source",
            'YYYY-MM-DD"T"HH24:MI:SSOF') as "time.source",
    {evtab}.id,
    {evtab}."feed.code" as feed,
    {evtab}."source.ip",
    {evtab}."source.port",
    {evtab}."source.asn",
    {evtab}."source.network",
    {evtab}."source.geolocation.cc",
    {evtab}."source.geolocation.region",
    {evtab}."source.geolocation.city",
    {evtab}."source.account",
    {evtab}."source.fqdn",
    {evtab}."source.local_hostname",
    {evtab}."source.local_ip",
    {evtab}."source.reverse_dns",
    {evtab}."source.tor_node",
    {evtab}."source.url",
    {evtab}."classification.identifier",
    {evtab}."classification.taxonomy",
    {evtab}."classification.type",
    {evtab}."comment",
    {evtab}."destination.ip",
    {evtab}."destination.port",
    {evtab}."destination.asn",
    {evtab}."destination.network",
    {evtab}."destination.geolocation.cc",
    {evtab}."destination.geolocation.region",
    {evtab}."destination.geolocation.city",
    {evtab}."destination.account",
    {evtab}."destination.fqdn",
    {evtab}."destination.local_hostname",
    {evtab}."destination.local_ip",
    {evtab}."destination.reverse_dns",
    {evtab}."destination.tor_node",
    {evtab}."destination.url",
    {evtab}."event_description.target",
    {evtab}."event_description.text",
    {evtab}."event_description.url",
    {evtab}."event_hash",
    {evtab}."extra",
    {evtab}."feed.accuracy",
    {evtab}."malware.hash",
    {evtab}."malware.hash.md5",
    {evtab}."malware.hash.sha1",
    {evtab}."malware.name",
    {evtab}."malware.version",
    {evtab}."misp_uuid",
    {evtab}."notify",
    {evtab}."protocol.application",
    {evtab}."protocol.transport",
    {evtab}."rtir_report_id",
    {evtab}."screenshot_url",
    {evtab}."status",
    {evtab}."time.observation"
FROM {evtab}
LEFT OUTER JOIN {conttab} ON {evtab}."source.asn" = {conttab}.asnum
WHERE
    notify = TRUE AND
    {evtab}.rtir_report_id IS NOT NULL AND
    (
        {evtab}.rtir_incident_id IS NULL OR
        {evtab}.rtir_investigation_id IS NULL
    ) AND
    (
        {evtab}."source.geolocation.cc" LIKE '{cc}' OR
        {evtab}."source.fqdn" LIKE %s
    ) AND
    {conttab}.contacts = %s AND
    {evtab}."feed.name" ILIKE %s AND
    {evtab}."time.source" IS NOT NULL AND
    {evtab}."time.source" >= now() - interval '1 month' AND
    {evtab}."classification.taxonomy" ILIKE %s;
"""

QUERY_BY_ASNUM = """
SELECT
    to_char({evtab}."time.source" at time zone 'UTC',
            'YYYY-MM-DD"T"HH24:MI:SSOF') as "time.source",
    {evtab}.id,
    {evtab}."feed.code" as feed,
    {evtab}."source.ip",
    {evtab}."source.port",
    {evtab}."source.asn",
    {evtab}."source.network",
    {evtab}."source.geolocation.cc",
    {evtab}."source.geolocation.region",
    {evtab}."source.geolocation.city",
    {evtab}."source.account",
    {evtab}."source.fqdn",
    {evtab}."source.local_hostname",
    {evtab}."source.local_ip",
    {evtab}."source.reverse_dns",
    {evtab}."source.tor_node",
    {evtab}."source.url",
    {evtab}."classification.identifier",
    {evtab}."classification.taxonomy",
    {evtab}."classification.type",
    {evtab}."comment",
    {evtab}."destination.ip",
    {evtab}."destination.port",
    {evtab}."destination.asn",
    {evtab}."destination.network",
    {evtab}."destination.geolocation.cc",
    {evtab}."destination.geolocation.region",
    {evtab}."destination.geolocation.city",
    {evtab}."destination.account",
    {evtab}."destination.fqdn",
    {evtab}."destination.local_hostname",
    {evtab}."destination.local_ip",
    {evtab}."destination.reverse_dns",
    {evtab}."destination.tor_node",
    {evtab}."destination.url",
    {evtab}."event_description.target",
    {evtab}."event_description.text",
    {evtab}."event_description.url",
    {evtab}."event_hash",
    {evtab}."extra",
    {evtab}."feed.accuracy",
    {evtab}."malware.hash",
    {evtab}."malware.hash.md5",
    {evtab}."malware.hash.sha1",
    {evtab}."malware.name",
    {evtab}."malware.version",
    {evtab}."misp_uuid",
    {evtab}."notify",
    {evtab}."protocol.application",
    {evtab}."protocol.transport",
    {evtab}."rtir_report_id",
    {evtab}."screenshot_url",
    {evtab}."status",
    {evtab}."time.observation"
FROM {evtab}
LEFT OUTER JOIN {conttab} ON {evtab}."source.asn" = {conttab}.asnum
WHERE
    notify = TRUE AND
    {evtab}.rtir_report_id IS NOT NULL AND
    (
        {evtab}.rtir_incident_id IS NULL OR
        {evtab}.rtir_investigation_id IS NULL
    ) AND
    (
        {evtab}."source.geolocation.cc" LIKE '{cc}' OR
        {evtab}."source.fqdn" LIKE %s
    ) AND
    {evtab}."source.asn" = %s AND
    {evtab}."feed.name" ILIKE %s AND
    {evtab}."time.source" IS NOT NULL AND
    {evtab}."time.source" >= now() - interval '1 month' AND
    {evtab}."classification.taxonomy" ILIKE %s;
"""


QUERY_SET_RTIRID = """
UPDATE {evtab} SET
    rtir_{type}_id = {rtirid},
    sent_at = LOCALTIMESTAMP
WHERE
    id = ANY('{{{ids}}}'::int[]);
"""
=======
CSV_FIELDS = ["time.source", "source.ip", "protocol.transport", "source.port", "protocol.application",
              "source.fqdn", "source.local_hostname", "source.local_ip", "source.url",
              "source.asn", "source.geolocation.cc",
              "source.geolocation.city",
              "classification.taxonomy", "classification.type", "classification.identifier",
              "destination.ip", "destination.port", "destination.fqdn", "destination.url",
              "feed", "event_description.text", "event_description.url", "malware.name", "extra",
              "comment", "additional_field_freetext", "version: 1.1"
              ]
>>>>>>> 544e5e8d61b164e38dd07308812c72736b4961d2

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
"time.source" >= now() - interval '1 month' AND
"sent_at" IS NULL AND
"feed.name" IS NOT NULL AND
"classification.taxonomy" IS NOT NULL AND
"source.abuse_contact" IS NOT NULL AND
UPPER("source.geolocation.cc") = 'AT'
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
    "source.network",
    "source.geolocation.cc",
    "source.geolocation.region",
    "source.geolocation.city",
    "source.account",
    "source.fqdn",
    "source.local_hostname",
    "source.local_ip",
    "source.reverse_dns",
    "source.tor_node",
    "source.url",
    "classification.identifier",
    "classification.taxonomy",
    "classification.type",
    "comment",
    "destination.ip",
    "destination.port",
    "destination.asn",
    "destination.network",
    "destination.geolocation.cc",
    "destination.geolocation.region",
    "destination.geolocation.city",
    "destination.account",
    "destination.fqdn",
    "destination.local_hostname",
    "destination.local_ip",
    "destination.reverse_dns",
    "destination.tor_node",
    "destination.url",
    "event_description.target",
    "event_description.text",
    "event_description.url",
    "event_hash",
    "extra",
    "feed.accuracy",
    "malware.hash",
    "malware.hash.md5",
    "malware.hash.sha1",
    "malware.name",
    "malware.version",
    "misp_uuid",
    "notify",
    "protocol.application",
    "protocol.transport",
    "rtir_report_id",
    "screenshot_url",
    "status",
    "time.observation"
FROM events
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
        self.parser.add_argument('--taxonomy', nargs='+',
                                 help='Select only events with given taxonomy.')
        self.parser.add_argument('-a', '--asn', type=int, nargs='+',
                                 help='Specify one or more AS numbers (integers) to process.')

        self.parser.add_argument('-b', '--batch', action='store_true',
                                 help='Run in batch mode (defaults to "yes" to all).')
        self.parser.add_argument('-q', '--quiet', action='store_true',
                                 help='Do not output anything, except for error messages. Useful in combination with --batch.')
        self.parser.add_argument('-n', '--dry-run', action='store_true',
                                 help='Do not store anything or change anything. Just simulate.')

        self.init()

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

        if self.args.feed:
            self.additional_where += """ AND "feed.name" = ANY(%s::VARCHAR[]) """
            self.additional_params += ('{' + ','.join(self.args.feed) + '}', )
        if self.args.asn:
            self.additional_where += """ AND "source.asn" = ANY(%s::INT[]) """
            self.additional_params += ('{' + ','.join(map(str, self.args.asn)) + '}', )
        if self.args.taxonomy:
            self.additional_where += """ AND "classification.taxonomy" = ANY(%s::VARCHAR[]) """
            self.additional_params += ('{' + ','.join(self.args.taxonomy) + '}', )

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
        """ Passes query to database. """
        if extend:
            query = query + self.additional_where
            parameters = parameters + self.additional_params
        self.logger.debug(self.cur.mogrify(query, parameters))
        if not self.dryrun or query.strip().upper().startswith('SELECT'):
            self.cur.execute(query, parameters)

    def executemany(self, query, parameters=(), extend=True):
        """ Passes query to database. """
        if extend:
            query = query + self.additional_where
            parameters = [param + self.additional_params for param in parameters]
        if self.config['log_level'] == 'debug':
            for param in parameters:
                self.logger.debug(self.cur.mogrify(query, param))
        if not self.dryrun or query.strip().upper().startswith('SELECT'):
            self.cur.executemany(query, parameters)

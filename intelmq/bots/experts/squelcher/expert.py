# -*- coding: utf-8 -*-
"""
Squelcher Expert marks events as new or old depending on a TTL(ASN, Net, IP).
"""
from __future__ import unicode_literals
from ipaddress import ip_address, ip_network

from intelmq.lib.bot import Bot
from intelmq.lib.message import Event
from intelmq.lib.utils import load_configuration

try:
    import psycopg2
except ImportError:
    psycopg2 = None
try:
    import netaddr
except ImportError:
    netaddr = None

SELECT_QUERY = '''
SELECT COUNT(*) FROM {table}
WHERE
"time.source" >= LOCALTIMESTAMP - INTERVAL '%s SECONDS' AND
"classification.type" = %s AND
"classification.identifier" = %s AND
"source.ip" = %s AND
notify IS TRUE AND
("time.source" >= LOCALTIMESTAMP - INTERVAL %s OR
 (sent_at IS NOT NULL AND "time.source" < LOCALTIMESTAMP - INTERVAL %s)
)
'''
"""
If the event in the DB is older than 2 days, then we also check if it has been sent out.
If this is not the case, we assume the event will be sent out, thus we squelch the new event.
"""


class SquelcherExpertBot(Bot):

    def init(self):
        self.config = load_configuration(self.parameters.configuration_path)

        self.logger.debug("Connecting to PostgreSQL.")
        if psycopg2 is None:
            raise ValueError('Could not import psycopg2. Please install it.')
        if netaddr is None:
            raise ValueError('Could not import netaddr. Please install it.')

        self.overwrite = getattr(self.parameters, 'overwrite', False)

        try:
            if hasattr(self.parameters, 'connect_timeout'):
                connect_timeout = self.parameters.connect_timeout
            else:
                connect_timeout = 5

            self.con = psycopg2.connect(database=self.parameters.database,
                                        user=self.parameters.user,
                                        password=self.parameters.password,
                                        host=self.parameters.host,
                                        port=self.parameters.port,
                                        sslmode=self.parameters.sslmode,
                                        connect_timeout=connect_timeout,
                                        )
            self.cur = self.con.cursor()
            self.con.autocommit = getattr(self.parameters, 'autocommit', True)

            global SELECT_QUERY
            SELECT_QUERY = SELECT_QUERY.format(table=self.parameters.table)
        except:
            self.logger.exception('Failed to connect to database.')
            self.stop()
        self.logger.info("Connected to PostgreSQL.")

        self.convert_config()

    def convert_config(self):
        for rule_index, ruleset in enumerate(self.config):
            for key, value in ruleset[0].items():
                if isinstance(value, list):
                    self.config[rule_index][0][key] = tuple(value)
                if isinstance(value, dict):
                    self.config[rule_index][0][key] = tuple(value.items())

    def process(self):
        event = self.receive_message()

        if 'notify' in event and not self.overwrite:
            self.logger.debug('Notify field present and not allowed to overwrite, skipping.')
            self.modify_end(event)
            return

        if 'source.ip' not in event and 'source.fqdn' in event:
            event.add('notify', True, overwrite=True)
            self.modify_end(event)
            return
        if 'source.asn' not in event:
            event.add('notify', False, overwrite=True)
            self.modify_end(event)
            return

        event_copy = event.to_dict()
        if 'extra.additionalmetadata' in event:
            event_copy['extra.additionalmetadata'] = tuple(event['extra.additionalmetadata'])

        ttl = None
        for ruleset in self.config:
            condition = ruleset[0].copy()
            conditions = []
            if 'source.network' in condition and 'source.ip' in event:
                conditions.append(ip_address(event['source.ip']) in
                                  ip_network(condition['source.network']))
                del condition['source.network']
            if 'source.iprange' in condition and 'source.ip' in event:
                conditions.append(event['source.ip'] in netaddr.IPRange(*condition['source.iprange']))
                del condition['source.iprange']
            if set(condition.items()).issubset(event_copy.items()) and all(conditions):
                ttl = ruleset[1]['ttl']
                break

        self.logger.debug('Found TTL {} for ({}, {}).'
                          ''.format(ttl, event['source.asn'],
                                    event['source.ip']))

        try:
            if ttl >= 0:
                self.cur.execute(SELECT_QUERY, (ttl, event['classification.type'],
                                                event['classification.identifier'],
                                                event['source.ip']) +
                                               (self.parameters.sending_time_interval, ) * 2)
                result = self.cur.fetchone()[0]
            else:  # never notify with ttl -1
                result = 1
        except (psycopg2.InterfaceError, psycopg2.InternalError,
                psycopg2.OperationalError, AttributeError):
            self.logger.exception('Cursor has been closed, connecting again.')
            self.init()
        else:
            if result == 0:
                notify = True
            else:
                notify = False

            event.add('notify', notify, overwrite=True)
            self.modify_end(event)

    def shutdown(self):
        try:
            self.cur.close()
        except:
            pass
        try:
            self.con.close()
        except:
            pass

    def modify_end(self, event):
        self.send_message(event)
        self.acknowledge_message()

    @staticmethod
    def check(parameters):
        retval = []
        try:
            config = load_configuration(parameters['configuration_path'])
        except ValueError as exc:
            return [['error', 'Could not load configuration: %r.' % exc]]
        for ruleset in config:
            condition = ruleset[0].copy()
            if 'source.network' in condition:
                try:
                    ip_network(condition['source.network'])
                except ValueError as exc:
                    retval += [['warning', '%r is not a valid IP network: %r.' % (condition['source.network'], exc)]]
                del condition['source.network']
            if 'source.iprange' in condition:
                try:
                    netaddr.IPRange(*condition['source.iprange'])
                except ValueError as exc:
                    retval += [['warning', '%r is not a valid IP range: %r.' % (condition['source.iprange'], exc)]]
                del condition['source.iprange']
            try:
                Event(condition)
            except Exception as exc:
                retval += [['warning', 'Failed to parse conditions as Event: %r.' % (exc)]]
            try:
                int(ruleset[1]['ttl'])
            except ValueError as exc:
                retval += [['error', '%r is not a valid TTL: %r.' % (ruleset[1]['ttl'], exc)]]
        return retval


BOT = SquelcherExpertBot

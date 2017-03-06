# -*- coding: utf-8 -*-
"""
Squelcher Expert marks events as new or old depending on a TTL(ASN, Net, IP).
"""
from __future__ import unicode_literals
from ipaddress import ip_address, ip_network
import psycopg2

import json
import netaddr

from intelmq.lib.bot import Bot
from intelmq.lib.utils import load_configuration


SELECT_QUERY = '''
SELECT COUNT(*) FROM {table}
WHERE
"time.source" >= LOCALTIMESTAMP - INTERVAL '%s SECONDS' AND
"classification.type" = %s AND
"classification.identifier" = %s AND
"source.ip" = %s AND
notify IS TRUE
'''


class SquelcherExpertBot(Bot):

    def init(self):
        self.config = load_configuration(self.parameters.configuration_path)

        self.logger.debug("Connecting to PostgreSQL.")
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

    def process(self):
        event = self.receive_message()

        if event is None:
            self.acknowledge_message()
            return

        # XXX FIXME: quick hack by aka 2017/3/3: ignore things which have extra._origin: "dnsmalware"
        extra = json.loads(event.get('extra', '{}'))
        if '_origin' in extra:
            if 'dnsmalware' == extra['_origin']:
                event.add('notify', False, force=True)
                self.modify_end(event)
                return

        if 'source.ip' not in event and 'source.fqdn' in event:
            event.add('notify', True, force=True)
            self.modify_end(event)
            return
        if 'source.asn' not in event:
            event.add('notify', False, force=True)
            self.modify_end(event)
            return

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
            if set(condition.items()).issubset(event.items()) and all(conditions):
                ttl = ruleset[1]['ttl']
                break

        self.logger.debug('Found TTL {} for ({}, {}).'
                          ''.format(ttl, event['source.asn'],
                                    event['source.ip']))

        try:
            if ttl >= 0:
                self.cur.execute(SELECT_QUERY, (ttl, event['classification.type'],
                                                event['classification.identifier'],
                                                event['source.ip']))
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

            event.add('notify', notify, force=True)
            self.modify_end(event)

    def stop(self):
        try:
            self.cur.close()
        except:
            pass
        try:
            self.con.close()
        except:
            pass
        super(SquelcherExpertBot, self).stop()

    def modify_end(self, event):
        self.send_message(event)
        self.acknowledge_message()


BOT = SquelcherExpertBot

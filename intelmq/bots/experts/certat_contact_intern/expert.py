# -*- coding: utf-8 -*-
"""
CERT.at geolocate the national CERT abuse service
"""
from intelmq.lib.bot import Bot

try:
    import psycopg2
except ImportError:
    psycopg2 = None


class CERTatContactExpertBot(Bot):

    def init(self):
        self.logger.debug("Connecting to database.")
        if psycopg2 is None:
            self.logger.error('Could not import psycopg2. Please install it.')
            self.stop()

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

        except:
            self.logger.exception('Failed to connect to database.')
            self.stop()
        self.logger.info("Connected to PostgreSQL.")

        self.query = ('SELECT "{column}", "can-see-tlp-amber_{feed_code}" FROM "{table}" WHERE "{ascolumn}" = %s'
                      ''.format(table=self.parameters.table, column=self.parameters.column,
                                feed_code=self.parameters.feed_code,
                                ascolumn=self.parameters.ascolumn))

    def process(self):
        event = self.receive_message()

        if 'source.asn' not in event:
            self.logger.warning('source.asn not present in event. Skipping event.')
            event['destination_visible'] = False
            self.send_message(event)
            self.acknowledge_message()
            return

        if 'source.abuse_contact' in event and not self.parameters.overwrite:
            event['destination_visible'] = False
            self.send_message(event)
            self.acknowledge_message()
            return

        try:
            self.logger.debug('Executing %r.' % self.cur.mogrify(self.query,
                                                                 (event['source.asn'], )))
            self.cur.execute(self.query, (event['source.asn'], ))
        except (psycopg2.InterfaceError, psycopg2.InternalError,
                psycopg2.OperationalError, AttributeError):
            self.logger.exception('Database connection problem, connecting again.')
            self.init()
        else:
            if self.cur.rowcount > 1:
                raise ValueError('Lookup returned more then one result. Please inspect.')
            elif self.cur.rowcount == 1:
                result = self.cur.fetchone()
                self.logger.debug('Changing `source.abuse_contact` from %r to %r.' % (event.get('source.abuse_contact'), result[0]))

                if 'source.abuse_contact' in event:
                    event.change('source.abuse_contact', result[0])
                else:
                    event['source.abuse_contact'] = result[0]

                if event['feed.code'] == self.parameters.feed_code:
                    if result[1]:
                        event['destination_visible'] = True
                    else:
                        event['destination_visible'] = False
                else:
                    event['destination_visible'] = True

            else:
                self.logger.debug('No contact found.')
                event['destination_visible'] = False

            self.send_message(event)
            self.acknowledge_message()


BOT = CERTatContactExpertBot

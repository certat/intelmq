Squelcher
~~~~~~~~~

The configuration defines a TTL based on matching fields. The bot looks
in the event table if an event has been sent to the customer in the time
frame defined by the TTL using the IP, classification type and
classification identifier. If an event has been found, we set notify to
false, otherwise to true. Only events with notify flag set to true are
considered for the lookups.

Edge cases: If no ASN is present, we ignore the event and set the flag
to false. If no IP is present, but an FQDN , we always set the flag to
true. if ``extra._origin`` equals ``"dnsmalware"``, the flag is always
set to false.

Information:
^^^^^^^^^^^^

-  ``name:`` squelcher
-  ``lookup:`` postgres
-  ``public:`` yes
-  ``cache (redis db):`` -
-  ``description:`` Sets the ``notify`` field to true or false depending
   on past notifications

Configuration Parameters:
^^^^^^^^^^^^^^^^^^^^^^^^^

-  ``autocommit``: use transactions per statement (``true``) or per
   connection (``false``)
-  ``configuration_path``: path to the squelcher configuration file,
   e.g. ``"/opt/intelmq/etc/squelcher.conf"``
-  ``database``: postgres database
-  ``host"`` postgres host
-  ``password``: postgres password
-  ``port``: postgres port (usually 5432)
-  ``sslmode``: e.g. ``"require"``
-  ``table``: postgres table
-  ``user``: postgres user

Configuration syntax
''''''''''''''''''''

The file must by valid JSON and must contain a list with lists
containing two dictionaries. The first is compared to the event and thus
has the same layout. The second dictionary has only one field ``"ttl"``
with the TTL as value.

.. code:: json

   [
       [
           {
               "source.asn": 0,
               "source.network": "192.0.2.0/24",
               "source.ip": "192.0.2.1",
               "classification.type": "vulnerable service"
           }, {
               "ttl": 3600
           }
       ]
   ]

The first dictionary must be a sub-set of the event -> All given fields
must exist in the event with the given values. The ``source.network``
field is checked separately with the IP in the event (if the
``source.ip`` is in the given network block). The same applies to the
additional ``source.iprange`` field (holding a list of two items, the
start and end IP address).

More examples can be found in ``intelmq/etc/squelcher.conf``.

Database index
^^^^^^^^^^^^^^

For a good performance, create this index:

.. code:: sql

   create index idx_squelch on events("source.ip", "time.source");

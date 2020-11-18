``intelmqcli``: Command Line Interface
======================================

The cli tool fetches unhandled events from the events database and
creates tickets in an RTIR instance to notify the abuse contacts of the
AS.

It is made for semi- and automatic usage. There are two programs:

-  ``intelmqcli_create_reports``: it creates reports for all events to
   send, where no RTIR report exists. There is not interactivity
   available.
-  ``intelmqcli``: Creates the Incident and Investigation tickets. This
   program can be run interactively and automatically.

Both programs share very similar paramaters. Look at their help pages
for more information. Their configuration file is ``intelmqcli.conf`` in
IntelMQ’s configration directory.

intelmqcli iterates over all taxonomies and further over all abuse
contacts. At the end it looks if there are “half processed” events where
incidents exist, but no investigations.

First, run ``intelmqcli_create_reports``. It shows if Incident Reports
have been created where necessary. Then, run ``intelmqcli``, if not
running in batch mode, we are asked if we want to create the
investigations

::

   ====================================================================================================
   To: wagner+test@cert.at
   Subject: Vulnerable device incidents in your network: 2019-07-22

   foobar text is ma wurscht
       
   time.source;source.ip;protocol.transport;source.port;protocol.application;source.fqdn;source.local_hostname;source.local_ip;source.url;source.asn;source.geolocation.cc;source.geolocation.city;classification.taxonomy;classification.type;classification.identifier;destination.ip;destination.port;destination.fqdn;destination.url;feed;event_description.text;event_description.url;malware.name;extra;comment;additional_field_freetext;feed.documentation;version: 1.2
   2019-07-21T13:15:16+02;192.168.23.44;;;;;;;;64511;AT;;vulnerable;vulnerable service;openrdp;;;;;testfeed;;;;;;;;

   ----------------------------------------------------------------------------------------------------
   [a]utomatic, [n]ext, [s]end, show [t]able, change [r]equestor or [q]uit? 

The data is hard to read in csv format, so we press ``t``:

.. code:: bash

   [a]utomatic, [n]ext, [s]end, show [t]able, change [r]equestor or [q]uit? t
   ====================================================================================================
   To: wagner+test@cert.at
   Subject: Vulnerable device incidents in your network: 2019-07-22

   foobar text is ma wurscht
       
   +------------------------+---------+----------+---------------+---------------+--------------+--------------+-------------------------+---------------------------+---------------+-------------------------+-------------------+-----------------------------+---------------------------+-----------------------+-----------+------------------+--------------------+--------------------+-------------------+--------------------------+-------------------------+---------+----------------------+----------------+------------------------+----------------------+
   | time.source            |      id | feed     | source.ip     | source.port   | source.url   |   source.asn | source.geolocation.cc   | source.geolocation.city   | source.fqdn   | source.local_hostname   | source.local_ip   | classification.identifier   | classification.taxonomy   | classification.type   | comment   | destination.ip   | destination.port   | destination.fqdn   | destination.url   | event_description.text   | event_description.url   | extra   | feed.documentation   | malware.name   | protocol.application   | protocol.transport   |
   |------------------------+---------+----------+---------------+---------------+--------------+--------------+-------------------------+---------------------------+---------------+-------------------------+-------------------+-----------------------------+---------------------------+-----------------------+-----------+------------------+--------------------+--------------------+-------------------+--------------------------+-------------------------+---------+----------------------+----------------+------------------------+----------------------|
   | 2019-07-21T13:15:16+02 | 1309479 | testfeed | 192.168.23.44 |               |              |        64511 | AT                      |                           |               |                         |                   | openrdp                     | vulnerable                | vulnerable service    |           |                  |                    |                    |                   |                          |                         |         |                      |                |                        |                      |
   +------------------------+---------+----------+---------------+---------------+--------------+--------------+-------------------------+---------------------------+---------------+-------------------------+-------------------+-----------------------------+---------------------------+-----------------------+-----------+------------------+--------------------+--------------------+-------------------+--------------------------+-------------------------+---------+----------------------+----------------+------------------------+----------------------+
   ----------------------------------------------------------------------------------------------------
   [a]utomatic, [n]ext, [s]end, show [t]able, change [r]equestor or [q]uit? 

Much easier to read. This mail will be sent in csv format anyway.

Change the requestor, the recipient of the report, by pressing ``r``.

Now we are ready to create the tickets and send the mail out by pressing
``s``

.. code:: bash

   Created Investigation 50.
   Linked events to investigation.
   Correspondence added to Investigation.
   Marked events as sent.

If you changed the recipient, the program asks if the recipient should
be saved to the database. An existing record will be updated or a new
one will be added:

.. code:: bash

   Save recipient 'null@localhost' for ASNs 1206? [Y/n]

Press ``a`` to send everything coming afterwards.

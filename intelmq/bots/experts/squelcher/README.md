# Squelcher Expert

This bot sets the notify flag according to the TTL (Time-To-Live) from a configuration file and if events with the same classifcation and IP have already been sent out in this time frame.

The parameter `sending_time_interval` should match what is configures in `intelmqcli`. For events in this time interval, `sent_at` may be `NULL` for an event in the database with `notify` equalling to `True`, but the event is still considered to be sent, because it could still be sent out in the next run.

## Configuration

The configuration file is a JSON-formatted file with a list of lists (rules) with two dictionaries each. The first dictionary matches the event, the second is the TTL.

### Parameters

* Postgresql connection parameters, see postgresql output bot for example
* `overwrite`, boolean: If `notify` is present and `overwrite` is false (default), no action is performed.

### Event matching

Each rule given is a field of the event, all of the given ones must match the event. It is not possible to do a logical OR.
If a rule matched, the TTL of this rule is used. Otherwise the bot continues with the next rule. The order of the rules is significant, first match wins.

There are two special cases, both concerning the network matching:

  * `source.network` (string, CIDR notation): It is checked if the `source.ip` of the event is in the `source.network` of the rule.
  * `source.iprange` (list of two strings with IP addresses): It is checked if the `source.ip` is in the given IPrange.

All other comparisons use the `==` operator.

### TTLs

The TTLs must be integer. The TTL -1 has a special meaning: Notify should be set to `False` always.

## Special cases

If no `source.ip` is given in the event and only a `source.fqdn` is present, `notify` is set to `True`.
If `source.asn` is not given, `notify` is set to `False`.

## Config Check

`intelmqctl check` also performs a check of the bot's configuration.

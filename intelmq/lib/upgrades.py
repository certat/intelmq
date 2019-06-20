#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
© 2019 Sebastian Wagner <wagner@cert.at>

SPDX-License-Identifier: AGPL-3.0

TODO: modify syntax conversion
"""
import json

from collections import OrderedDict

import intelmq
import intelmq.lib.utils as utils

__all__ = ['v201_defaults_statistics', 'v201_defaults_broker',
           'v112_feodo_tracker_ips',
           'v112_feodo_tracker_domains',
           'v110_shadowserver_feednames', 'v110_deprecations'
           ]


def v201_defaults_statistics():
    """
    Inserting "statistics_*" parameters into defaults.conf file
    """
    values = {"statistics_database": 3,
              "statistics_host": "127.0.0.1",
              "statistics_password": None,
              "statistics_port": 6379
              }
    changed = False
    defaults = utils.load_configuration(intelmq.DEFAULTS_CONF_FILE)
    for key, value in values.items():
        if key not in defaults:
            defaults[key] = value
            changed = True
    if not changed:
        # all keys exist already
        return None

    try:
        with open(intelmq.DEFAULTS_CONF_FILE, 'w') as handle:
            json.dump(defaults, fp=handle, indent=4, sort_keys=True,
                      separators=(',', ': '))
    except PermissionError:
        return 'Can\'t update defaults configuration: Permission denied.'
    return True


def v201_defaults_broker():
    """
    Inserting "*_pipeline_broker" and deleting broker into/from defaults configuration
    """
    changed = False
    defaults = utils.load_configuration(intelmq.DEFAULTS_CONF_FILE)
    values = {"destination_pipeline_broker": defaults.get("broker", "redis"),
              "source_pipeline_broker": defaults.get("broker", "redis"),
              }
    for key, value in values.items():
        if key not in defaults:
            defaults[key] = value
            changed = True
    if "broker" in defaults:
        del defaults["broker"]
        changed = True
    if not changed:
        # all keys exist already and broker is gone
        return None

    try:
        with open(intelmq.DEFAULTS_CONF_FILE, 'w') as handle:
            json.dump(defaults, fp=handle, indent=4, sort_keys=True,
                      separators=(',', ': '))
    except PermissionError:
        return 'Can\'t update defaults configuration: Permission denied.'
    return True


def v112_feodo_tracker_ips():
    """
    Fix URL of feodotracker IPs feed in runtime configuration
    """
    runtime = utils.load_configuration(intelmq.RUNTIME_CONF_FILE)
    changed = False
    for bot_id, bot in runtime.items():
        if bot["parameters"].get("http_url") == "https://feodotracker.abuse.ch/blocklist/?download=ipblocklist":
            bot["parameters"]["http_url"] = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
            changed = True
    if not changed:
        return None

    try:
        with open(intelmq.RUNTIME_CONF_FILE, 'w') as handle:
            json.dump(runtime, fp=handle, indent=4, sort_keys=True,
                      separators=(',', ': '))
    except PermissionError:
        return 'Can\'t update runtime configuration: Permission denied.'
    return True


def v112_feodo_tracker_domains():
    """
    Search for discontinued feodotracker domains feed
    """
    runtime = utils.load_configuration(intelmq.RUNTIME_CONF_FILE)
    found = False
    for bot_id, bot in runtime.items():
        if bot["parameters"].get("http_url") == "https://feodotracker.abuse.ch/blocklist/?download=domainblocklist":
            found = bot_id

    if not found:
        return None
    else:
        return ('The discontinued feed "Feodo Tracker Domains" has been found '
                'as bot %r. Remove it yourself please.' % found)


def v110_shadowserver_feednames():
    """
    Replace depreacated Shadowserver feednames
    """
    mapping = {
        "Botnet-Drone-Hadoop": "Drone",
        "DNS-open-resolvers": "DNS-Open-Resolvers",
        "Open-NetBIOS": "Open-NetBIOS-Nameservice",
        "Ssl-Freak-Scan": "SSL-FREAK-Vulnerable-Servers",
        "Ssl-Scan": "SSL-POODLE-Vulnerable-Servers",
    }
    runtime = utils.load_configuration(intelmq.RUNTIME_CONF_FILE)
    changed = False
    for bot_id, bot in runtime.items():
        if bot["module"] == "intelmq.bots.parsers.shadowserver.parser":
            if bot["parameters"]["feedname"] in mapping:
                changed = True
                bot["parameters"]["feedname"] = mapping[bot["parameters"]["feedname"]]
    if not changed:
        return None

    try:
        with open(intelmq.RUNTIME_CONF_FILE, 'w') as handle:
            json.dump(runtime, fp=handle, indent=4, sort_keys=True,
                      separators=(',', ': '))
    except PermissionError:
        return 'Can\'t update runtime configuration: Permission denied.'
    return True


def v110_deprecations():
    """
    Checking for deprecated runtime configurations
    """
    mapping = {
        "intelmq.bots.collectors.n6.collector_stomp": "intelmq.bots.collectors.stomp.collector",
        "intelmq.bots.parsers.cymru_full_bogons.parser": "intelmq.bots.parsers.cymru.parser_full_bogons",
    }
    runtime = utils.load_configuration(intelmq.RUNTIME_CONF_FILE)
    changed = False
    for bot_id, bot in runtime.items():

        if bot["module"] in mapping:
            changed = True
            bot["module"] = mapping[bot["module"]]
        if bot["module"] == "intelmq.bots.experts.ripencc_abuse_contact.expert":
            changed = True
            bot["module"] = "intelmq.bots.experts.ripe.expert"
        if bot["module"] == "intelmq.bots.experts.ripe.expert":
            if bot["parameters"].get("query_ripe_stat"):
                changed = True
                if "query_ripe_stat_asn" not in bot["parameters"]:
                    bot["parameters"]["query_ripe_stat_asn"] = bot["parameters"]["query_ripe_stat"]
                if "query_ripe_stat_asn" not in bot["parameters"]:
                    bot["parameters"]["query_ripe_stat_ip"] = bot["parameters"]["query_ripe_stat_ip"]
                del bot["parameters"]["query_ripe_stat"]
        if bot["group"] == 'Collector' and bot["parameters"].get("feed"):
            changed = True
            bot["parameters"]["feed"] = bot["parameters"]["name"]
    if not changed:
        return None

    try:
        with open(intelmq.RUNTIME_CONF_FILE, 'w') as handle:
            json.dump(runtime, fp=handle, indent=4, sort_keys=True,
                      separators=(',', ': '))
    except PermissionError:
        return 'Can\'t update runtime configuration: Permission denied.'
    return True


UPGRADES = OrderedDict([
    ((1, 1, 0), (v110_shadowserver_feednames, v110_deprecations)),
    ((1, 1, 2), (v112_feodo_tracker_ips, v112_feodo_tracker_domains, )),
    ((2, 0, 1), (v201_defaults_statistics, v201_defaults_broker)),
])

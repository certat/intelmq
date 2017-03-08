#!/bin/bash

# How often should this run?
#  Once a day max

# crontab entry for this (proposal):
# # m h  dom mon dow   command
# 02  01 *   *   *     ( cd /tmp; /my/path/to/this/script )
#

BGPROUTER=qualle.cert.at

cd /tmp
mkdir bgproutingtable
cd bgproutingtable

echo "Download IPv4 table from '$BGPROUTER'."
whois -h $BGPROUTER block origin v4table > ipasn.dat
echo "Download IPv6 table from '$BGPROUTER'."
whois -h $BGPROUTER block origin v6table >> ipasn.dat

echo "Convert format"
sed -i 's/^v[46]*table //' ipasn.dat
sed -i 's/ /\t/' ipasn.dat

echo "Perform sanity checks"
if [[ $(wc -l ipasn.dat | awk '{print $1}') -lt 650000 ]]; then
    echo "Less then 650k entries, can't be true."
    exit 1
fi

python3 -c "import pyasn; pyasn.pyasn('/tmp/bgproutingtable/ipasn.dat')" > /dev/null
if [[ $? -ne 0 ]]; then
    echo "Unparseable data."
    exit 1
fi

echo "Applying new data to '/opt/intelmq/var/lib/bots/asn_lookup/'."
mv ipasn.dat  /opt/intelmq/var/lib/bots/asn_lookup/

cd ..
rmdir /tmp/bgproutingtable

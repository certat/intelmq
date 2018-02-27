Cert.at Contact Intern Expert
=============================

Parmeters
---------

 * `autocommit`: true
 * `ascolumn`: name of the column containing the ASN
 * `column`: name of the column containing the contact
 * `feed_code`: name of the feed that has tlp:amber data
 * `host`, `port`, `database`, `user`, `password`, `sslmode`, `table`: postgres parameters

Table layout
------------

Apart from the columns with ASN and contacts, you should have a column like `can-see-tlp-amber_example-feed` where `example-feed` is a `feed.code`.
 * By default `destination_visible` is true
 * If `feed.code` matches, `destination_visible` is false
   * If additionally `can-see-tlp-amber_example-feed` is true, the field `destination_visible` is true

You also need a view which enforces these rules containing columns like:

```sql
...
CASE WHEN events."destination_visible" THEN events."destination.ip" ELSE NULL END AS "destination.ip",
...
```
instead of simply `events."destination.ip"`.

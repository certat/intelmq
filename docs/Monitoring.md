# Monitoring concept

## Definitions
In this document, when we write "syslog" we mean both: IntelMQ logging to a dedicated log file or via the syslog facility.


## Types of monitoring

- OS level monitoring of a server running intelmq
- Monitoring & triggering alerts of background jobs (cron) which peridocially update reference data (such as pyasn)
- Intelmq performance monitoring
- Alerts on errors which IntelMQ reports via its log files

## OS level monitoring

All the regular monitoring of 
  * free RAM
  * free disk space
  * CPU level 
  * IOStat  levels
applies and is outside the scope of this document. Note that since IntelMQ uses Redis internally, RAM monitoring is especially important.
When IntelMQ is configured to log in DEBUG mode, disk space monitoring is important.

## Monitoring the success of scheduled cron jobs

In addition to the regularl OS level monitoring, many experts in IntelMQ rely on up to date databases to perform their lookup functionality: ip2asn (pyasn) comes to mind.
These databases needs to be downloaded (usually once per night) and the relevant IntelMQ processes are being sent a SIGHUP to reload their configuration and their databases.

In case such a cron job does not work (non-zero exit code), this SHALL be an alert for the ops team.
In case an IntelMQ bot has errors upon reloading the database (SIGHUP), this SHALL be an alert for the ops team.

## IntelMQ performance monitoring

IntelMQ MUST implement a "PERFMON" syslog facility at the INFO log level. This PERFMON facility will be used in the following fashion:

  * after each invocation of a bot's ``process()`` method, the caller of ``process()`` MUST emit a single PERFMON facility log line in the following format:
  
```
    <identifier> | <number of OK events> | <number of not OK events> | <duration for processing in nanosecs>  | <processing time per event in nanosecs>
```
  
Example:
```
    shadowserver-parser | 112 | 2 | 10020 | 87
```
How to read this: the shadowserver parser reports that after it's run it processed 114 events. 2 out of these it could not process.
The processing took 10020 nanosecs (10.02 microsecs) with an average processing time of 87 nanosecs per event.
  
  
Note that this format gives IntelMQ the flexibility to log performance stats after every _N_ events. _N_ might be even 1!
  
Tools such as check_mk might be used to grab these PERFMON syslog facility log lines , parse them and create performance graphs.
The creation of these graphs is outside of the scope of IntelMQ
  
## Alerts on errors which IntelMQ reports via its log files
  
IntelMQ MUST report every error via the ERROR log level in syslog.
The operations team MUST be able to react on ERROR log level messages and hence the error messages MUST be understandable and have a clear description of any needed actions in order to get things working again.

  

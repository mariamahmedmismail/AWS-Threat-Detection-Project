SELECT eventtime, eventname, eventsource, sourceipaddress, errorcode, requestparameters
FROM cloudtrail_logs.events
WHERE useridentity.arn LIKE '%<role-or-user-name>%'
ORDER BY eventtime

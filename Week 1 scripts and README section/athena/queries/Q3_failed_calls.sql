SELECT eventtime, eventname, useridentity.arn, sourceipaddress, errorcode, errormessage
FROM cloudtrail_logs.events
WHERE errorcode IS NOT NULL
ORDER BY eventtime DESC

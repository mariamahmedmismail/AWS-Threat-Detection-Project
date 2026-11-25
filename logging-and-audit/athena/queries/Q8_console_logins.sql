SELECT eventtime, useridentity.arn, sourceipaddress, useragent, responseelements
FROM cloudtrail_logs.events
WHERE eventname = 'ConsoleLogin'
ORDER BY eventtime DESC

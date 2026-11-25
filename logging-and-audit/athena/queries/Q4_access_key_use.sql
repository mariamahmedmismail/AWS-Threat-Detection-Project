SELECT eventtime, eventname, sourceipaddress, useragent, errorcode
FROM cloudtrail_logs.events
WHERE useridentity.accesskeyid = '<ACCESS_KEY_ID>'
ORDER BY eventtime

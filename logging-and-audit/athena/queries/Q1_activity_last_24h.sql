SELECT eventtime, eventname, eventsource, useridentity.arn, sourceipaddress, errorcode
FROM cloudtrail_logs.events
WHERE from_iso8601_timestamp(eventtime) > current_timestamp - INTERVAL '1' DAY
ORDER BY eventtime

SELECT eventtime, eventname, useridentity.arn, sourceipaddress, requestparameters
FROM cloudtrail_logs.events
WHERE eventsource IN ('iam.amazonaws.com','sts.amazonaws.com')
  AND readonly = 'false'
ORDER BY eventtime

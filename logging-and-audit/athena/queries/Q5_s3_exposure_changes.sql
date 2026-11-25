SELECT eventtime, eventname, useridentity.arn, sourceipaddress, requestparameters
FROM cloudtrail_logs.events
WHERE eventsource = 's3.amazonaws.com'
  AND eventname IN ('PutBucketPolicy','PutBucketAcl','DeleteBucketPolicy',
                    'PutBucketPublicAccessBlock','DeletePublicAccessBlock')
ORDER BY eventtime

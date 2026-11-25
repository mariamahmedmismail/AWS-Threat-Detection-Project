SELECT eventtime, eventname, useridentity.arn, sourceipaddress, requestparameters
FROM cloudtrail_logs.events
WHERE eventsource = 'ec2.amazonaws.com'
  AND eventname IN ('RunInstances','StopInstances','TerminateInstances',
                    'ModifyInstanceAttribute','AuthorizeSecurityGroupIngress',
                    'RevokeSecurityGroupIngress','CreateSnapshot','CreateSecurityGroup')
ORDER BY eventtime

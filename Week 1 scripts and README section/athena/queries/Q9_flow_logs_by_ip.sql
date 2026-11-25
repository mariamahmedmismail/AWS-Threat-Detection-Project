SELECT from_unixtime(start) AS start_time, srcaddr, dstaddr, dstport, protocol, packets, bytes, action
FROM cloudtrail_logs.vpc_flow_logs
WHERE srcaddr = '<IP>' OR dstaddr = '<IP>'
ORDER BY start

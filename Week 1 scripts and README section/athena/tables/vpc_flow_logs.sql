CREATE EXTERNAL TABLE IF NOT EXISTS cloudtrail_logs.vpc_flow_logs (
  version INT,
  account_id STRING,
  interface_id STRING,
  srcaddr STRING,
  dstaddr STRING,
  srcport INT,
  dstport INT,
  protocol BIGINT,
  packets BIGINT,
  bytes BIGINT,
  start BIGINT,
  `end` BIGINT,
  action STRING,
  log_status STRING
)
ROW FORMAT DELIMITED FIELDS TERMINATED BY ' '
LOCATION 's3://__FLOW_BUCKET__/AWSLogs/__ACCOUNT_ID__/vpcflowlogs/__REGION__/'
TBLPROPERTIES ('skip.header.line.count'='1')

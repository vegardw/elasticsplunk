ElasticSplunk Search Command
====================================================

A Search command to explore Elasticsearch data within Splunk.

# Currently supported
- Multiple node search
- Index Specification
- SSL connections
- Scroll searches
- Fields to include
- Splunk timepicker values
- Relative time values
- Timestamp field specification
- Index listing "action=indices-list"
- Cluster health "action=cluster-health"

# Included libraries
- elasticsearch-py
- urllib3
- splunklib from the splunk-sdk-python

# Examples

## Search:

When searching with the ess command, it uses by default the Splunk timepicker provided time range unless the earliest and latest parameters are specified.</br>
When earliest and latest parameters are specified this will be the effective range for the search, even though the range below the search bar shows the one from the timepicker.

### Using the Splunk timepicker provided time range
```
|ess eaddr="https://node1:9200,https://node2:9200" index=indexname tsfield="@timestamp" query="field:value AND host:host*"
```

### Using the earliest and latest parameters
```
|ess eaddr="https://node1:9200,https://node2:9200" index=indexname tsfield="@timestamp" latest=now earliest="now-24h" query="field:value AND host:host*"
```

## List indices
```
|ess eaddr="https://node1:9200,https://node2:9200" action=indices-list"
```

## Cluster health
```
|ess eaddr="https://node1:9200,https://node2:9200" action=cluster-health"
```

## Correlation
```
<splunk command> | esscorrelate correlate_fields="src_ip,dest_ip" eaddr="https://node1:9200,https://node2:9200" index=indexname tsfield="@timestamp" query="field:value AND host:host*"
```

### Update Elasticsearch document
```
|ess eaddr="https://node:9200" index=indexname tsfield="@timestamp" query="field:value" include_es=true | eval newfield="foo" | essupdate
```

Written by Bruno Moura <brunotm@gmail.com>  
Changes and additional commands by Vegard Wærp <vegardw@gmail.com>

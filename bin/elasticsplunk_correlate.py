# vim: set fileencoding=utf-8:
# ElasticSplunkCorrelate
# streaming command that correlates a chosen field from a pipeline with Elasticsearch
#
# Written by Vegard Wærp, heavily based on ElasticSplunk by Bruno Moura
#

import os
import sys
import re
import time
import json
import calendar
from datetime import datetime
from elasticsearch import Elasticsearch, helpers
from splunklib.searchcommands import \
    dispatch, StreamingCommand, Configuration, Option, validators

# Time units for relative time conversion
UNITS = {
    "s": 1,
    "m": 60,
    "h": 3600,
    "d": 86400,
    "M": 2592000,
    "y": 31104000,
}

# Elasticsearch document metadata keys
KEYS_ELASTIC = ("_index", "_type", "_id", "_score")
KEY_ELASTIC_SOURCE = "_source"

# Config keys
KEY_CONFIG_CORRELATE_FIELDS = "correlate_fields"
KEY_CONFIG_EADDR = "hosts"
KEY_CONFIG_TIMESTAMP = "tsfield"
KEY_CONFIG_USE_SSL = "use_ssl"
KEY_CONFIG_VERIFY_CERTS = "verify_certs"
KEY_CONFIG_FIELDS = "fields"
KEY_CONFIG_EXCLUDE_FIELDS = "exclude_fields"
KEY_CONFIG_SOURCE_TYPE = "stype"
KEY_CONFIG_LATEST = "latest"
KEY_CONFIG_EARLIEST = "earliest"
KEY_CONFIG_SCAN = "scan"
KEY_CONFIG_INDEX = "index"
KEY_CONFIG_INCLUDE_ES = "include_es"
KEY_CONFIG_INCLUDE_RAW = "include_raw"
KEY_CONFIG_LIMIT = "limit"
KEY_CONFIG_QUERY = "query"
KEY_CONFIG_NO_TIMESTAMP = "no_timestamp"
KEY_CONFIG_CONVERT_TIMESTAMP = "convert_timestamp"
KEY_CONFIG_RETURN_MV = "return_mv"

# Splunk keys
KEY_SPLUNK_TIMESTAMP = "_time"
KEY_SPLUNK_EARLIEST = "startTime"
KEY_SPLUNK_LATEST = "endTime"
KEY_SPLUNK_RAW = "_raw"

# Default time range
DEFAULT_EARLIEST = "now-24h"
DEFAULT_LATEST = "now"


@Configuration()
class ElasticSplunkCorrelate(StreamingCommand):
    correlate_fields = Option(require=True, default=None, doc="Fields to correlate")
    return_mv = Option(require=False, default=False, doc="Return multivalue fields instead of separate records")
    eaddr = Option(require=False, default="127.0.0.1 9200", doc="server:port,server:port or config item")
    index = Option(require=False, default=None, doc="Index to search")
    scan = Option(require=False, default=True, doc="Perform a scan search")
    stype = Option(require=False, default=None, doc="Source/doc_type")
    tsfield = Option(require=False, default="@timestamp", doc="Field holding the event timestamp")
    query = Option(require=False, default="*", doc="Query string in ES DSL")
    fields = Option(require=False, default=None, doc="Only include selected fields")
    exclude_fields = Option(require=False, default=None, doc="Exclude selected fields")
    limit = Option(require=False, default=10000, doc="Max number of hits")
    include_es = Option(require=False, default=False, doc="Include Elasticsearch relevant fields")
    include_raw = Option(require=False, default=False, doc="Include event source")
    use_ssl = Option(require=False, default=None, doc="Use SSL")
    verify_certs = Option(require=False, default=None, doc="Verify SSL Certificates")
    no_timestamp = Option(require=False, default=False, doc="Elastic data has no timestamps, generate dummy")
    convert_timestamp = Option(require=False, default=True, doc="Convert timestamps from text to unix timestamp")
    earliest = Option(require=False, default=None,
                      doc="Earliest event, format relative eg. now-4h or 2016-11-18T23:45:00")
    latest = Option(require=False, default=None,
                      doc="Latest event, format 2016-11-17T23:45:00")

    @staticmethod
    def parse_dates(time_value):
        """Parse relative dates if specified"""

        if isinstance(time_value, int):
            return time_value

        if re.search(r"^now$", time_value):
            return int(time.time())

        match = re.search(r"^now-(\d+)([a-zA-Z])$", time_value)
        if match:
            multi, unit = match.groups()
            return int(multi) * UNITS[unit]

        if re.search(r"^\d{4}-\d{2}-\d{2}$", time_value):
            return int(time.mktime(time.strptime(time_value, "%Y-%m-%d")))

        if re.search(r"^\d{4}-\d{2}-\d{2}T\d{2}$", time_value):
            return int(time.mktime(time.strptime(time_value, "%Y-%m-%dT%H")))

        if re.search(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$", time_value):
            return int(time.mktime(time.strptime(time_value, "%Y-%m-%dT%H:%M")))

        if re.search(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$", time_value):
            return int(time.mktime(time.strptime(time_value, "%Y-%m-%dT%H:%M:%S")))

    @staticmethod
    def to_epoch(timestring):
        tmp = datetime.strptime(timestring, "%Y-%m-%dT%H:%M:%S.%fZ")
        tmp2 = tmp.timetuple()
        return str(calendar.timegm(tmp2)) + "." + str(tmp.microsecond)
    
    def _get_search_config(self):
        """Parse and configure search parameters"""

        # Load default configs if available
        app_path = os.path.dirname(os.path.abspath(__file__)) + "/.."
        local_config = "{0}/local/elasticsplunk.json".format(app_path)
        if os.path.isfile(local_config):
            config_file = open(local_config)
            config = json.load(config_file)
        else:
            config = {}

        # Load eaddr stored config
        if self.eaddr in config:
            config = config[self.eaddr]
        else:
            config[KEY_CONFIG_EADDR] = self.eaddr.split(",")

        if KEY_CONFIG_TIMESTAMP not in config:
            config[KEY_CONFIG_TIMESTAMP] = self.tsfield
            # raise Exception("Required tsfield parameter not specified")

        # Handle SSL connections
        if self.use_ssl != None:
            config[KEY_CONFIG_USE_SSL] = True if self.use_ssl == "true" else False
        elif KEY_CONFIG_USE_SSL not in config:
            config[KEY_CONFIG_USE_SSL] = False

        if not config[KEY_CONFIG_USE_SSL]:
            config[KEY_CONFIG_VERIFY_CERTS] = False
        elif self.verify_certs != None:
            config[KEY_CONFIG_VERIFY_CERTS] = True if self.verify_certs == "true" else False
        elif KEY_CONFIG_VERIFY_CERTS not in config:
            config[KEY_CONFIG_VERIFY_CERTS] = False

        # Fields to correlate
        if self.correlate_fields:
            config[KEY_CONFIG_CORRELATE_FIELDS] = self.correlate_fields.split(",")
        else:
            config[KEY_CONFIG_CORRELATE_FIELDS] = None
        
        # Fields to fetch
        if self.fields:
            config[KEY_CONFIG_FIELDS] = self.fields.split(",")
            if not config[KEY_CONFIG_TIMESTAMP] in config[KEY_CONFIG_FIELDS]:
                config[KEY_CONFIG_FIELDS].append(config[KEY_CONFIG_TIMESTAMP])
        else:
            config[KEY_CONFIG_FIELDS] = None

        # Fields to exclude
        if self.exclude_fields:
            config[KEY_CONFIG_EXCLUDE_FIELDS] = self.exclude_fields.split(",")
        else:
            config[KEY_CONFIG_EXCLUDE_FIELDS] = None

        # source type
        config[KEY_CONFIG_SOURCE_TYPE] = self.stype.split(",") if self.stype else None

        if self.latest:
            config[KEY_CONFIG_LATEST] = self.parse_dates(self.latest)
        elif hasattr(self.search_results_info, KEY_SPLUNK_LATEST):
            config[KEY_CONFIG_LATEST] = int(self.search_results_info.endTime)
        else:
            config[KEY_CONFIG_LATEST] = self.parse_dates(DEFAULT_LATEST)

        if self.earliest:
            config[KEY_CONFIG_EARLIEST] = config[KEY_CONFIG_LATEST] - self.parse_dates(self.earliest)
        elif hasattr(self.search_results_info, KEY_SPLUNK_EARLIEST):
             config[KEY_CONFIG_EARLIEST] = int(self.search_results_info.startTime)
        else:
            config[KEY_CONFIG_EARLIEST] = config[KEY_CONFIG_LATEST] - self.parse_dates(DEFAULT_EARLIEST)

        config[KEY_CONFIG_SCAN] = self.scan
        config[KEY_CONFIG_INDEX] = self.index
        config[KEY_CONFIG_INCLUDE_ES] = self.include_es
        config[KEY_CONFIG_INCLUDE_RAW] = self.include_raw
        config[KEY_CONFIG_LIMIT] = self.limit
        config[KEY_CONFIG_QUERY] = self.query
        config[KEY_CONFIG_NO_TIMESTAMP] = self.no_timestamp
        config[KEY_CONFIG_CONVERT_TIMESTAMP] = self.convert_timestamp
        config[KEY_CONFIG_RETURN_MV] = self.return_mv

        return config

    def _search(self, esclient, config, record):
        """Search Correlate Splunk events from a Elasticsearch search"""

        # Search body
        # query-string-syntax
        # www.elastic.co/guide/en/elasticsearch/reference/current/query-dsl-query-string-query.html
        if self.no_timestamp in [True, "true", "True", 1, "y"]:
            body = {
                "query": {
                    "bool": {
                            "must": [
                                {"query_string" : {
                                    "query" : config[KEY_CONFIG_QUERY],
                                }}
                        ]
                    }
                }
            }
        else:
            body = {
                "sort":[{config[KEY_CONFIG_TIMESTAMP]:{"order": "asc"}}],
                "query": {
                    "bool": {
                        "must": [
                            {"range": {
                                config[KEY_CONFIG_TIMESTAMP]: {
                                    "gte": config[KEY_CONFIG_EARLIEST],
                                    "lte": config[KEY_CONFIG_LATEST],
                                    "format": "epoch_second",
                                }
                            }},
                            {"query_string" : {
                                "query" : config[KEY_CONFIG_QUERY],
                            }}
                        ]
                    }
                }
            }

    	# Populate body with correlation fields
        if config[KEY_CONFIG_CORRELATE_FIELDS]:
            for field in config[KEY_CONFIG_CORRELATE_FIELDS]:
              body["query"]["bool"]["must"].append({"match" : {field: record[field]}})

        
        # Execute search
        if self.scan in [True, "true", "True", 1, "y"]:
            res = helpers.scan(esclient,
                               size=config[KEY_CONFIG_LIMIT],
                               index=config[KEY_CONFIG_INDEX],
                               _source_include=config[KEY_CONFIG_FIELDS],
                               _source_exclude=config[KEY_CONFIG_EXCLUDE_FIELDS],
                               doc_type=config[KEY_CONFIG_SOURCE_TYPE],
                               query=body)
            for row in self._generate_row(config, res, record):
                yield row
        else:
            res = esclient.search(index=config[KEY_CONFIG_INDEX],
                                  size=config[KEY_CONFIG_LIMIT],
                                  _source_include=config[KEY_CONFIG_FIELDS],
                                  _source_exclude=config[KEY_CONFIG_EXCLUDE_FIELDS],
                                  doc_type=config[KEY_CONFIG_SOURCE_TYPE],
                                  body=body)
            for row in self._generate_row(config, res['hits']['hits'], record):
                yield row

    def _generate_row(self,config, hits, record):
        """Generate row(s) combining row piped from splunk and hit from Elasticsearch"""
        if self.return_mv in [True, "true", "True", 1, "y"]:
            for hit in hits:
                parsed = self._parse_hit(config, hit)
                for a in parsed:
                    if not a in record:
                        record[a] = parsed[a]
                    elif isinstance(record[a], list):
                        record[a].append(parsed[a])
                    else:
                        tmp = record[a]
                        record[a]=[]
                        record[a].append(tmp)
                        record[a].append(parsed[a])
            yield record
        else:
            for hit in hits:
                parsed = self._parse_hit(config, hit)
                record.update(parsed)
                yield record

    def _parse_hit(self, config, hit):
        """Parse a Elasticsearch Hit"""

        event = {}
        if self.no_timestamp in [True, "true", "True", 1, "y"]:
            event[KEY_SPLUNK_TIMESTAMP] = time.time()
        elif self.convert_timestamp in [True, "true", "True", 1, "y"]:
            event[KEY_SPLUNK_TIMESTAMP] = self.to_epoch(hit[KEY_ELASTIC_SOURCE][config[KEY_CONFIG_TIMESTAMP]])
        else:
            event[KEY_SPLUNK_TIMESTAMP] = hit[KEY_ELASTIC_SOURCE][config[KEY_CONFIG_TIMESTAMP]]
        for key in hit[KEY_ELASTIC_SOURCE]:
            if key != config[KEY_CONFIG_TIMESTAMP]:
                if isinstance(hit[KEY_ELASTIC_SOURCE][key], dict):
                    event.update(_flattern(key, hit[KEY_ELASTIC_SOURCE][key]))
                else:
                    event[key] = hit[KEY_ELASTIC_SOURCE][key]

        if config[KEY_CONFIG_INCLUDE_ES]:
            for key in KEYS_ELASTIC:
                event["es{0}".format(key)] = hit[key]

        if config[KEY_CONFIG_INCLUDE_RAW]:
            event[KEY_SPLUNK_RAW] = json.dumps(hit)

        return event
    
    def stream(self, records):

        # Get config
        config = self._get_search_config()

        # Create Elasticsearch client
        esclient = Elasticsearch(
            config[KEY_CONFIG_EADDR],
            verify_certs=config[KEY_CONFIG_VERIFY_CERTS],
            use_ssl=config[KEY_CONFIG_USE_SSL])

        for record in records:
                for item in self._search(esclient, config, record):
                    yield item

def _flattern(key, data):
    result = {}
    for inkey in data:
        if isinstance(data[inkey], dict):
            for inkey2, value in _flattern(inkey, data[inkey]).items():
                result[key+"."+inkey2] = value
        else:
            result[key+"."+inkey] = data[inkey]
    return result
            
if __name__ == "__main__":
    dispatch(ElasticSplunkCorrelate, sys.argv, sys.stdin, sys.stdout, __name__)

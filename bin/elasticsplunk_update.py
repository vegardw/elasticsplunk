import sys
import os
import json
import calendar
from datetime import datetime
from elasticsearch import Elasticsearch, helpers
from splunklib.searchcommands import \
    dispatch, StreamingCommand, Configuration, Option, validators

# Elasticsearch document metadata keys
KEYS_ELASTIC = ("_index", "_type", "_id", "_score")
KEY_ELASTIC_SOURCE = "_source"

# Config keys
KEY_CONFIG_EADDR = "hosts"
KEY_CONFIG_TIMESTAMP = "tsfield"
KEY_CONFIG_USE_SSL = "use_ssl"
KEY_CONFIG_VERIFY_CERTS = "verify_certs"
KEY_CONFIG_FIELDS = "fields"
KEY_CONFIG_EXCLUDE_FIELDS = "exclude_fields"
KEY_CONFIG_INDEX_FIELD = "index_field"
KEY_CONFIG_INDEX = "index"
KEY_CONFIG_ID_FIELD = "id_field"
KEY_CONFIG_SOURCE_TYPE = "stype"
KEY_CONFIG_SOURCE_TYPE_FIELD = "stype_field"
KEY_CONFIG_INCLUDE_ES = "include_es"
KEY_CONFIG_INCLUDE_RAW = "include_raw"
KEY_CONFIG_CONVERT_TIMESTAMP = "convert_timestamp"
KEY_CONFIG_FORCE_REFRESH = "force_refresh"

# Splunk keys
KEY_SPLUNK_TIMESTAMP = "_time"
KEY_SPLUNK_RAW = "_raw"

@Configuration()
class ElasticSplunkUpdate(StreamingCommand):
    eaddr = Option(require=False, default="127.0.0.1 9200", doc="server:port,server:port or config item")
    tsfield = Option(require=False, default="@timestamp", doc="Field holding the event timestamp")
    index = Option(require=False, default=None, doc="Index to update")
    index_field = Option(require=False, default="es_index", doc="Field containing index to update")
    stype = Option(require=False, default=None, doc="Source/doc_type")
    stype_field = Option(require=False, default="es_type", doc="Field containing source/doc_type")
    id_field = Option(require=False, default="es_id", doc="Field containing id to update")
    fields = Option(require=False, default=None, doc="Only include selected fields")
    exclude_fields = Option(require=False, default=None, doc="Exclude selected fields")
    include_es = Option(require=False, default=False, doc="Include Elasticsearch relevant fields")
    include_raw = Option(require=False, default=False, doc="Include event source")
    use_ssl = Option(require=False, default=None, doc="Use SSL")
    verify_certs = Option(require=False, default=None, doc="Verify SSL Certificates")
    convert_timestamp = Option(require=False, default=True, doc="Convert timestamps from text to unix timestamp")
    force_refresh = Option(require=False, default=False, doc="Force refresh of shards after update")
    

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
        config[KEY_CONFIG_SOURCE_TYPE_FIELD] = self.stype_field

        config[KEY_CONFIG_INDEX] = self.index
        config[KEY_CONFIG_INDEX_FIELD] = self.index_field

        config[KEY_CONFIG_ID_FIELD] = self.id_field

        config[KEY_CONFIG_INCLUDE_ES] = self.include_es
        config[KEY_CONFIG_INCLUDE_RAW] = self.include_raw
        config[KEY_CONFIG_CONVERT_TIMESTAMP] = True if self.convert_timestamp in [True, "true", "True", 1, "y"] else False
        config[KEY_CONFIG_FORCE_REFRESH] = True if self.force_refresh in [True, "true", "True", 1, "y"] else False

        return config

    def _parse_hit(self, config, hit):
        """Parse a Elasticsearch Hit"""

        event = {}
        if config[KEY_CONFIG_TIMESTAMP] in hit["get"][KEY_ELASTIC_SOURCE]:
            if config[KEY_CONFIG_CONVERT_TIMESTAMP]:
                event[KEY_SPLUNK_TIMESTAMP] = self.to_epoch(hit["get"][KEY_ELASTIC_SOURCE][config[KEY_CONFIG_TIMESTAMP]])
            else:
                event[KEY_SPLUNK_TIMESTAMP] = hit["get"][KEY_ELASTIC_SOURCE][config[KEY_CONFIG_TIMESTAMP]]
        for key in hit["get"][KEY_ELASTIC_SOURCE]:
            if key != config[KEY_CONFIG_TIMESTAMP]:
                if isinstance(hit["get"][KEY_ELASTIC_SOURCE][key], dict):
                    event.update(_flattern(key, hit["get"][KEY_ELASTIC_SOURCE][key]))
                else:
                    event[key] = hit["get"][KEY_ELASTIC_SOURCE][key]

        if config[KEY_CONFIG_INCLUDE_ES]:
            for key in KEYS_ELASTIC:
                if key in hit:
                    event["es{0}".format(key)] = hit[key]

        if config[KEY_CONFIG_INCLUDE_RAW]:
            event[KEY_SPLUNK_RAW] = json.dumps(hit)

        return event

    def _update(self, esclient, config, record):
        remove_fields = [KEY_SPLUNK_TIMESTAMP, KEY_SPLUNK_RAW]
        for key in KEYS_ELASTIC:
            remove_fields.append("es{0}".format(key))

        if config[KEY_CONFIG_INDEX_FIELD] in record:
            config[KEY_CONFIG_INDEX] = record[config[KEY_CONFIG_INDEX_FIELD]]
            remove_fields.append(config[KEY_CONFIG_INDEX_FIELD])
        elif not config[KEY_CONFIG_INDEX]:
            raise Exception("Index to update not specified via either index or index_field parameter")
        if config[KEY_CONFIG_SOURCE_TYPE_FIELD] in record:
            config[KEY_CONFIG_SOURCE_TYPE] = record[config[KEY_CONFIG_SOURCE_TYPE_FIELD]]
            remove_fields.append(config[KEY_CONFIG_SOURCE_TYPE_FIELD])
        elif not config[KEY_CONFIG_SOURCE_TYPE]:
            raise Exception("Source/doc_type not specified via either stype or stype_field parameter")
        if not config[KEY_CONFIG_ID_FIELD] in record:
            raise Exception("Correct field containing id to update not specified via correct id_field parameter")
        else:
            remove_fields.append(config[KEY_CONFIG_ID_FIELD])

        remove_fields=set(remove_fields)
        
        body = { "doc" : {}} 
        for field in record:
            if field not in remove_fields:
                body["doc"][field] = record[field]

        res = esclient.update(index=config[KEY_CONFIG_INDEX],
                                  _source_include=config[KEY_CONFIG_FIELDS],
                                  _source_exclude=config[KEY_CONFIG_EXCLUDE_FIELDS],
                                  doc_type=config[KEY_CONFIG_SOURCE_TYPE],
                                  id=record[config[KEY_CONFIG_ID_FIELD]],
                                  body=body,
                                  refresh=config[KEY_CONFIG_FORCE_REFRESH],
                                  _source=True)

        print json.dumps(res, indent=2)

        return self._parse_hit(config, res)

    def stream(self, records):
        
        # Get config
        config = self._get_search_config()

        # Create Elasticsearch client
        esclient = Elasticsearch(
            config[KEY_CONFIG_EADDR],
            verify_certs=config[KEY_CONFIG_VERIFY_CERTS],
            use_ssl=config[KEY_CONFIG_USE_SSL])

        for record in records:
            yield self._update(esclient, config, record)

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
    dispatch(ElasticSplunkUpdate, sys.argv, sys.stdin, sys.stdout, __name__)
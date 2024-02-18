#!/usr/bin/env python
# coding: utf-8
import json
from elasticsearch import Elasticsearch
client = Elasticsearch(hosts=["http://192.168.1.235:9200"], timeout=10000)
client.info
with open('SuricataToStix/alerts/output.json') as scan_json1:
    scan_json = json.load(scan_json1)
#client.indices.delete(index="test_index")
#client.indices.create(index="test_index")

#Create fields in index
for hit in scan_json:
    print(hit)
    resp = client.index(index='test_index', id =hit['id'], body= hit)
    print(hit['id'])

client.indices.refresh()

#QUERRY INDEX
resp_test_index =client.search(index="test_index", body={"query": {"match_all": {}},"size":50})
print("Got %d Hits:" % resp_test_index['hits']['total']['value'])
for hit in resp_test_index['hits']['hits']:
    json_output = json.dumps(hit["_source"], indent=4)
    print(json_output)
    print()
#QUERRY INDEX END


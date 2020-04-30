import requests
import json
import csv
from elasticsearch import *
import time
import datetime
import _thread


es = Elasticsearch('https://87.233.6.250:64297/es/', verify_certs=False, http_auth=("honey", "G1efH0neyN0w"))

def get_honeypot_data():
    duplicate = []
    verwerkt = []
    time_last_request = datetime.datetime.utcnow()
    while True:
        tmp = str(time_last_request).split(" ")
        ES_query = {"query": {
            "bool": {
                "must": {
                    "range": {
                        "@timestamp": {
                            "gte": tmp[0] + "T" + tmp[1]
                        }
                    }
                }
            }
        }
        }

        res = es.search(index="logstash-*", size=100, body=ES_query)

        hits = res['hits']
        print(hits)

        if len(hits['hits']) != 0:
            time_last_request = datetime.datetime.utcnow()
            for hit in hits['hits']:
                try:
                    if not hit in duplicate:
                        verwerking = process_data_honeypot(hit)
                        if verwerking != None:
                            verwerkt.append(verwerking)
                except:
                    pass
                duplicate.append(hit)
            print(verwerkt)
            print(len(verwerkt))
        time.sleep(1)

def process_data_honeypot(hit):
    alert = {}
    alert['Application'] = "Honeypot"
    alert['id'] = hit['_id']
    alert['timestamp'] = hit['_source']['@timestamp']
    return alert


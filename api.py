import requests
import json
import time
from elasticsearch import *
import time
import datetime
import _thread

def get_duckhunt_data():
  verwerkt = []
  duplicate = []
  while True:
    r = requests.get(
      'https://webinsight.true.nl:443/api/search/universal/relative?query=*&range=1&fields=*&decorate=true',
      headers={'accept': 'application/json'}, allow_redirects=True, auth=('admin', '1hil6ep6Y3jI2tfCXIKcKsTlUjnZpTj8'))
    message = r.json()['messages']
    if(len(message) != 0):
      for hit in message:
        try:
          if not hit in duplicate:
            verwerking = process_data_duckhunt(hit)
            if verwerking != None:
              verwerkt.append(verwerking)
          duplicate.append(hit)
        except:
          pass
      print(verwerkt)
    time.sleep(1)


def process_data_duckhunt(hit):
  alert = {}
  alert['application'] = "Duckhunt"
  alert['id'] = hit['message']['_id']
  alert['timestamp'] = hit['message']['timestamp']
  alert['source'] = hit['message']['source']
  # if(hit['message']['rule_name']):
  #   alert['rule-name'] = hit['message']['rule_name']
  # else:
  #   alert['rule-name'] = "gelukt!"
  return alert

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
    alert['application'] = "Honeypot"
    alert['id'] = hit['_id']
    alert['timestamp'] = hit['_source']['@timestamp']
    return alert

try:
  _thread.start_new_thread(get_honeypot_data,())
  _thread.start_new_thread(get_duckhunt_data,())
except:
  print("Unable to start threads")
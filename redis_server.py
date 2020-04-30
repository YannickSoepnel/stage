import _thread
import time
import requests
import json
import time
from elasticsearch import *
import datetime

es = Elasticsearch('https://87.233.6.250:64297/es/', verify_certs=False, http_auth=("honey", "G1efH0neyN0w"))

# Define a function for the thread
def get_honeypot_data():
   count = 0
   # while True:
   #    time.sleep(1)
   #    count += 1
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

       count += 1
       hits = res['hits']
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
           print("Thread1: " + str(verwerkt))
       time.sleep(1)


def process_data_honeypot(hit):
    alert = {}
    alert['Application'] = "Honeypot"
    alert['id'] = hit['_id']
    alert['timestamp'] = hit['_source']['@timestamp']
    return alert

def get_duckhunt_data():
    duplicate = []
    verwerkt = []
    while True:
        r = requests.get(
            'https://webinsight.true.nl:443/api/search/universal/relative?query=*&range=1&fields=*&decorate=true',
            headers={'accept': 'application/json'}, allow_redirects=True,
            auth=('admin', '1hil6ep6Y3jI2tfCXIKcKsTlUjnZpTj8'))
        message = r.json()['messages']
        print("Thread2: " + str(message))
        if (len(message) != 0):
            for hit in message:
                try:
                    if not hit in duplicate:
                        verwerking = process_data_duckhunt(hit)
                        if verwerking != None:
                            verwerkt.append(verwerking)
                    duplicate.append(hit)
                except:
                    pass
        # print(hits)
        # print(threadName + time.ctime(time.time()))
        time.sleep(1)

# Create two threads as follows
try:
    _thread.start_new_thread( get_honeypot_data, () )
    _thread.start_new_thread( get_duckhunt_data, () )
except:
   print("Error: unable to start thread")

while 1:
   pass
from flask import Flask, render_template, url_for
import _thread
import time
import requests
import json
import time
from elasticsearch import *
import datetime
from dateutil.tz import tz, tzlocal

app = Flask(__name__)

es = Elasticsearch('https://87.233.6.250:64297/es/', verify_certs=False, http_auth=("honey", "G1efH0neyN0w"))

# Define a function for the thread
duplicate_honeypot = []
verwerkt_honeypot = []
duplicate_duckhunt = []
verwerkt_duckhunt = []
lengte_honeypot = {}
lengte_duckhunt = {}
lengte_combined = {}
honeypot_type = {}
abdhoney = 0
ciscoasa = 0
conpot = 0
cowrie = 0
dionaea = 0
heralding = 0
honeypy = 0
mailoney = 0
medpot = 0
rdpy = 0
tanner = 0
uncategorized = 0

gecombineerd = []

tijd1 = datetime.datetime.now() - datetime.timedelta(hours=2, seconds=15)
tijd2 = datetime.datetime.now() - datetime.timedelta(hours=1, minutes= 59, seconds = 30)
test_time = datetime.datetime.now() - datetime.timedelta(hours=2, seconds=12)
# tijd1 = last_seconds.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]+ 'Z'
# tijd2 = last_between_seconds.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]+ 'Z'
# tijd3 = test_time.strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3]+ 'Z'

# if(tijd1 <= tijd3 <= tijd2):
#     print("gelukt")
#     print(tijd3)


# print(local_datetime_converted)

def get_honeypot_data():
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

       # last_seconds = datetime.datetime.now() - datetime.timedelta(hours=2, seconds=15)
       # timeformat = str(last_seconds).split(" ")
       # tijd = timeformat[0] + "T" + timeformat[1]

       res = es.search(index="logstash-*", size=100, body=ES_query)
       hits = res['hits']
       if len(hits['hits']) != 0:
           time_last_request = datetime.datetime.utcnow()
           for hit in hits['hits']:
               try:
                   if not hit in duplicate_honeypot:
                       verwerking = process_data_honeypot(hit)
                       # print(hit['_source']['ip'])
                       if verwerking != None:
                           verwerkt_honeypot.append(verwerking)
                           gecombineerd.append(verwerking)
               except:
                   pass
               duplicate_honeypot.append(hit)
       # print("thread1: " + str(verwerkt_honeypot))
       time.sleep(1)

def rekenwerk():
    while True:
        lengte_honeypot['lengte'] = len(verwerkt_honeypot)
        lengte_duckhunt['lengte'] = len(verwerkt_duckhunt)
        lengte_combined['lengte'] = len(gecombineerd)
        time.sleep(1)

def process_data_honeypot(hit):
    global abdhoney, ciscoasa, conpot, cowrie, dionaea, heralding, honeypy, mailoney, medpot, rdpy, tanner, uncategorized
    alert = {}
    alert['application'] = "Honeypot"
    alert['id'] = hit['_id']
    alert['timestamp'] = datetime.datetime.strptime(hit['_source']['timestamp'], '%Y-%m-%dT%H:%M:%S.%fZ')
    alert['ip'] = hit['_source']['geoip']['ip']
    alert['ip_country'] = hit['_source']['geoip']['country_name']
    if(hit['_source']['type'] == "Adbhoney"):
        alert['source'] = hit['_source']['type']
        abdhoney += 1
        honeypot_type['abdhoney'] = abdhoney
    elif (hit['_source']['type'] == "Ciscoasa"):
        alert['source'] = hit['_source']['type']
        ciscoasa += 1
        honeypot_type['ciscoasa'] = ciscoasa
    elif (hit['_source']['type'] == "Conpot"):
        alert['source'] = hit['_source']['type']
        conpot += 1
        honeypot_type['conpot'] = conpot
    elif (hit['_source']['type'] == "Cowrie"):
        alert['source'] = hit['_source']['type']
        cowrie += 1
        honeypot_type['cowrie'] = cowrie
    elif (hit['_source']['type'] == "Dionaea"):
        alert['source'] = hit['_source']['type']
        dionaea += 1
        honeypot_type['dionaea'] = dionaea
    elif (hit['_source']['type'] == "Heralding"):
        alert['source'] = hit['_source']['type']
        heralding += 1
        honeypot_type['heralding'] = heralding
    elif (hit['_source']['type'] == "HoneyPy"):
        alert['source'] = hit['_source']['type']
        honeypy += 1
        honeypot_type['honeypy'] = honeypy
    elif (hit['_source']['type'] == "Mailoney"):
        alert['source'] = hit['_source']['type']
        mailoney += 1
        honeypot_type['mailoney'] = mailoney
    elif (hit['_source']['type'] == "Medpot"):
        alert['source'] = hit['_source']['type']
        medpot += 1
        honeypot_type['medpot'] = medpot
    elif (hit['_source']['type'] == "Rdpy"):
        alert['source'] = hit['_source']['type']
        rdpy += 1
        honeypot_type['rdpy'] = rdpy
    elif (hit['_source']['type'] == "Tanner"):
        alert['source'] = hit['_source']['type']
        tanner += 1
        honeypot_type['tanner'] = tanner
    else:
        alert['source'] = ""
        uncategorized += 1
        honeypot_type['uncategorized'] = uncategorized
    return alert

def get_duckhunt_data():
    while True:
        r = requests.get(
            'https://webinsight.true.nl:443/api/search/universal/relative?query=*&range=1&fields=*&decorate=true',
            headers={'accept': 'application/json'}, allow_redirects=True,
            auth=('admin', '1hil6ep6Y3jI2tfCXIKcKsTlUjnZpTj8'))
        message = r.json()['messages']
        if (len(message) != 0):
            for hit in message:
                try:
                    if not hit in duplicate_duckhunt:
                        verwerking = process_data_duckhunt(hit)
                        if verwerking != None:
                            verwerkt_duckhunt.append(verwerking)
                            gecombineerd.append(verwerking)
                    duplicate_duckhunt.append(hit)
                except:
                    pass
        time.sleep(1)

def process_data_duckhunt(hit):
  alert = {}
  alert['application'] = "Duckhunt"
  alert['id'] = hit['message']['_id']
  alert['timestamp'] = datetime.datetime.strptime(hit['message']['timestamp'], '%Y-%m-%dT%H:%M:%S.%fZ')
  alert['source'] = hit['message']['source']
  # if(hit['message']['rule_name']):
  #   alert['rule-name'] = hit['message']['rule_name']
  # else:
  #   alert['rule-name'] = "gelukt!"
  return alert

# Create two threads as follows
try:
    _thread.start_new_thread( get_honeypot_data, ())
    _thread.start_new_thread( get_duckhunt_data, ())
    _thread.start_new_thread( rekenwerk, ())
except:
   print("Error: unable to start thread")

@app.route('/')
def index():
    return 'Hello, okay!'

@app.route('/home')
def home():
    return render_template('home.html', alert_list=verwerkt_duckhunt, title='home', tijd1=tijd1, tijd2=tijd2, lengte=lengte_duckhunt)

@app.route('/combined')
def combined():
    return render_template('combined.html', alert_list=gecombineerd, title='combined', lengte=lengte_combined)

@app.route('/about')
def about():
    return render_template('about.html', title='about')

@app.route('/honeypot')
def honeypot():
    return render_template('honeypot.html', title='honeypot', alert_list=verwerkt_honeypot, tijd1=tijd1, tijd2=tijd2, lengte=lengte_honeypot, honeypot_type=honeypot_type)


if __name__ == '__main__':
    app.run(debug=True, port=5000, threaded=True)

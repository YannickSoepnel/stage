from flask import Flask, render_template, url_for, request, redirect
import _thread
import time
import requests
import json
import time
from elasticsearch import *
import datetime
import pytz
import tzlocal
import random

app = Flask(__name__)

es = Elasticsearch('https://87.233.6.250:64297/es/', verify_certs=False, http_auth=("honey", "G1efH0neyN0w"))

# Define a function for the thread
duplicate_honeypot = []
verwerkt_honeypot = []
verwerkt_ip = {}
verwerkt_landen = {}
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
lengte_unique_ips = 0

gecombineerd = []

data_visualise = []
labels_visualise = []
sorted_d = []

tijd1 = datetime.datetime.now() - datetime.timedelta(seconds=10)

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
                       if verwerking != None:
                           verwerkt_honeypot.append(verwerking)
                           gecombineerd.append(verwerking)
               except:
                   pass
               duplicate_honeypot.append(hit)
       time.sleep(1)

count = 0
histogram = {}
time_seconden_ophogen = 0

def rekenwerk():
    global count, time_seconden_ophogen, lengte_unique_ips

    time1 = datetime.datetime.now()
    time2 = datetime.datetime.now() - datetime.timedelta(seconds=20)

    while True:
        lengte_honeypot['lengte'] = len(verwerkt_honeypot)
        lengte_duckhunt['lengte'] = len(verwerkt_duckhunt)
        lengte_combined['lengte'] = len(gecombineerd)

        #--------------------------------------------------------------------
        # VISUALISEREN REKENWERK
        lengte_unique_ips = len(verwerkt_ip) #lengte van unique source ips

        #Labels voor pie chart landen met aantal keer aanval
        for key in verwerkt_ip:
            if not key in labels_visualise:
                labels_visualise.append(key)
                data_visualise.append(verwerkt_ip[key][0])

        #Rekenwerk voor histogram
        time_seconden_ophogen += 1 #Elke seconde verhogen met 1 seconde
        if(time_seconden_ophogen == 20): #1800 seconden = 30 minuten
            for item in verwerkt_honeypot:
                if (time2 <= item['timestamp'] <= time1):
                    count += 1
            histogram[time2] = count
            count = 0
            time_seconden_ophogen = 0
            time1 = datetime.datetime.now() #na 30 minuten wordt er een nieuwe now time aangeroepen
            time2 = datetime.datetime.now() - datetime.timedelta(seconds=20) #now tot +30 minuten wordt berekend
        time.sleep(1) #Elke seconde aanroepen
        #--------------------------------------------------------------------


def process_data_honeypot(hit):
    global abdhoney, ciscoasa, conpot, cowrie, dionaea, heralding, honeypy, mailoney, medpot, rdpy, tanner, uncategorized, verwerkt_ip, sorted_d
    alert = {}
    alert['application'] = "Honeypot"
    alert['id'] = hit['_id']
    alert['timestamp'] = convert_timezone(hit['_source']['@timestamp'])
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
    ip_to_add = hit['_source']['geoip']['ip']
    if not ip_to_add in verwerkt_ip:
        verwerkt_ip[ip_to_add] = [1, hit['_source']['geoip']['country_name']]
    else:
        verwerkt_ip[ip_to_add][0] += 1
    country_to_add = hit['_source']['geoip']['country_name']
    r = str(random.randint(0, 255))
    g = str(random.randint(0, 255))
    b = str(random.randint(0, 255))
    color = "rgba(" + r + ", " + g + ", " + b + ")"
    if not country_to_add in verwerkt_landen:
        verwerkt_landen[country_to_add] = [1, color]
    else:
        verwerkt_landen[country_to_add][0] += 1

    sorted_d = sorted(verwerkt_ip.items(), key=lambda x: x[1], reverse=True)
    print(sorted_d)

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
  alert['timestamp'] = convert_timezone(hit['message']['timestamp'])
  alert['source'] = hit['message']['source']
  # if(hit['message']['rule_name']):
  #   alert['rule-name'] = hit['message']['rule_name']
  # else:
  #   alert['rule-name'] = "gelukt!"
  return alert

def convert_timezone(time):
    tijd = time
    convert_time = datetime.datetime.strptime(tijd, '%Y-%m-%dT%H:%M:%S.%fZ')
    local_timezone = tzlocal.get_localzone() #Haal locale tijdzone op
    convert = convert_time.replace(tzinfo=pytz.utc).astimezone(local_timezone)
    converted = convert.replace(tzinfo=None) #Verwijder +02:00 aan date format
    return converted

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

@app.route('/home', methods=["GET", "POST"])
def home():
    return render_template('home.html', alert_list=verwerkt_duckhunt, title='home', tijd1=tijd1, lengte=lengte_duckhunt)

@app.route('/combined', methods=["GET", "POST"])
def combined():
    if request.method == "POST":
        nieuwe_tijd = request.form["tijd"]
        print(nieuwe_tijd)
        print("gelukt")
    return render_template('combined.html', alert_list=gecombineerd, title='combined', lengte=lengte_combined)
@app.route('/about')
def about():
    return render_template('about.html', title='about')

@app.route('/honeypot', methods=["GET", "POST"])
def honeypot():
    global tijd1
    if request.method == "POST":
        nieuwe_tijd = request.form["tijd"]
        if(nieuwe_tijd == "15 minuten"):
            tijd1 = datetime.datetime.now() - datetime.timedelta(seconds=10)
            print("15 minuten")
            return redirect(request.path,code=302)
        elif(nieuwe_tijd == "30 minuten"):
            tijd1 = datetime.datetime.now() - datetime.timedelta(minutes=10)
            print("30 minuten")
            return redirect(request.path,code=302)
        elif(nieuwe_tijd == "1 uur"):
            tijd1 = datetime.datetime.now() - datetime.timedelta(minutes=15)
            return redirect(request.path, code=302)
    elif request.method == "POST":
        tijd1 = datetime.datetime.now() - datetime.timedelta(minutes=1)
        print("else")
    return render_template('honeypot.html', title='honeypot', alert_list=verwerkt_honeypot, tijd1=tijd1, lengte=lengte_honeypot, honeypot_type=honeypot_type, verwerkt_ip=verwerkt_ip, histogram=histogram)

@app.route("/visualise")
def visualise():
    legend = 'Most attacking ips'
    # labels = ["January", "February", "March", "April", "May", "June", "July", "August"]
    # values = [10, 9, 8, 7, 6, 4, 7, 8]
    return render_template('visualise.html', values=data_visualise, labels=labels_visualise, legend=legend, verwerkt_ip=verwerkt_ip, verwerkt_landen=verwerkt_landen, histogram=histogram, lengte_unique_ips = lengte_unique_ips,lengte_honeypot=lengte_honeypot, sorted_d = sorted_d)


if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5000, threaded=True)

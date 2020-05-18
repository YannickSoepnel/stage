from flask import Flask, render_template, url_for, request, redirect
import _thread
import urllib3
import time
import requests
import json
import time
from elasticsearch import *
import datetime
import pytz
import tzlocal
import random
import pycountry
import mysql.connector
from flaskext.mysql import MySQL
from flask_sqlalchemy import SQLAlchemy

urllib3.disable_warnings()

app = Flask(__name__)

db = SQLAlchemy(app)

SQLALCHEMY_DATABASE_URI = "mysql+pymysql://root:ihvhbs93@localhost/stageproject"

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI

mysql = MySQL()

mysql.init_app(app)

class landen_db(db.Model):
    landen_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))
    score = db.Column(db.Integer)

class frequentie_db(db.Model):
    frequentie_id = db.Column(db.Integer, primary_key=True)
    waarde1 = db.Column(db.Integer)
    waarde2 = db.Column(db.Integer)
    score = db.Column(db.Integer)

class alerts_db(db.Model):
    alerts_id = db.Column(db.Integer, primary_key=True)
    applicatie = db.Column(db.String(255))
    id = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime)
    source_ip = db.Column(db.String(255))
    destination_ip = db.Column(db.String(255))
    document_type = db.Column(db.String(255))
    unieke_data = db.Column(db.Text)


alert = alerts_db.query.filter_by(applicatie='honeypot').all()
for ding in alert:
    print(ding.id)
    print(ding.destination_ip)
    print(ding.timestamp)

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
lengte_unique_ips = 0
gecombineerd = []
ungraded_events = []
host_grade = {}

data_visualise = []
labels_visualise = []
sorted_d = []
sorted_histogram = []
count_meer_informatie = 0

count = 0
histogram = {}
time_seconden_ophogen = 0


tijd1 = datetime.datetime.now() - datetime.timedelta(seconds=10)

def get_honeypot_data():
    es = Elasticsearch('https://87.233.6.250:64297/es/', verify_certs=False, http_auth=("honey", "G1efH0neyN0w"), ignore_warnings=True)
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
                           ungraded_events.append(verwerking)
               except:
                   pass
               duplicate_honeypot.append(hit)
       time.sleep(1)


def unieke_data_sorteren_honeypot(data):
    unieke_data_honeypot = {}
    for key, value in data.items():
        if isinstance(value, dict):
            for key1, value1 in value.items():
                if isinstance(value1, dict):
                    for key2, value2 in value1.items():
                        if isinstance(value2, dict):
                            for key3, value3 in value2.items():
                                if isinstance(value3, dict):
                                    for key4, value4 in value3.items():
                                        if isinstance(value4, dict):
                                            pass
                                        else:
                                            unieke_data_honeypot[key4] = value4
                                else:
                                    unieke_data_honeypot[key3] = value3
                        else:
                            unieke_data_honeypot[key2] = value2
                else:
                    unieke_data_honeypot[key1] = value1
        else:
            unieke_data_honeypot[key] = value
    return unieke_data_honeypot


def unieke_data_sorteren_duckhunt(data):
    unieke_data_duckhunt = {}
    for key, value in data.items():
        if isinstance(value, dict):
            for key1, value1 in value.items():
                if isinstance(value1, dict):
                    for key2, value2 in value1.items():
                        if isinstance(value2, dict):
                            for key3, value3 in value2.items():
                                if isinstance(value3, dict):
                                    for key4, value4 in value3.items():
                                        if isinstance(value4, dict):
                                            pass
                                        else:
                                            unieke_data_duckhunt[key4] = value4
                                else:
                                    unieke_data_duckhunt[key3] = value3
                        else:
                            unieke_data_duckhunt[key2] = value2
                else:
                    unieke_data_duckhunt[key1] = value1
        else:
            unieke_data_duckhunt[key] = value
    return unieke_data_duckhunt

def rekenwerk():
    global count, time_seconden_ophogen, lengte_unique_ips, sorted_d, sorted_histogram

    time1 = datetime.datetime.now()
    time2 = datetime.datetime.now() - datetime.timedelta(seconds=60)

    while True:
        lengte_combined['lengte'] = len(gecombineerd)

        #--------------------------------------------------------------------
        # VISUALISEREN REKENWERK
        lengte_unique_ips = len(verwerkt_ip) #lengte van unique source ips

        sorted_d = sorted(verwerkt_ip.items(), key=lambda x: x[1], reverse=True) #Gesorteerde lijst voor top 10 aanvallers tabel

        #Labels voor pie chart landen met aantal keer aanval
        for key in verwerkt_ip:
            if not key in labels_visualise:
                labels_visualise.append(key)
                data_visualise.append(verwerkt_ip[key][0])

        #Rekenwerk voor histogram
        time_seconden_ophogen += 1 #Elke seconde verhogen met 1 seconde
        if(time_seconden_ophogen == 60): #1800 seconden = 30 minuten
            for item in verwerkt_honeypot:
                if (time2 <= item['timestamp'] <= time1):
                    count += 1
            histogram[time2.strftime("%H:%M:%S")] = count
            count = 0
            time_seconden_ophogen = 0
            time1 = datetime.datetime.now() #na 30 minuten wordt er een nieuwe now time aangeroepen
            time2 = datetime.datetime.now() - datetime.timedelta(seconds=60) #now tot +30 minuten wordt berekend
        sorted_histogram = sorted(histogram.items(), key=lambda x: x[0])
        #--------------------------------------------------------------------


        #Grading events
        #
        #   host_grade[IP-adres] = [LAND, FREQUENTIE, APPLICATIE, RULE_ID]
        #
        #   {'IP-adres': [LAND, FREQUENTIE, APPLICATIE]}
        #
        for alert in ungraded_events:
            host_grade_ip = alert['source_ip']
            if(alert['source_country'] == "Netherlands") or (alert['source_country'] == "Belgium"): #Grading home country)
                host_grade[host_grade_ip] = [-1, 0, 0]
            elif(alert['source_country'] == "Germany") or (alert['source_country'] == "France") or (alert['source_country'] == "Italy"):
                host_grade[host_grade_ip] = [2, 0, 0]
            elif(alert['source_country'] == "China"):
                host_grade[host_grade_ip] = [10, 0, 0]
            else:
                host_grade[host_grade_ip] = [5, 0, 0]
            if(host_grade_ip in verwerkt_ip):
                if(verwerkt_ip[host_grade_ip][0] <= 10):
                    host_grade[host_grade_ip][1] = 2
                elif(10 <= verwerkt_ip[host_grade_ip][0] <= 20):
                    host_grade[host_grade_ip][1] = 5
                elif (20 <= verwerkt_ip[host_grade_ip][0] <= 100):
                    host_grade[host_grade_ip][1] = 10
                elif(100 <= verwerkt_ip[host_grade_ip][0]):
                    host_grade[host_grade_ip][1] = 100
            if(alert['application'] == 'honeypot'): #Hogere score als alert van honeypot is
                host_grade[host_grade_ip][2] = 10
            elif(alert['application'] == 'duckhunt'):
                host_grade[host_grade_ip][2] = 5
            ungraded_events.remove(alert)
        time.sleep(1)

def process_data_honeypot(hit):
    alert = {}
    alert['application'] = "honeypot"
    alert['id'] = hit['_id']
    alert['timestamp'] = convert_timezone(hit['_source']['@timestamp'])
    alert['source_ip'] = hit['_source']['geoip']['ip']
    alert['destination_ip'] = hit['_source']['dest_ip']
    alert['source_country'] = hit['_source']['geoip']['country_name']
    alert['document_type'] = hit['_source']['type']
    alert['unieke_data'] = unieke_data_sorteren_honeypot(hit)

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

    new_alert = alerts_db(
        applicatie = alert['application'],
        id = alert['id'],
        timestamp = alert['timestamp'],
        source_ip = alert['source_ip'],
        destination_ip = alert['destination_ip'],
        document_type = alert['document_type'],
        unieke_data = str(alert['unieke_data'])
    )
    db.session.add(new_alert)
    db.session.commit()
    return alert

def get_duckhunt_data():
    while True:
        r = requests.get(
            'https://webinsight.true.nl:443/api/search/universal/relative?query=trueserver_document_type%3Aduckhunt%5C-modsecurity%20OR%20trueserver_document_type%3Aduckhunt%5C-suricata&range=1&fields=*&decorate=true',
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
                            ungraded_events.append(verwerking)
                    duplicate_duckhunt.append(hit)
                except:
                    pass
        time.sleep(1)

def get_palo_data():
    while True:
        r = requests.get(
            'https://logs.true.nl:443/api/search/universal/relative?query=pa5050&range=10&decorate=true',
            headers={'accept': 'application/json'}, allow_redirects=True,
            auth=('yannick.soepnel@true.nl', 'Rome:Fell:0!'))
        message = r.json()['messages']
        # if (len(message) != 0):
        #     for hit in message:
        #         try:
        #             print(hit)
        #         except:
        #             pass
        time.sleep(1)

def process_data_duckhunt(hit):
    alert = {}
    alert['application'] = "duckhunt"
    alert['id'] = hit['message']['_id']
    alert['timestamp'] = convert_timezone(hit['message']['timestamp'])
    if(hit['message']['trueserver_document_type'] == 'duckhunt-suricata'):
        alert['source_ip'] = hit['message']['http_xff']
        alert['destination_ip'] = hit['message']['http_hostname']
        alert['source_country'] = pycountry.countries.get(alpha_2=hit['message']['http_xff_country_code']).name
        alert['document_type'] = "suricata"
        alert['unieke_data'] = unieke_data_sorteren_duckhunt(hit)
    elif(hit['message']['trueserver_document_type'] == 'duckhunt-modsecurity'):
        alert['source_ip'] = hit['message']['transaction_client_ip']
        alert['destination_ip'] = hit['message']['transaction_host_ip']
        alert['source_country'] = pycountry.countries.get(alpha_2=hit['message']['transaction_client_ip_country_code']).name
        alert['document_type'] = "modsecurity"
        alert['unieke_data'] = unieke_data_sorteren_duckhunt(hit)
    ip_to_add = alert['source_ip']
    if not ip_to_add in verwerkt_ip:
      verwerkt_ip[ip_to_add] = [1, alert['source_country']]
    else:
      verwerkt_ip[ip_to_add][0] += 1
    country_to_add = alert['source_country']
    r = str(random.randint(0, 255))
    g = str(random.randint(0, 255))
    b = str(random.randint(0, 255))
    color = "rgba(" + r + ", " + g + ", " + b + ")"
    if not country_to_add in verwerkt_landen:
        verwerkt_landen[country_to_add] = [1, color]
    else:
        verwerkt_landen[country_to_add][0] += 1
    new_alert = alerts_db(
        applicatie=alert['application'],
        id=alert['id'],
        timestamp=alert['timestamp'],
        source_ip=alert['source_ip'],
        destination_ip=alert['destination_ip'],
        document_type=alert['document_type'],
        unieke_data=str(alert['unieke_data'])
    )
    db.session.add(new_alert)
    db.session.commit()
    return alert

def convert_timezone(time):
    tijd = time
    convert_time = datetime.datetime.strptime(tijd, '%Y-%m-%dT%H:%M:%S.%fZ')
    local_timezone = tzlocal.get_localzone() #Haal locale tijdzone op
    convert = convert_time.replace(tzinfo=pytz.utc).astimezone(local_timezone)
    converted = convert.replace(tzinfo=None) #Verwijder +02:00 aan date format
    return converted

# def refresh_database():
    global database_landen
    while True:
        mycursor.execute("SELECT * FROM landen")
        database_landen = mycursor.fetchall()
        mydb.commit()
        # print(database_landen)
        time.sleep(3)

# Create two threads as follows
try:
    _thread.start_new_thread( get_honeypot_data, ())
    _thread.start_new_thread( get_duckhunt_data, ())
    _thread.start_new_thread( rekenwerk, ())
    # _thread.start_new_thread( get_palo_data, ())
    # _thread.start_new_thread( refresh_database, ())
except:
   print("Error: unable to start thread")

@app.route('/')
def index():
    return 'Hello, okay!'

@app.route('/home', methods=["GET", "POST"])
def home():
    return render_template('home.html', alert_list=verwerkt_duckhunt, title='home', tijd1=tijd1, lengte=lengte_duckhunt)

@app.route('/visualisation', methods=["GET", "POST"])
def visualisation():
    return render_template('visualisation.html', alert_list=verwerkt_duckhunt, title='home', tijd1=tijd1, lengte=lengte_duckhunt)

@app.route('/combined', methods=["GET", "POST"])
def combined():
    global tijd1, count_meer_informatie
    if request.method == "POST":
        nieuwe_tijd = request.form["tijd"]
        if (nieuwe_tijd == "15 minuten"):
            tijd1 = datetime.datetime.now() - datetime.timedelta(seconds=10)
            print("15 minuten")
            return redirect(request.path, code=302)
        elif (nieuwe_tijd == "30 minuten"):
            tijd1 = datetime.datetime.now() - datetime.timedelta(minutes=10)
            print("30 minuten")
            return redirect(request.path, code=302)
        elif (nieuwe_tijd == "1 uur"):
            tijd1 = datetime.datetime.now() - datetime.timedelta(minutes=15)
            return redirect(request.path, code=302)
    elif request.method == "POST":
        tijd1 = datetime.datetime.now() - datetime.timedelta(seconds=2)
        print("else")
    return render_template('combined.html', alert_list=gecombineerd, title='combined', lengte=lengte_combined, tijd1=tijd1, count=count_meer_informatie)

@app.route('/settings', methods=["GET", "POST"])
def settings():
    if request.method == "POST":
        form = request.form
        print(form)
        for k,v in form.items():
            sql = """UPDATE landen SET score = %s WHERE name = %s"""
            data = (v, k)
            mycursor.execute(sql, data)
            print(mycursor)
    return render_template('settings.html', title='settings', database_landen=database_landen)

@app.route('/about')
def about():
    return render_template('about.html', title='about')


p = ['a','b','c','d']

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
    return render_template('honeypot.html', title='honeypot', alert_list=verwerkt_honeypot, tijd1=tijd1, lengte=lengte_honeypot, verwerkt_ip=verwerkt_ip, histogram=histogram, p=p)

@app.route("/visualise")
def visualise():
    legend = 'Most attacking ips'
    # labels = ["January", "February", "March", "April", "May", "June", "July", "August"]
    # values = [10, 9, 8, 7, 6, 4, 7, 8]
    return render_template('visualise.html', sorted_histogram = sorted_histogram,values=data_visualise, labels=labels_visualise, legend=legend, verwerkt_ip=verwerkt_ip, verwerkt_landen=verwerkt_landen, histogram=histogram, lengte_unique_ips = lengte_unique_ips,lengte=lengte_combined, sorted_d = sorted_d, host_grade=host_grade)


if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5000, threaded=True)

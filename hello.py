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
from flaskext.mysql import MySQL
from flask_sqlalchemy import SQLAlchemy
from geoip import geolite2
import traceback
from sqlalchemy import *
from sqlalchemy.orm import scoped_session, sessionmaker
from collections import OrderedDict
import smtplib
import pymsteams

urllib3.disable_warnings()

app = Flask(__name__)

db = SQLAlchemy(app)
db2 = SQLAlchemy(app)
db3 = SQLAlchemy(app)
db4 = SQLAlchemy(app)
db5 = SQLAlchemy(app)
db6 = SQLAlchemy(app)
db7 = SQLAlchemy(app)

engine = create_engine("mysql+pymysql://root:ihvhbs93@localhost/stageproject", pool_pre_ping=True)

server = smtplib.SMTP('smtp.office365.com', 587)
server.starttls()
server.login('yannick.soepnel@true.nl', 'Rome:Fell:0!')

Session = scoped_session(sessionmaker(engine, autoflush=True, expire_on_commit = False))

SQLALCHEMY_DATABASE_URI = "mysql+pymysql://root:ihvhbs93@localhost/stageproject?charset=utf8mb4"

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI

mysql = MySQL()

mysql.init_app(app)

class landen_db(db.Model):
    land_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))
    score = db.Column(db.Integer)

class frequenties_db(db.Model):
    frequentie_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))
    value1 = db.Column(db.Integer)
    value2 = db.Column(db.Integer)
    score = db.Column(db.Integer)

class alerts_db(db.Model):
    alert_id = db.Column(db.Integer, primary_key=True)
    applicatie = db.Column(db.String(255))
    id = db.Column(db.String(255))
    timestamp = db.Column(db.DateTime)
    source_ip = db.Column(db.String(255))
    destination_ip = db.Column(db.String(255))
    source_country = db.Column(db.String(255))
    document_type = db.Column(db.String(255))
    unieke_data = db.Column(db.Text(4294000000))

class rules_db(db3.Model):
    rule_db_id = db3.Column(db.Integer, primary_key=True)
    name = db3.Column(db.String(255))
    rule_code = db3.Column(db.Integer, unique=True)
    score = db3.Column(db.Integer)
    count = db3.Column(db.Integer)

class applicaties_db(db.Model):
    applicatie_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))
    score = db.Column(db.Integer)

class acties_db(db.Model):
    actie_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255))
    score1 = db.Column(db.Integer)
    score2 = db.Column(db.Integer)

#Laad alle database gegevens in lijsten
database_landen = landen_db.query.all()
database_alerts = alerts_db.query.all()
database_frequenties = frequenties_db.query.all()
database_rules = rules_db.query.order_by(rules_db.count.desc()).all()
database_applicaties = applicaties_db.query.all()
database_acties = acties_db.query.all()

duplicate_honeypot = []
verwerkt_honeypot = []
verwerkt_ip = {}
verwerkt_landen = {}
duplicate_duckhunt = []
verwerkt_duckhunt = []
verwerkt_logprocessor = []
duplicate_logprocessor = []
duplicate_palo_alto = []
gecombineerd = []                   ## Dit is de lijst met alle verwerkte alerts
ungraded_events = []
host_grade = {}
host_grade_log = {}
host_grade_alert = {}
host_grade_ban = {}
send_alert_list = []
send_abuse_list = []

data_visualise = []
labels_visualise = []
sorted_d_verwerkt_ip = []
sorted_d_verwerkt_land = []
sorted_histogram = []
sorted_d_host_grade_log = []
sorted_d_host_grade_alert = []
sorted_d_host_grade_ban = []

count = 0
histogram = {}
time_seconden_ophogen = 0

tijd1 = datetime.datetime.now() - datetime.timedelta(seconds=10)

def get_honeypot_data(): ## ophalen honeypot data
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

def get_duckhunt_data(): ## ophalen duckhunt data
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
                        print(hit)
                        if verwerking != None:
                            verwerkt_duckhunt.append(verwerking)
                            gecombineerd.append(verwerking)
                            ungraded_events.append(verwerking)
                    duplicate_duckhunt.append(hit)
                except:
                    pass
        time.sleep(1)

def get_palo_data(): ## ophalen palo alto data
    while True:
        r = requests.get(
            'https://logs.true.nl:443/api/search/universal/relative?query=pa5050&range=10&decorate=true',
            headers={'accept': 'application/json'}, allow_redirects=True,
            auth=('yannick.soepnel@true.nl', 'Rome:Fell:0!'))
        message = r.json()['messages']
        if (len(message) != 0):
            for hit in message:
                try:
                    if not hit in duplicate_palo_alto:
                        verwerking = process_data_palo(hit)
                        if verwerking != None:
                            gecombineerd.append(verwerking)
                            ungraded_events.append(verwerking)
                    duplicate_palo_alto.append(hit)
                except:
                    pass
        time.sleep(1)

def get_logprocessor_data(): ## ophalen logprocessor data
    while True:
        r = requests.get(
            'https://logprocessor.true.nl/abuser/get_security_alerts?timeframe=1'
        )
        message = r.json()

        if (len(message) != 0):
            for m in message:
                hit = json.loads(m)
                try:
                    if not hit in duplicate_logprocessor:
                        verwerking = process_data_logprocessor(hit)
                        if verwerking != None:
                            verwerkt_logprocessor.append(verwerking)
                            gecombineerd.append(verwerking)
                            ungraded_events.append(verwerking)
                    duplicate_logprocessor.append(hit)
                except:
                    pass
        time.sleep(1)

def unieke_data_sorteren(data): ## Deze functie zorgt ervoor dat een hele alert goed geparsed wordt zodat hij weergegeven kan worden in unieke data / Meer informatie knop
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
    global count, time_seconden_ophogen, sorted_d_verwerkt_ip, sorted_histogram, sorted_d_verwerkt_land, error_rekenwerk, sorted_d_host_grade_log, sorted_d_host_grade_alert, sorted_d_host_grade_ban

    time1 = datetime.datetime.now()
    time2 = datetime.datetime.now() - datetime.timedelta(seconds=60)

    while True:
        #--------------------------------------------------------------------
        # VISUALISEREN REKENWERK

        sorted_d_verwerkt_ip = sorted(verwerkt_ip.items(), key=lambda x: x[1], reverse=True) #Gesorteerde lijst voor top 10 aanvallers tabel
        sorted_d_verwerkt_land = sorted(verwerkt_landen.items(), key=lambda x: x[1], reverse=True) ##gesorteerde lijst voor piechart
        sorted_d_host_grade_log = sorted(host_grade_log.items(), key=lambda x: x[1][1][0], reverse=True) #Gesorteerde lijst voor logs
        sorted_d_host_grade_alert = sorted(host_grade_alert.items(), key=lambda x: x[1][1][0], reverse=True) #Gesorteerde lijst voor alerts
        sorted_d_host_grade_ban = sorted(host_grade_ban.items(), key=lambda x: x[1][1][0], reverse=True) #Gesorteerde lijst voor bans

        #Labels voor pie chart landen met aantal keer aanval
        for key in verwerkt_ip:
            if not key in labels_visualise:
                labels_visualise.append(key)
                data_visualise.append(verwerkt_ip[key][0])

        #Rekenwerk voor histogram
        time_seconden_ophogen += 1 #Elke seconde verhogen met 1 seconde
        if(time_seconden_ophogen == 3600): #3600 seconden = 60 minuten
            for item in gecombineerd:
                if (time2 <= item['timestamp'] <= time1):
                    count += 1
            histogram[time2.strftime("%H:%M:%S")] = count
            count = 0
            time_seconden_ophogen = 0
            time1 = datetime.datetime.now() #na 60 minuten wordt er een nieuwe now time aangeroepen
            time2 = datetime.datetime.now() - datetime.timedelta(seconds=3600) #now tot +60 minuten wordt berekend
        sorted_histogram = sorted(histogram.items(), key=lambda x: x[0])
        #--------------------------------------------------------------------


        #Grading events
        #
        #   host_grade[IP-adres] = [LAND, FREQUENTIE, APPLICATIE , RULE_ID]
        #
        #   {'IP-adres': [LAND, FREQUENTIE, APPLICATIE]}
        #
        for alert in ungraded_events:
            try:
                host_grade_ip = alert['source_ip']
                for land in database_landen:
                    if (land.name == alert['source_country']): #graden op basis van het land.
                        host_grade[host_grade_ip] = [land.score, 0, 0, 0],[alert['timestamp'], alert['source_country'], alert['application']]
                for frequentie in database_frequenties: #Grading op basis van aantal keer dat IP voorkomt
                    if(frequentie.frequentie_id == 1):
                        if (verwerkt_ip[host_grade_ip][0] <= frequentie.value2):
                            host_grade[host_grade_ip][0][1] = frequentie.score
                    elif(frequentie.frequentie_id == 2):
                        if(frequentie.value1 <= verwerkt_ip[host_grade_ip][0] <= frequentie.value2):
                            host_grade[host_grade_ip][0][1] = frequentie.score
                    elif(frequentie.frequentie_id == 3):
                        if(frequentie.value1 <= verwerkt_ip[host_grade_ip][0]):
                            host_grade[host_grade_ip][0][1] = frequentie.score
                for applicatie in database_applicaties:             #Grading op basis van applicatie
                    if(applicatie.name == alert['application']):
                        if(alert['application'] == 'duckhunt'):
                            host_grade[host_grade_ip][0][2] = applicatie.score
                            for rule in database_rules:                 #Grading op basis van getriggerde rule
                                if(str(rule.rule_code) == alert['rule_id']):
                                    host_grade[host_grade_ip][0][3] = rule.score
                        elif(alert['application'] == 'honeypot'):
                            host_grade[host_grade_ip][0][2] = applicatie.score
                        else:
                            host_grade[host_grade_ip][0][2] = applicatie.score
                total_score = host_grade[host_grade_ip][0][0] + host_grade[host_grade_ip][0][1] + host_grade[host_grade_ip][0][2] + host_grade[host_grade_ip][0][3]

                for actie in database_acties: #Actie ondernemen op gemaakte score
                    if(actie.actie_id == 1):
                        if(total_score <= actie.score2):
                            host_grade_log[host_grade_ip] = host_grade[host_grade_ip]
                    elif(actie.actie_id == 2):
                        if(actie.score1 <= total_score <= actie.score2):
                            host_grade_alert[host_grade_ip] = host_grade[host_grade_ip]
                            send_alert(alert)
                            try:
                                del host_grade_log[host_grade_ip]
                            except:
                                pass
                    elif(actie.actie_id == 3):
                        if(actie.score1 <= total_score):
                            host_grade_ban[host_grade_ip] = host_grade[host_grade_ip]
                            send_abuse_email(alert)
                            try:
                                del host_grade_alert[host_grade_ip]
                            except:
                                pass
            except:
                pass
            ungraded_events.remove(alert)
        time.sleep(1)

def process_data_honeypot(hit): #verwerken van honeypot data
    global database_alerts
    alert = {}
    alert['application'] = "honeypot"
    alert['id'] = hit['_id']
    alert['timestamp'] = convert_timezone(hit['_source']['@timestamp'])
    alert['source_ip'] = hit['_source']['geoip']['ip']
    alert['destination_ip'] = hit['_source']['dest_ip']
    if(hit['_source']['geoip']['country_name'] == "Republic of Moldova"):
        alert['source_country'] = "Moldova"
    elif(hit['_source']['geoip']['country_name'] == 'Republic of Korea'):
        alert['source_country'] = "Korea, Republic of"
    elif(hit['_source']['geoip']['country_name'] == 'Iran'):
        alert['source_country'] = "Iran, Islamic Republic of"
    else:
        alert['source_country'] = hit['_source']['geoip']['country_name']
    alert['document_type'] = hit['_source']['type']
    alert['unieke_data'] = unieke_data_sorteren(hit)
    ip_to_add = hit['_source']['geoip']['ip']
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
        applicatie = alert['application'],
        id = alert['id'],
        timestamp = alert['timestamp'],
        source_ip = alert['source_ip'],
        destination_ip = alert['destination_ip'],
        source_country=alert['source_country'],
        document_type = alert['document_type'],
        unieke_data = str(alert['unieke_data'])
    )
    db2.session.add(new_alert)
    db2.session.commit()
    db2.session.close()
    return alert

def process_data_duckhunt(hit):
    global database_rules, duplicate_process_duckhunt, database_alerts
    alert = {}
    alert['application'] = "duckhunt"
    alert['id'] = hit['message']['_id']
    alert['timestamp'] = convert_timezone(hit['message']['timestamp'])
    if (hit['message']['trueserver_document_type'] == 'duckhunt-suricata'):
        try:
            alert['source_ip'] = hit['message']['http_xff']
            alert['destination_ip'] = hit['message']['http_hostname']
            try:
                if (hit['message']['http_xff_country_code'] == 'RU'):
                    alert['source_country'] = "Russia"
                elif (hit['message']['http_xff_country_code'] == 'TW'):
                    alert['source_country'] = "Taiwan"
                elif (hit['message']['http_xff_country_code'] == 'KR'):
                    alert['source_country'] = "Korea, Republic of"
                else:
                    try:
                        alert['source_country'] = pycountry.countries.get(
                            alpha_2=hit['message']['http_xff_country_code']).common_name
                    except:
                        alert['source_country'] = pycountry.countries.get(alpha_2=hit['message']['http_xff_country_code']).name
            except KeyError:
                match = geolite2.lookup(hit['message']['http_xff'])
                if match is not None:
                    try:
                        alert['source_country'] = pycountry.countries.get(
                            alpha_2=match.country).common_name
                    except:
                        alert['source_country'] = pycountry.countries.get(
                            alpha_2=match.country).name
                    print("except land gevonden suricata")
                    print(alert['source_country'])
                else:
                    alert['source_country'] = 'None'
            try:
                alert['rule_id'] = hit['message']['alert_signature_id']
                if (db3.session.query(rules_db.rule_code).filter_by(rule_code=alert['rule_id']).scalar() is not None):
                    sql = """UPDATE rules_db SET count = count + 1 WHERE rule_code = %s"""
                    data = alert['rule_id']
                    db3.engine.execute(sql, data)
                else:
                    new_rule = rules_db(
                        name=hit['message']['alert_signature'],
                        rule_code=int(hit['message']['alert_signature_id']),
                        score=1,
                        count=1
                    )
                    db3.session.add(new_rule)
                    print(alert['rule_id'])
                    print('nieuwe rule geadd')
                    print(hit)
            except Exception as e:
                pass
        except KeyError:
            return None
        alert['document_type'] = "suricata"
        alert['unieke_data'] = unieke_data_sorteren(hit)

    elif (hit['message']['trueserver_document_type'] == 'duckhunt-modsecurity'):
        try:
            alert['source_ip'] = hit['message']['transaction_client_ip']
            alert['destination_ip'] = hit['message']['transaction_host_ip']
            try:
                if (hit['message']['transaction_client_ip_country_code'] == 'RU'):
                    alert['source_country'] = "Russia"
                elif (hit['message']['transaction_client_ip_country_code'] == 'TW'):
                    alert['source_country'] = "Taiwan"
                elif (hit['message']['transaction_client_ip_country_code'] == 'KR'):
                    alert['source_country'] = "Korea, Republic of"
                else:
                    try:
                        alert['source_country'] = pycountry.countries.get(
                            alpha_2=hit['message']['transaction_client_ip_country_code']).common_name
                    except:
                        alert['source_country'] = pycountry.countries.get(
                            alpha_2=hit['message']['transaction_client_ip_country_code']).name
            except KeyError:
                match = geolite2.lookup(hit['message']['transaction_client_ip'])
                if match is not None:
                    try:
                        alert['source_country'] = pycountry.countries.get(
                            alpha_2=match.country).common_name
                    except:
                        alert['source_country'] = pycountry.countries.get(
                            alpha_2=match.country).name
                    print(alert['source_country'])
                else:
                    alert['source_country'] = 'None'
            try:
                alert['rule_id'] = hit['message']['ruleId']
                if (db3.session.query(rules_db.rule_code).filter_by(rule_code=alert['rule_id']).scalar() is not None):
                    sql = """UPDATE rules_db SET count = count + 1 WHERE rule_code = %s"""
                    data = alert['rule_id']
                    db3.engine.execute(sql, data)
                else:
                        new_rule = rules_db(
                            name=hit['message']['rule_name'],
                            rule_code=int(hit['message']['ruleId']),
                            score=1,
                            count=1
                        )
                        db3.session.add(new_rule)
                        print(alert['rule_id'])
                        print('nieuwe rule geadd')
                        print(hit)
            except Exception as e:
                pass
        except KeyError:
            return None
    alert['document_type'] = "modsecurity"
    alert['unieke_data'] = unieke_data_sorteren(hit)

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
        source_country=alert['source_country'],
        document_type=alert['document_type'],
        unieke_data=str(alert['unieke_data'])
    )
    db3.session.add(new_alert)
    db3.session.commit()
    db3.session.close()
    return alert

def process_data_logprocessor(hit):
    alert = {}
    alert['application'] = "logprocessor"
    alert['id'] = hit['event_id']
    alert['timestamp'] = datetime.datetime.strptime((hit['date'] + "T" + hit['time'] + "Z"), '%Y-%m-%dT%H:%M:%SZ')
    alert['source_ip'] = hit['source']
    alert['destination_ip'] = hit['destination']
    match = geolite2.lookup(hit['source'])
    if match is not None:
        try:
            if (match.country == 'RU'):
                alert['source_country'] = "Russia"
            elif (match.country == 'KR'):
                alert['source_country'] = "Korea, Republic of"
            elif (match.country == 'PS'):
                alert['source_country'] = "Palestine, State of"
            elif( match.country == 'LU'):
                alert['source_country'] = "Lithuania"
            else:
                try:
                    alert['source_country'] = pycountry.countries.get(
                        alpha_2=match.country).common_name
                except:
                    alert['source_country'] = pycountry.countries.get(
                        alpha_2=match.country).name
        except:
            pass
    else:
        alert['source_country'] = 'None'
    alert['document_type'] = "logprocessor"
    alert['unieke_data'] = unieke_data_sorteren(hit)

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
        source_country=alert['source_country'],
        document_type=alert['document_type'],
        unieke_data=str(alert['unieke_data'])
    )
    db5.session.add(new_alert)
    db5.session.commit()
    db5.session.close()
    return alert

def process_data_palo(hit):
    global database_alerts
    alert = {}
    alert['application'] = "palo alto"
    alert['id'] = hit['message']['sessionid']
    alert['timestamp'] = convert_timezone(hit['message']['timestamp'])
    alert['source_ip'] = hit['message']['source']
    alert['destination_ip'] = hit['message']['dst_ip']
    alert['source_country'] = "None"
    alert['document_type'] = "logprocessor"
    alert['unieke_data'] = hit
    ip_to_add = hit['message']['log_srcip']
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
        source_country=alert['source_country'],
        document_type=alert['document_type'],
        unieke_data=str(alert['unieke_data'])
    )
    db6.session.add(new_alert)
    db6.session.commit()
    db6.session.close()
    return alert

def convert_timezone_logprocessor(time):
    tijd = time
    convert_time = datetime.datetime.strptime(tijd, '%Y-%m-%dT%H:%M:%SZ')
    local_timezone = tzlocal.get_localzone() #Haal locale tijdzone op
    convert = convert_time.replace(tzinfo=pytz.utc).astimezone(local_timezone)
    converted = convert.replace(tzinfo=None) #Verwijder +02:00 aan date format
    return converted

def convert_timezone(time):
    tijd = time
    convert_time = datetime.datetime.strptime(tijd, '%Y-%m-%dT%H:%M:%S.%fZ')
    local_timezone = tzlocal.get_localzone() #Haal locale tijdzone op
    convert = convert_time.replace(tzinfo=pytz.utc).astimezone(local_timezone)
    converted = convert.replace(tzinfo=None) #Verwijder +02:00 aan date format
    return converted

def send_abuse_email(alert):
    global send_abuse_list
    try:
        ip = alert['source_ip']
        if not ip in send_abuse_list:
            print(send_abuse_list)
            send_abuse_list.append(ip)
            country = alert['source_country']
            tijd = alert['timestamp']
            timestamp = tijd.strftime("%m/%d/%Y, %H:%M:%S")
            destination = alert['destination_ip']
            r = requests.get(
                'https://stat.ripe.net/data/abuse-contact-finder/data.json?resource=' + ip,
                headers={'accept': 'application/json'}, allow_redirects=True)
            message_abuse = r.json()
            # abuse_mail = message_abuse['data']['anti_abuse_contacts']['abuse_c'][0]['email']
            abuse_mail = 'yannick.soepnel@true.nl'
            subject = "Abuse alert - TRUE"
            text = 'Dear,\n \n' \
                   '' \
                   'We at True care for our security. Our security alert has received alerts regarding one specific IP-address. This email is being sent to report abuse. The full alert is as following:\n \n' \
                   'IP-address: ' + ip + '\n'+ \
                   'Destination IP: ' + destination + '\n' + \
                   'Country: ' + country + '\n'+\
                   'Timestamp: ' + timestamp + '\n'+\
                   '\n \n If you would like to receive more information please contact us at security@true.nl'
            message = 'Subject: {}\n\n{}'.format(subject, text)
            server.sendmail('yannick.soepnel@true.nl', abuse_mail, message)
        else:
            pass
    except:
        pass

def send_alert(alert):
    global send_alert_list
    myTeamsMessage = pymsteams.connectorcard("https://outlook.office.com/webhook/70680fab-f393-4f6e-bf4a-02d5166ad298@fcea803c-cd1f-45a6-8e44-11b1d7165ccc/IncomingWebhook/46e03e0ef6fe4d738d4e9b5c88474eb8/d373d754-fdb2-4e8a-b96a-01806c6e2e2a")
    ip = alert['source_ip']
    if not ip in send_alert_list:
        print(send_alert_list)
        send_alert_list.append(ip)
        country = alert['source_country']
        tijd = alert['timestamp']
        timestamp = tijd.strftime("%m/%d/%Y, %H:%M:%S")
        applicatie = alert['application']
        id = alert['id']
        myTeamsMessage.text("<pre>Melding Sauron: <br>"
                            "IP-adres: " + ip + '<br>'+
                            "Land: " + country + '<br>'+
                            "Tijd: " + timestamp + '<br>' +
                            "ID: " + id + '<br>' +
                            "Applicatie: " + applicatie
                            )
        myTeamsMessage.send()
    else:
        pass

# Create two threads as follows
try:
    _thread.start_new_thread( get_honeypot_data, ())
    _thread.start_new_thread( get_duckhunt_data, ())
    _thread.start_new_thread( rekenwerk, ())
    # _thread.start_new_thread( get_palo_data, ())
    _thread.start_new_thread( get_logprocessor_data, ())
except:
   print("Error: unable to start thread")

@app.route("/")
def index():
    return render_template('visualise.html', sorted_histogram = sorted_histogram,values=data_visualise, labels=labels_visualise, verwerkt_ip=verwerkt_ip, verwerkt_landen=verwerkt_landen, histogram=histogram, sorted_d_verwerkt_ip = sorted_d_verwerkt_ip, host_grade=host_grade, sorted_d_verwerkt_land=sorted_d_verwerkt_land)

@app.route('/log', methods=["GET", "POST"])
def log():
    return render_template('log.html', host_grade_log=sorted_d_host_grade_log)

@app.route('/meldingen', methods=["GET", "POST"])
def alert():
    return render_template('meldingen.html', host_grade_alert=sorted_d_host_grade_alert)

@app.route('/ban', methods=["GET", "POST"])
def ban():
    return render_template('ban.html', host_grade_ban=sorted_d_host_grade_ban)

@app.route('/combined', methods=["GET", "POST"])
def combined():
    global tijd1
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
    return render_template('combined.html', alert_list=gecombineerd, title='combined', tijd1=tijd1)

@app.route('/settings', methods=["GET", "POST"])
def settings():
    try:
        database_rules = rules_db.query.order_by(rules_db.count.desc()).all()
        if request.method == "POST":
            for land in database_landen:
                form = request.form[land.name]
                if (form == ''):
                    land.score = land.score
                else:
                    land.score = int(form)
                sql = """UPDATE landen_db SET score = %s WHERE name = %s"""
                data = (land.score, land.name)
                db4.engine.execute(sql, data)
            for frequentie in database_frequenties:
                if(frequentie.name == "Eerste frequentie" or frequentie.name == "Tweede frequentie"):
                    form = request.form[frequentie.name]
                    form_value1 = str(request.form["a" + frequentie.name])
                    form_value2 = str(request.form["b" + frequentie.name])
                    if (form == ''):
                        frequentie.score = frequentie.score
                    else:
                        frequentie.score = int(form)
                    if (form_value1 == ''):
                        frequentie.value1 = frequentie.value1
                    else:
                        frequentie.value1 = int(form_value1)
                    if (form_value2 == ''):
                        frequentie.value2 = frequentie.value2
                    else:
                        frequentie.value2 = int(form_value2)
                    sql = """UPDATE frequenties_db SET score = %s, value1 = %s, value2 = %s WHERE name = %s"""
                    data = (frequentie.score, frequentie.value1, frequentie.value2, frequentie.name)
                    db4.engine.execute(sql, data)
                else:
                    form = request.form[frequentie.name]
                    form_value1 = str(request.form["a" + frequentie.name])
                    if (form == ''):
                        frequentie.score = frequentie.score
                    else:
                        frequentie.score = int(form)
                    if (form_value1 == ''):
                        frequentie.value1 = frequentie.value1
                    else:
                        frequentie.value1 = int(form_value1)
                    sql = """UPDATE frequenties_db SET score = %s, value1 = %s, value2 = %s WHERE name = %s"""
                    data = (frequentie.score, frequentie.value1, frequentie.value2, frequentie.name)
                    db4.engine.execute(sql, data)
            for rule in database_rules:
                form = request.form["a" + str(rule.rule_code)]
                if (form == ''):
                    rule.score = rule.score
                else:
                    rule.score = int(form)
                sql = """UPDATE rules_db SET score = %s WHERE rule_code = %s"""
                data = (rule.score, rule.rule_code)
                db4.engine.execute(sql, data)
            for applicatie in database_applicaties:
                form = request.form[applicatie.name]
                if (form == ''):
                    applicatie.score = applicatie.score
                else:
                    applicatie.score = int(form)
                sql = """UPDATE applicaties_db SET score = %s WHERE name = %s"""
                data = (applicatie.score, applicatie.name)
                db4.engine.execute(sql, data)

            for actie in database_acties:
                if (actie.name == "log" or actie.name == "alert"):
                    form_value1 = request.form[actie.name]
                    form_value2 = str(request.form["a" + str(actie.name)])
                    if(form_value1== ''):
                        actie.score1 = actie.score1
                    else:
                        actie.score1 = int(form_value1)
                    if(form_value2 == ''):
                        actie.score2 = actie.score2
                    else:
                        actie.score2 = int(form_value2)
                    sql = """UPDATE acties_db SET score1 = %s, score2 = %s WHERE name = %s"""
                    data = (actie.score1, actie.score2, actie.name)
                    db4.engine.execute(sql, data)
                else:
                    form_value1 = request.form[actie.name]
                    if (form_value1 == ''):
                        actie.score1 = actie.score1
                    else:
                        actie.score1 = int(form_value1)
                    sql = """UPDATE acties_db SET score1 = %s, score2 = %s WHERE name = %s"""
                    actie.score2 = 1000
                    data = (actie.score1, actie.score2, actie.name)
                    db4.engine.execute(sql, data)
            db4.session.commit()
            db4.session.close()
        # print(form)
        # for k,v in form.items():
        #     for land in database_landen:
        #         if (land.name == k):
        #             land.score = v
        #     sql = """UPDATE landen_db SET score = %s WHERE name = %s"""
        # #     data = (v, k)
        #     db.engine.execute(sql, data)
        #     # db.session.execute(sql, data)
        #     db.session.commit()
            # print(db.engine)
        return render_template('settings.html', title='settings', database_landen=database_landen, database_frequenties=database_frequenties, database_rules=database_rules, database_applicaties=database_applicaties, database_acties=database_acties)
    except:
        return render_template('settings.html', title='settings', database_landen=database_landen,
                               database_frequenties=database_frequenties, database_rules=database_rules,
                               database_applicaties=database_applicaties, database_acties=database_acties)

@app.route('/about', methods=["GET", "POST"])
def about():
    if request.method == "POST":
        form = request.form
        print(form)
        for k,v in form.items():
            for land in database_landen:
                if (land.name == k):
                    land.score = v
            sql = """UPDATE landen_db SET score = %s WHERE name = %s"""
            data = (v, k)
            db3.engine.execute(sql, data)
            # db.session.execute(sql, data)
            db3.session.commit()
            # print(db.engine)
    return(request.form)
    # return render_template('settings.html', title='about')

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
    return render_template('honeypot.html', title='honeypot', alert_list=verwerkt_honeypot, tijd1=tijd1, verwerkt_ip=verwerkt_ip, histogram=histogram)


if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5000, threaded=True,use_reloader=False)
data_set = {
        "_index" : "logstash-2020.05.13",
        "_type" : "doc",
        "_id" : "V33FDXIB16V78q83Cq2Z",
        "_score" : 1.0,
        "_source" : {
          "geoip" : {
            "country_code2" : "BG",
            "timezone" : "Europe/Sofia",
            "latitude" : 42.7,
            "country_name" : "Bulgaria",
            "ip" : "78.128.112.26",
            "country_code3" : "BG",
            "longitude" : 23.3333,
            "continent_code" : "EU",
            "location" : {
              "lon" : 23.3333,
              "lat" : 42.7
            }
          },
          "t-pot_hostname" : "variedreality",
          "@version" : "1",
          "@timestamp" : "2020-05-13T11:21:55.702Z",
          "host" : "ea796d043b47",
          "username" : "null",
          "dest_port" : 5900,
          "session_id" : "8f860748-5934-4e71-832a-94ab34594607",
          "proto" : "vnc",
          "src_ip" : "78.128.112.26",
          "dest_ip" : "87.233.6.250",
          "tags" : [
            "_geoip_lookup_failure"
          ],
          "t-pot_ip_ext" : "87.233.6.250",
          "path" : "/data/heralding/log/auth.csv",
          "auth_id" : "c990e2ad-8d18-4a13-b862-fcc544b76f86",
          "column11" : "{'challenge': '58f73b844ebff3b2067a6e0ca43d0b17', 'response': '999cfb79ffe751dcf82d312a00579e6f'}",
          "message" : """2020-05-13 11:21:55.702076,c990e2ad-8d18-4a13-b862-fcc544b76f86,8f860748-5934-4e71-832a-94ab34594607,78.128.112.26,19706,87.233.6.250,5900,vnc,,,"{'challenge': '58f73b844ebff3b2067a6e0ca43d0b17', 'response': '999cfb79ffe751dcf82d312a00579e6f'}"
""",
          "src_port" : 19706,
          "password" : "null",
          "t-pot_ip_int" : "87.233.6.250",
          "ip_rep" : "known attacker",
          "type" : "Heralding"
        }
      }

unieke_data_honeypot = {}

def unieke_data_sorteren_honeypot(data):
    global unieke_data
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
                                    print(key3)
                                    print(value3)
                                    unieke_data_honeypot[key3] = value3
                        else:
                            unieke_data_honeypot[key2] = value2
                else:
                    print(key1)
                    print(value1)
                    unieke_data_honeypot[key1] = value1
        else:
            print(key)
            print(value)
            unieke_data_honeypot[key] = value

unieke_data_sorteren_honeypot(data_set)

# print(unieke_data_honeypot)

# for key,value in unieke_data_honeypot.items():
#     print("key--------")
#     print(key)
#     print("value----------")
#     print(value)
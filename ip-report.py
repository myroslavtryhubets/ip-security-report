import random
from datetime import datetime
from flask import render_template
import flask, csv, requests, time
report_data = []

def get_key():
    with open('keys.txt') as read_file:
        file_lines = read_file.read().splitlines()
        return random.choice(file_lines)



i = 0
with open('ip-list.csv', newline='\n') as csvfile:
    reader = csv.reader(csvfile, delimiter=',', quotechar='|')
    for row in reader:
        
        i += 1
        print(i, row[0])
        response = requests.get(
            'https://www.virustotal.com/api/v3/ip_addresses/'+row[0],
            headers={
                'x-apikey': get_key()},
        )

        json_response = response.json()
        json_data = json_response["data"]["attributes"]

        try:
            last_modification_date = datetime.fromtimestamp(
                json_data["last_modification_date"]).strftime('%Y-%m-%d %H:%M:%S')
        except:
            last_modification_date = datetime.fromtimestamp(1).strftime('%Y-%m-%d %H:%M:%S')

        api_response = {
            "id": i,
            "ip": json_response["data"]["id"],
            "reputation": json_data["reputation"],
            "country": json_data["country"],
            "harmless": json_data["last_analysis_stats"]["harmless"],
            "malicious": json_data["last_analysis_stats"]["malicious"],
            "suspicious": json_data["last_analysis_stats"]["suspicious"],
            "undetected": json_data["last_analysis_stats"]["undetected"],
            "last_modification_date": last_modification_date,
            "link": "https://www.virustotal.com/gui/ip-address/"+json_response["data"]["id"]+"/detection"
        }

        report_data.append(api_response)
        print(api_response)
        print()
        time.sleep(10)

#print(a_list)


now = datetime.now()
dt_string = now.strftime("%Y-%m-%d %H-%M-%S")
app = flask.Flask('ip-security-report')

with app.app_context():
    rendered = render_template('report-v2.html',
                                title="My Generated Page",
                                data=report_data)
    with open('report-'+dt_string+'.html', 'w') as file:
        file.write(rendered)

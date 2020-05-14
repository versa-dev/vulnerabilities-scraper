import pandas as pd
from urllib.request import urlopen
from bs4 import BeautifulSoup
from datetime import datetime
import json

# input the target url
ORIGIN_URL = input('Please enter the URL!')

cves = [] 

first_page = urlopen(ORIGIN_URL)
bsObj = BeautifulSoup(first_page.read())
vulnerability_details = bsObj.findAll('div', {'class': 'table parbase section'})[3]

timestamp = datetime.now().strftime('%Y-%m-%dT%H:%mZ')
name = bsObj.find('div', {'class': 'page-description'}).text.replace('\t','').replace('\n','')
url = ORIGIN_URL
published_date = bsObj.find('div',{'class':'table parbase section'}).findAll('td')[4].text.replace('\xa0','')


if(vulnerability_details.text.find('Affected Versions') == -1):  # the first case
    cpe_list = []
    affected_versions = bsObj.findAll('div', {'class': 'table parbase section'})[1].findAll('tr')
    for ind in range(1, len(affected_versions)):
        version = affected_versions[ind].findAll('td')[1].text.split(' ')[0]
        dict = {'vendor':'magento', 'product':'magento', 'category':'a', 'versionEndIncluding':version}
        cpe_list.append(dict)
        
    cpes = {'cpe_list':cpe_list}
    for ind in range(1, len(vulnerability_details)):
        ID = vulnerability_details.findAll('tr')[ind].findAll('td')[4].text.replace('\xa0', '').replace('\n','')
        description = vulnerability_details.findAll('tr')[ind].findAll('td')[0].text.replace('\xa0', '').replace('\n','')
        dict = {'timestamp':timestamp, 'published_date':published_date, 'id':ID, 'url':url, 'name':name, 'description':description, 'cpes':cpes}
        cves.append(dict)
    print(cves)
else:       # the second case
    for ind in range(1, len(vulnerability_details)):
        cpe_list = []
        ID = vulnerability_details.findAll('tr')[ind].findAll('td')[3].text.replace('\xa0', '').replace('\n','')
        description = vulnerability_details.findAll('tr')[ind].findAll('td')[0].text.replace('\xa0', '').replace('\n','')
        versions = vulnerability_details.findAll('tr')[ind].findAll('td')[4]
        if len(versions.findAll('p')) > 0:
            versionStartIncluding = versions.findAll('p')[0].text
            versionEndIncluding = versions.findAll('p')[-1].text
        else:
            versionStartIncluding = versions.text
            versionEndIncluding = versions.text
        dict = {'vendor':'adobe', 'product':'exprience_manager', 'category':'a', 'versionStartIncluding':versionStartIncluding, 'versionEndIncluding': versionEndIncluding}
        cpe_list.append(dict)
        cpes = {'cpe_list':cpe_list}
        dict = {'timestamp':timestamp, 'published_date':published_date, 'id':ID, 'url':url, 'name':name, 'description':description, 'cpes':cpes}
        cves.append(dict)

dict = {'source': 'adobe', 'type': 'vendor', 'cves': cves}
result = json.dumps(dict)

# write the json to the file
with open("sample.json", "w") as outfile: 
    outfile.write(result) 

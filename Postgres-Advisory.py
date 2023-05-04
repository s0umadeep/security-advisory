import requests
from bs4 import BeautifulSoup
import json

versions = ['15','14', '13', '12', '11', '10', '9.6', '9.5', '9.4', '9.3', '9.2', '9.1', '9.0', '8.4', '8.3', '8.2', '8.1', '8.0', '7.4', '7.3']
baseurl = 'https://www.postgresql.org/support/security/'

json_data = []

for version in versions:
    url = f'{baseurl}{version}/'
    response = requests.get(url)
    soup = BeautifulSoup(response.content, 'html.parser')
    rows = soup.find('table', {'class': 'table'}).find_all('tr')[1:]
    for row in rows:
        cols = row.find_all('td')
        cve = cols[0].text.strip("\nAnnouncement")
        vulnerable_version = cols[1].text.strip()
        #reference = cols[2].find_all('a')[0].text.strip()
        #summary = cols[2].find_all('a')[1].text.strip()
        if (cols[3].find('a') is not None):
            advisory_link = cols[3].find('a').get('href')

        fix_version = cols[2].text.strip()

        summary = cols[4].text.strip("more details")
        #public_release_date = cols[5].text.strip()
        #description = cols[6].text.strip()
        #files_updated = cols[7].text.strip()
        if(cols[0].find('a') is not None):
            source = baseurl+cols[0].find('a').get('href').strip("/support/security")

        responsesource = requests.get(source)
        sourcesoup = BeautifulSoup(responsesource.content,'html.parser')
        sourcerows = sourcesoup.find('table', {'class': 'table'}).find_all('tr')[1:]
        description = sourcesoup.text.replace("\n","")
        for row in sourcerows:
            cols = row.find_all('td')
            if len(cols)>2:
                public_release_date = cols[2].text.strip()
            
        # Create a dictionary to store the data
        data = {
            'Summary': summary,
            'Description': description,
            'CVE': cve,
            'Advisory link': advisory_link,
            'Source': source,
            'PublicReleaseDate': public_release_date,
            'Vulnerable version': vulnerable_version,
            'Files_updated': fix_version
        }

        json_data.append(data)
        print(data)
        print("-----------------------------------------------------")
        
with open('Postgres-Advisory.json','w') as pf:
    pf.write(json.dumps(json_data, indent = 4))

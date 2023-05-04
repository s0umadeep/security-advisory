import os
import requests
from bs4 import BeautifulSoup
import json

# define the URL to scrape
url = 'https://python-security.readthedocs.io/vulnerabilities.html'
url_vuln = 'https://python-security.readthedocs.io/'
nvd_base = 'https://nvd.nist.gov/vuln/detail/'

# make a GET request to the URL and create a BeautifulSoup object
response = requests.get(url)
soup = BeautifulSoup(response.text, 'html.parser')

# find all the folders within the URL
rows = soup.find('table', {'class': 'docutils'}).find_all('tr')[1:]

# loop through each folder and check for .yaml files
yaml_data = []

for row in rows:
        cols = row.find_all('td')
        summary = cols[0].text.strip()
        public_release_date = cols[1].text.strip()
        fix_version = cols[2].text.strip()
        vulnerable_version = cols[3].text.strip()
        cve = cols[4].text.split()
        if (cols[3].find('a') is not None):
            advisory_link = cols[3].find('a').get('href')

        if(cols[0].find('a') is not None):
            advisory_link = url_vuln + cols[0].find('a').get('href')


        
        # Create a dictionary to store the data
        data = {
            'Summary': summary,
#            'Description': description,
            'CVEs': {},
            'Advisory link': advisory_link,
#            'Source': source,
            'PublicReleaseDate': public_release_date,
            'Vulnerable version': vulnerable_version,
            'Files_updated': fix_version,
        }

        for indx in cve:
            if "CVE-" in indx:
                source = nvd_base+indx
                print(source)
                
                responsesource = requests.get(source)
                sourcesoup = BeautifulSoup(responsesource.content,'html.parser')
                sourcerows = sourcesoup.find('p', {'data-testid': 'vuln-description'})
                description = sourcerows.text
                indxdict = {
                    "Description": description,
                    "Source": source
                }
                data["CVEs"][indx] = indxdict

        yaml_data.append(data)
        print(data)
        print("-----------------------------------------------------")

# write the yaml_data to a json file
with open('Python-Advisory.json','w') as pf:
    pf.write(json.dumps(yaml_data, indent = 4))

import requests
from bs4 import BeautifulSoup
import re, json

def get_advisories_nginx():
    # Base URL for nginx advisory
    url = 'http://nginx.org/en/security_advisories.html'
    response = requests.get(url)
    soup = BeautifulSoup(response.content, 'html.parser')

    advisories = []
    for li in soup.find('ul').find_all('li'):
        advisory = {}
        #################### Title/Summary ####################
        title_tag = li.find('p')
        if title_tag:
            title_parts = title_tag.text.split('<br>', 1)
            if title_parts:
                advisory['title'] = title_parts[0].split('Severity:')[0]
                print(advisory['title'])
        #################### Title/Summary ####################

        #################### Severity Start ####################
        try:
            severity_tag = li.find('b').text
            if severity_tag:
                advisory['severity'] = severity_tag.split(':', 1)[-1].strip()
        except:
            severity_tag = li.find(string=re.compile(r'Severity:'))
            if severity_tag:
                advisory['severity'] = severity_tag.split(':', 1)[-1].strip()
        #################### Severity ####################

        #################### CVE ####################
        cve_tag = li.find('a', href=re.compile(r'^http://cve.mitre.org'))
        if cve_tag:
            advisory['cve_name'] = cve_tag.text
        #################### CVE ####################

        #################### Affected Versions ####################
        affected_versions = li.find(string=re.compile(r'Vulnerable:'))
        if affected_versions:
            advisory['affected_versions'] = affected_versions.split(':', 1)[-1].strip()
        #################### Affected Versions ####################

        #################### Fix Versions ####################
        fix_versions = li.find(string=re.compile(r'Not vulnerable:'))
        if fix_versions:
            advisory['fix_versions'] = fix_versions.split(':', 1)[-1].strip()
        #################### Fix Versions ####################

        #################### Description and Date ####################
        advisory_tag = li.find('a', href=re.compile(r'^http://mailman.nginx.org'))
        if advisory_tag:
            advisory['advisory_link'] = advisory_tag['href']
            # print(advisory['advisory_link'])
            advisory.update(get_advisory_details_nginx(advisory['advisory_link']))
            # print(advisory.update(get_advisory_details(advisory['advisory_link'])))
        print("----------------------------------------------------------")
        advisories.append(advisory)
        #################### Description and Date ####################

    return advisories

def get_advisory_details_nginx(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.content, 'html.parser')

    details = {}

    #################### Publish Date ####################
    publish_date = soup.find('i').text
    #print(publish_date)
    details['published_date'] = publish_date
    #################### Publish Date ####################

    #################### Description ####################
    pre_tag = soup.find('pre')
    
    if pre_tag:
        pre_text = pre_tag.text
        description_match = re.search(r'\bHello\b[\s\S]*?(?=The issues affect)', pre_text)
        description_match2 = re.search(r'\bHello\b[\s\S]*?(?=The issue affects)', pre_text)
        description_match3 = re.search(r'\bHello\b[\s\S]*?(?=The problem)', pre_text)
        if description_match == None:
            try:
                details['description'] = description_match2.group(0).strip()[6:-1]
            except:
                try:
                    details['description'] = description_match3.group(0).strip()[6:-1]
                except:
                    details['description'] = f"Unable to parse the description. Please check the advisory link for more information. {url}"
        else:
            # print(description_match.group(0).strip()[6:-1])
            details['description'] = description_match.group(0).strip()[6:-1]

        print(details['description'])
    #################### Description ####################

        return details


# Summary:
# Description:
# CVE:
# Advisory link:
# Source:
# PublicReleaseDate:
# Vulnerable version:
# Files_updated:

if __name__ == '__main__':
    advisories = get_advisories_nginx()
    advisories_final = json.dumps(advisories, indent=2)
    # print(advisories_final)
    with open('nginx_data.json', 'w', encoding='utf-8') as f:
        json.dump(advisories, f, ensure_ascii=False, indent=4)



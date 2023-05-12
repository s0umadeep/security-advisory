
from urllib.request import urlopen
import json



url = "https://www.mongodb.com/api/alerts/all"
  

response = urlopen(url)
  
# Summary:
# Description:
# CVE:
# Advisory link:
# Source:
# PublicReleaseDate:
# Vulnerable version:
# Files_updated:
def get_advisories_mongodb():
    data_json = json.loads(response.read())
    
    output_dict = {}
    advisories = []
    for item in data_json:
        try:
            output_dict['summary'] = item['CVE_data_meta']['TITLE']
        except:
            output_dict['summary'] = "No title"
        
        output_dict['description'] = item['description']['description_data'][0]['value']
        output_dict['cve'] = item['CVE_data_meta']['ID']
        # output_dict['severity'] = item['CVE_data_meta']['TITLE']
        output_dict['release_date'] = item['CVE_data_meta']['DATE_PUBLIC']
        output_dict['affected_product'] = item['affects']['vendor']['vendor_data'][0]['product']['product_data'][0]['product_name']
        output_dict['affected_version'] = f"{item['affects']['vendor']['vendor_data'][0]['product']['product_data'][0]['version']['version_data'][0]['version_value']} and prior"
        # output_dict['files_updated'] = item['CVE_data_meta']['TITLE']
        output_dict['advisory_link'] = item['references']['reference_data'][0]['url']
        advisories.append(output_dict)

    return advisories


if __name__ == '__main__':
    advisories = get_advisories_mongodb()
    with open('mongo_data.json', 'w', encoding='utf-8') as f:
        json.dump(advisories, f, ensure_ascii=False, indent=4)

## A1

from bs4 import BeautifulSoup
import requests
import re
import ipaddress

url = "https://www.secureworks.com/blog/opsec-mistakes-reveal-cobalt-mirage-threat-actors"

# Pull the page for analysis
res = requests.get(url)

# Parse the downloaded html page and through the data in <body>
site = BeautifulSoup(res.content, "html.parser")
content = site.body

# For prevention of duplicate IOCs, a list is used
ioclist=set()

# Checks for content in the body, not yet including the table as the newline character '\n' is a hindrance at this point
# Following for loop captures all IP addresses, domains and email addresses (as \w\d captures all word characters and numbers)
for string in content.strings:
    nonhash = re.findall(r"(?:[\w\d]+\s+(?:@|\.)\s+)+[\w\d]+", string)
    for x in nonhash:
        if '@' in x:
            # Ignore email addresses
            continue
        ioclist.add('.'.join(x.replace('.','').split()).lower())

# Grab the table containing the IOCs
# Note that SHA256 hashes are split across two rows so some sanitising is required
for row in site.find_all('table')[0].tbody.findAll('tr'):
    ioclist.add(''.join(row.findAll('td')[0].text.split()).lower())

# Once duplicates have been removed, we can convert it into a list
ioclist=list(ioclist)

# Data cleaning
# For purposes related to this document, subdomains will be merged into the domains (This is not recommended when there are known domains that are hosting providers, for example azurewebsites etc.)
idxpop = set()
for i in range(len(ioclist)-1):
    for j in range(i+1, len(ioclist)):
        if ioclist[i] in ioclist[j]:
            # if the string i is in j, that means j is the subdomain of i and vice versa
            idxpop.add(j)
        if ioclist[j] in ioclist[i]:
            idxpop.add(i)
for i in idxpop:
    ioclist.pop(i)

# Classify each type of IOC (Enriches data)
# IPv6 is omitted but uses the same library to check
ioc = {}
for i in ioclist:
    try:
        ipaddress.ip_address(i)
        ioc[(len(ioc))]={"Type":"IPv4", "Value":i}
        continue
    except ValueError:
        pass
    j = re.findall(r"^[0-9a-f]{32}$",i)
    if i in j:
        ioc[(len(ioc))]={"Type":"MD5", "Value":i}
        continue
    j = re.findall(r"[0-9a-f]{40}",i)
    if i in j:
        ioc[(len(ioc))]={"Type":"SHA1", "Value":i}
        continue
    j = re.findall(r"[0-9a-f]{64}",i)
    if i in j:
        ioc[(len(ioc))]={"Type":"SHA256", "Value":i}
        continue
    ioc[(len(ioc))]={"Type":"Domain", "Value":i}

## A2

import whois
import pandas as pd
from datetime import datetime

whoisdata = {}

for i in range(len(ioc)):
    if ioc[i]["Type"] == 'Domain':
        x=whois.whois(ioc[i]['Value'])
        
        # This line is here because domains that are not owned will appear as 'None' in the results
        x['domain_name'] = ioc[i]['Value']
        
        # This line checks for all datetime values and converts them into MM/DD/YY HH:MM:SS format
        for j in x.keys():
            if 'date' in j:
                # Check if the field is populated, and whether it has only 1 timestamp or has multiple in a list
                if x[j] == None:
                    continue
                elif type(x[j])==type(datetime.now()):
                    x[j]=x[j].strftime("%d/%m/%Y, %H:%M:%S")
                elif len(x[j])>1:
                    for k in range(len(x[j])):
                        x[j][k]=x[j][k].strftime("%d/%m/%Y, %H:%M:%S")
        
        # Preserve original data (ioc) in the event of future use
        ioc[i]["Data"]=x
        whoisdata[len(whoisdata)]=x
        
        # No further processing of information as the result is not standardised (varies by registrar), and over-cleaning of data may result in loss of data fidelity

# Write the dict into CSV via pandas, which will give us a union of headers
pd.DataFrame.from_dict(whoisdata, orient='index').to_csv('whois_data.csv', index=False)
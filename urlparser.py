## A1

from bs4 import BeautifulSoup
import requests
import re
import ipaddress

url = "https://www.secureworks.com/blog/opsec-mistakes-reveal-cobalt-mirage-threat-actors"

res = requests.get(url)

site = BeautifulSoup(res.content, "html.parser")

content = site.body

ioclist=set()

# Checks for content in the body, not yet including the table as newlines the regex would not be able to capture newlines '\n'
for string in content.strings:
    # Use https://regex101.com/ to test regex
    # Attempt to find all URLs, IP address (domains) and Hashes in text (not yet considering tables as hashes are in split across lines)

    # Captures all IP addresses, domains and email addresses (as \w\d captures all word characters and numbers)
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

ioclist=list(ioclist)

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
# IPv6 is omitted by uses the same library to check
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

whoisdata = {}

for i in range(len(ioc)):
    if ioc[i]["Type"] == 'Domain':
        x=whois.whois(ioc[i]['Value'])
        ioc[i]["Data"]=x
        whoisdata[len(whoisdata)]=x

pd.DataFrame.from_dict(whoisdata, orient='index')
print(ioc)
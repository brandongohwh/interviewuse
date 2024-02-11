from bs4 import BeautifulSoup
import requests
import re

url = "https://www.secureworks.com/blog/opsec-mistakes-reveal-cobalt-mirage-threat-actors"

res = requests.get(url)

site = BeautifulSoup(res.content, "html.parser")

content = site.body
for string in content.strings:
    # Use https://regex101.com/ to test regex
    # Attempt to find all URLs, IP address and Hashes in text (not yet considering tables as hashes are in split across lines)
    ip = re.findall(r"(\s?[0-9]{1,3}\s?\.){3}\s?[0-9]{1,3}")
    domain = re.findall(r"[\w\d]+\s?\.\s?[\w\d]+") # Regex for domains (subdomains not yet considered)
    
    
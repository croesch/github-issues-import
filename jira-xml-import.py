#!/usr/bin/env python3

import xml.etree.ElementTree as ET

tree = ET.parse('SearchRequest.xml')
root = tree.getroot()

channel = root.find('channel')
for issue in channel.iter('item'):
    thetitle = issue.find('title')
    print (thetitle.text)

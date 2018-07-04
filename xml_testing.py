import xml.etree.ElementTree as ET
from lxml import etree
b='<?xml version="1.0"?><data><main>aa</main></data>'
e =ET.fromstring(b)
for elt in e.iter():
    elt.text="1"
    print elt.tag,elt.text
a=ET.tostring(e, encoding='utf8', method='xml')
print(a)
# tree = ET.parse('1.xml')
# root = tree.getroot()
# country=root.findall('./')
# for i in country:
# 	rank=i.findall("./")
# 	print(rank[0].text)
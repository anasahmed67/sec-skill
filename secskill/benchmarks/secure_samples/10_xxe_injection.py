import defusedxml.ElementTree as ET
def parse_xml(data):
    return ET.fromstring(data)

"""Expose failed test details in reviewable CI annotations without retaining endpoint evidence."""

import sys
from pathlib import Path
import xml.etree.ElementTree as ET

path = Path(sys.argv[1])
if path.exists():
    for testcase in ET.parse(path).iter("testcase"):
        for failure in list(testcase.findall("failure")) + list(testcase.findall("error")):
            text = (
                testcase.attrib.get("name", "test")
                + ": "
                + (failure.text or failure.attrib.get("message", ""))
            )[:6000]
            text = text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
            print("::error::" + text)

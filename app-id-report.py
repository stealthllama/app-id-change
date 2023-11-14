#!/usr/bin/env python3

# Copyright (c) 2023, Palo Alto Networks
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

import os
import requests
from urllib3.exceptions import InsecureRequestWarning
import argparse
from dotenv import load_dotenv, find_dotenv
import xml.etree.ElementTree as ET

REPORTXML = 'report.xml'
REPORTNAME = 'Impacted Rules and Apps'

def get_arguments():
    parser = argparse.ArgumentParser(
        prog="app-id-report.py",
        description="Create a report that summarizes app-id-change events"
    )
    parser.add_argument('panorama', help='The IP or FQDN of the Panorama instance')
    parser.add_argument('-d', '--devicegroup', help='The name of the Panorama Device Group')
    args = parser.parse_args()
    return args


def get_xml_string(xml_file):
    # Read the XML templates are convert to a string
    with open(xml_file, 'r') as f:
        xml_string = f.read().replace('\t', '').replace('\n', '')
        return xml_string


def add_report(panorama, devicegroup, xml_body, creds):
    element = str(xml_body).replace('\t', '').replace('\n', '')
    if devicegroup is None:
        base_path = "/config/shared/reports"
    else:
        base_path = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='{}']/reports".format(devicegroup)
    xpath = base_path + "/entry[@name='{}']".format(REPORTNAME)
    params = [
        ('type','config'),
        ('action','set'),
        ('xpath', xpath),
        ('element', element)
    ]
    response = requests.get('https://' + panorama + ':443/api', params=params, auth=creds, verify=False)
    return response


def main():
    # Suppress certificate warnings
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
    # Process command line arguments
    args = get_arguments()
    # Load any environment files
    load_dotenv()
    creds = requests.auth.HTTPBasicAuth(
        os.getenv('PANORAMA_USERNAME'),
        os.getenv('PANORAMA_PASSWORD')
    )
    # Create a new report
    print("Adding {} ... ".format(REPORTNAME), end="")
    new_report = get_xml_string(REPORTXML)
    result = add_report(args.panorama, args.devicegroup, new_report, creds)
    xml_result = ET.fromstring(result.text)
    print(xml_result.find('./msg').text)


if __name__ == "__main__":
    main()

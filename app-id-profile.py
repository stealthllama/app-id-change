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
import sys
import requests
from urllib3.exceptions import InsecureRequestWarning
import argparse
from dotenv import load_dotenv, find_dotenv
import xml.etree.ElementTree as ET

PROFILEXML = 'profile.xml'
RULEXML = 'rule.xml'

def get_arguments():
    parser = argparse.ArgumentParser(
        prog="app-id-profile.py",
        description="Create or update a vulnerability protection profiles to check for app-id-change events"
    )
    parser.add_argument('panorama', help='The IP or FQDN of the Panorama instance')
    parser.add_argument('profile', help='The name of the Vulnerability Protection Profile')
    parser.add_argument('-d', '--devicegroup', help='The name of the Panorama Device Group')
    args = parser.parse_args()
    return args


def get_xml_string(xml_file):
    # Read the XML templates are convert to a string
    with open(xml_file, 'r') as f:
        xml_string = f.read().replace('\t', '').replace('\n', '')
        return xml_string
    

def get_profile(panorama, devicegroup, profilename, creds):
    # Check to see if a profile already exists
    if devicegroup is None:
        xpath = "/config/shared/profiles/vulnerability/entry[@name='{}']".format(profilename)
    else:
        xpath = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='{}']/profiles/vulnerability/entry[@name='{}']".format(devicegroup, profilename)
    params = [
        ('type','config'),
        ('action','get'),
        ('xpath', xpath)
    ]
    response = requests.get('https://' + panorama + ':443/api', params=params, auth=creds, verify=False)
    result = ET.fromstring(response.text)
    if (result.attrib['status'] == 'success') and ('count' in result.find('result').attrib):
        if result.find('./result').attrib['count'] == '1':
            return True
    return False


def update_config(panorama, devicegroup, name, xml_body, existing_profile, creds):
    element = str(xml_body).replace('\t', '').replace('\n', '')
    if devicegroup is None:
        base_path = "/config/shared/profiles/vulnerability"
    else:
        base_path = "/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='{}']/profiles/vulnerability".format(devicegroup)
    if existing_profile is True:    
        xpath = base_path + "/entry[@name='{}']/rules".format(name)
    elif existing_profile is False:
        xpath = base_path + "/entry[@name='{}']".format(name)
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
    # Check if the profile exists
    existing_profile = get_profile(args.panorama, args.devicegroup, args.profile, creds)
    if existing_profile is True:
        # Update an existing vulnerability protection profile
        print("Updating {}".format(args.profile), end="")
        new_rule = get_xml_string(RULEXML)
        result = update_config(args.panorama, args.devicegroup, args.profile, new_rule, existing_profile, creds)
    elif existing_profile is False:
        # Create a new vulnerability protection profile
        print("Adding {}".format(args.profile), end="")
        new_profile = get_xml_string(PROFILEXML)
        result = update_config(args.panorama, args.devicegroup, args.profile, new_profile, existing_profile, creds)
    xml_result = ET.fromstring(result.text)
    print(xml_result.find('./msg').text)


if __name__ == "__main__":
    main()

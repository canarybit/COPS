#!/usr/bin/env python3

import logging
import re
import json
import requests
import subprocess
import sys
import os

def convert_to_json(filename,output):
    with open(filename) as file, open(output, 'w') as json_file:
         items = []
         d = {}
         content = file.readlines()
         # Add the type of report to json
         key = "Type"
         value = "AMD-SEV"
         d[key.strip()] = value.strip()
         for index in range( len(content)):
             if ":" not in content[index]:
                continue
             else:
                key, sep, value = content[index].partition(': ')
                # Handle signature which is different from others
                if "Signature:" in key:
                 key = "Signature-R"
                 value_1 = content[index+2]
                 value_2 = content[index+3]
                 value = value_1.strip() + value_2.strip()
                 d[key.strip()] = value.strip()
                 key = "Signature-S"
                 value_1 = content[index+5]
                 value_2 = content[index+6]
                 value = value_1.strip() + value_2.strip()
                 d[key.strip()] = value.strip()
                 break
                # Remove special characters from key
                if ":" in key:
                 key = key.replace(":","")
                if "-" in key:
                 key = key.replace("-","")
                # Handle the values which are not in the same line with key
                if not value:
                   value_1 = content[index+1]
                   value_2 = content[index+2]
                   # Handle the values which are in two separate lines
                   if ":" not in value_2:
                       value = value_1.strip() + value_2.strip()
                   else:
                       value = value_1
                d[key.strip()] = value.strip()
         items.append(d)
         json.dump(items, json_file)




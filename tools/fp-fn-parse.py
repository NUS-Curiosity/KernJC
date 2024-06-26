#!/usr/bin/env python

import sys
from pprint import pprint
import re

if len(sys.argv) != 3:
    print(f"Usage: {sys.argv[0]} <input_file> [FP|FN]")
    sys.exit(-1)

f = open(sys.argv[1], 'r')
content = f.read().split('\n')
f.close()

current_cve = None

res = dict()

for idx, line in enumerate(content):
    if "CVE-" in line:
        # get CVE id with regex
        current_cve = re.findall(r'CVE-\d{4}-\d{4,7}', line)[0]
        continue
    if sys.argv[2].upper() == "FP" and "FP" in line:
        if current_cve not in res:
            res[current_cve] = list()
        version = line.split('FP:')[-1].strip().split(' ')[0]
        commit = line.split('FP:')[-1].strip().split(' ')[-1]
        res[current_cve].append(' '.join([version, commit]))
        continue
    if sys.argv[2].upper() == "FN" and "FN" in line:
        if current_cve not in res:
            res[current_cve] = list()
        version = line.split('FN:')[-1].strip().split(' ')[0]
        commit = line.split('FN:')[-1].strip().split(' ')[-1]
        res[current_cve].append(' '.join([version, commit]))
        continue

for cve, info in res.items():
    print(cve)
    for item in info:
        print(item)

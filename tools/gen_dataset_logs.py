#!/usr/bin/env python

# read ../db/vuln_desc/items.yaml and get the dict of CVEs (filter out the ones without patch commits)
# for each CVE, run the following command:
# ./kjc query CVE-ID --list-cfg

import os
import yaml

def get_cves():
    cves = []
    with open('../db/vuln_desc/items.yaml', 'r') as f:
        # load safely
        items = yaml.safe_load(f)
        for item in items:
            if item['patch']:
                cves.append(item['cve'])
    return cves


if __name__ == '__main__':
    cves = get_cves()
    # sort cves by CVE-ID (reverse order)
    cves.sort(reverse=True)
    print("Total number of CVEs: {}".format(len(cves)))
    # change dir to ../
    os.chdir('../')
    for i, cve in enumerate(cves):
        # print current process
        print(f"Processing {i+1}/{len(cves)}: {cve}")
        os.system(f'./kjc query {cve} --list-cfg')

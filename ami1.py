#-*-coding:utf-8-*-
import boto3
import json
import csv

import urllib3
import requests
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
urllib3.disable_warnings()

session = boto3.Session()

def find_group():
    f = open('group.csv','w',encoding='utf-8',newline='')
    wr = csv.writer(f)

    iam = session.client('iam',verify=False)

    groupdetaillist = iam.get_account_authorization_details(Filter=['Group'])

    wr.writerow(["User Name","Group/Policy","Group/Policy Name"])
    for group in  groupdetaillist["GroupDetailList"]:
        vargroup = group["GroupName"]
        varpolicies = group['AttachedManagedPolicies']
        for policy in varpolicies:
            varpolicyname = policy["PolicyName"]
            wr.writerow([vargroup,"Managed Policy", policy['PolicyName']])

        varinlinelist = group["GroupPolicyList"]
        for inline in varinlinelist:
            wr.writerow([vargroup,"Inline Policy",inline['PolicyName']])
    f.close()

if __name__ == '__main__':
    find_group()
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

def find_user():
    f = open('policy.csv','w',encoding='utf-8',newline='')
    wr = csv.writer(f)

    iam = session.client('iam',verify=False)

    iamdetaillist = iam.get_account_authorization_details(Filter=['User'])

    wr.writerow(["User Name","Group/Policy","Group/Policy Name"])
    for user in  iamdetaillist["UserDetailList"]:
        varname = user["UserName"]
        varinlinelist = user["AttachedManagedPolicies"]
        for inline in varinlinelist:
            varpolicyname = inline["PolicyName"]
            wr.writerow([varname,"Inline Policy", varpolicyname])
        vargrouplist = user["GroupList"]
        for group in vargrouplist:
            wr.writerow([varname,"Groups",group])
    f.close()

if __name__ == '__main__':
    find_user()
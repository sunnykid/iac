#-*-coding:utf-8-*-
import boto3
import json
import csv

import urllib3
import requests
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
urllib3.disable_warnings()

session = boto3.session.Session()

def Cloudtrail_check():
    regions = session.get_available_regions('cloudtrail')

    for region in regions:
        cloudtrail_client = session.client('cloudtrail',region,verify=False)
        try:
            traillist = cloudtrail_client.describe_trails()
            for trail in traillist['trailList']:
                varname = trail["Name"]
                varTrailARN = trail["TrailARN"]
                varIsMultiRegionTrail = trail["isMultiRegionTrail"]
                varLoggin = cloudtrail_client.get_trail_status(varTrailARN)
                print("TrailNme:",varname,"Trail ARN:",varTrailARN,"IsMulti Region :",varIsMultiRegionTrail,"IsLogging",varLoggin)
        except Exception as e:
            print(region + "is Inactivated")
if __name__ == '__main__':
    Cloudtrail_check()
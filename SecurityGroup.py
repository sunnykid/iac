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

def get_securitygroup():
    cidr_block = ""  #IP 표기방법
    ip_protpcol = "" #TCP, UDP, ICMP 등의 통신 프로토콜
    from_port = ""
    to_port = ""
    from_source = "" #Security Group

    #Security_Group.csv 파일 생성
    f = open('Security_Group.csv','w',encoding='utf-8',newline='')
    wr = csv.writer(f)

    # 커맨드창에 출력
    print("%s,%s,%s,%s,%s,%s,%s" % ("Region","Group-Name","Group-ID","Im/Out","Protocol","Port","Source/Destination"))

    # csv파일에 출력
    wr.writerow(["Region","Group-Name","Group-ID","Im/Out","Protocol","Port","Source/Destination"])

    # EC2서비스가 제공되는 리전 조회
    regions = session.get_available_regions('ec2')

    for region in regions:
        # EC2 Client 요청
        ec2_client = session.client('ec2', region, verify=False)

        try: # EC2 서비스는 제공되지만 미사용 리전인 경우 예외 처리
            vpts = ec2_client.describe_vpcs()

            sgs = ec2_client.describe_security_groups()["SecurityGroups"]

            for sg in sgs:
                group_name = sg['GroupName']
                group_id = sg['GroupId']

                # InBound permissions
                inbound = sg['IpPermissions']

                for rule in inbound:
                    # -1은 가장 마지막 숫자를 의미, Any 정첵으로 판단
                    if rule['IpProtocol'] == "-1":
                        traffic_type = "All Trafic"
                        ip_protpcol = "All"
                        to_port = "All"
                    else:
                        ip_protpcol = rule['IpProtocol']
                        from_port = rule['FromPort']
                        to_port = rule['ToPort']
                        # to_port가 -1이면 ICMP/ICMPv6
                        if to_port == -1:
                            to_port = "N/A"

                    # 32비트 IP, IPv4
                    if len(rule['IpRanges']) > 0:
                        for ip_range in rule['IpRanges']:
                            cidr_block = ip_range['CidrIp']
                            if 'Description' in ip_range.keys():
                                desc = ip_range['Description']
                                wr.writerow([region, group_name, group_id, "Inbound", ip_protpcol, to_port, cidr_block, desc])


                    # 128비트 IP, IPV6
                    if len(rule['Ipv6Ranges']) > 0:
                        for ip_range in rule['Ipv6Ranges']:
                            cidr_block = ip_range['CidrIpv6']
                            if 'Description' in ip_range.keys():
                                desc = ip_range['Description']
                                wr.writerow([region, group_name, group_id, "Inbound", ip_protpcol, to_port, cidr_block, desc])


                    # Is source/target a security group?
                    if len(rule['UserIdGroupPairs']) > 0:
                        for source in rule['UserIdGroupPairs']:
                            from_source = source['GroupId']
                            wr.writerow([region, group_name, group_id, "Inbound", ip_protpcol, to_port, from_source])


                    # OutBound permissions
                    outbound = sg['IpPermissionsEgress']
                    for rule in outbound:
                        if rule['IpProtocol'] == "-1":
                            traffic_type = "All Traffic"
                            ip_protpcol = "All"
                            to_port = "All"
                        else:
                            ip_protpcol = rule['IpProtocol']
                            from_port = rule['FromPort']
                            to_port = rule['ToPort']
                            #If ICMP, report "N/A" for port #
                            if to_port == -1:
                                to_port = "N/A"


                    # Is source/target an IPv4?
                    if len(rule['IpRanges']) > 0:
                        for ip_range in rule['IpRanges']:
                            cidr_block = ip_range['CidrIp']
                            if 'Description' in ip_range.keys():
                                desc = ip_range['Description']
                                wr.writerow([region, group_name, group_id, "Outbound", ip_protpcol, to_port, cidr_block, desc])


                    # Is source/target an IPv6?
                    if len(rule['Ipv6Ranges']) > 0:
                        for ip_range in rule['Ipv6Ranges']:
                            cidr_block = ip_range['CidrIpv6']
                            if 'Description' in ip_range.keys():
                                desc = ip_range['Description']
                                wr.writerow([region, group_name, group_id, "Outbound", ip_protpcol, to_port, cidr_block, desc])


                    # Is source/target a security group?
                    if len(rule['UserIdGroupPairs']) > 0:
                        for source in rule['UserIdGroupPairs']:
                            from_source = source['GroupId']
                            wr.writerow([region, group_name, group_id, "Outbound", ip_protpcol, to_port, from_source])


        except Exception as e:
            print(region + "is Inactivated")  # 리전이 비활성화된 경우 Inactivated라고 출력

    f.close()

if __name__ == '__main__':
    get_securitygroup()
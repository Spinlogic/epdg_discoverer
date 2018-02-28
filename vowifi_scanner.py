#!/usr/bin/env python

# The MIT License (MIT)

# Copyright (c) 2018 Spinlogic S.L., Albacete, Spain

# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in 
# the Software without restriction, including without limitation the rights to 
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies 
# of the Software, and to permit persons to whom the Software is furnished to do 
# so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all 
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, 
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE 
# SOFTWARE.


#################################################################
#
# Module : vowifi_scanner.py
# Author : Juan Noguera
# Purpose: This script goes through the list of operators in 
#          file declared as parameter and finds whether there
#          is a DNS entry for the ePDG of each operator.
#          
# Input:  file generated from http://www.imei.info/operator-codes/
#
# Output: csv file with the following columns:
#
#    Country   Operator_Name  FQDN_for_ePDG   Resolved_IP_Address   Responds to ping?   length of response to IKEv2_SA_INIT
#
#   One entry per IP Address resolved. I.e. if the FQDN of an 
#   operator resolves to multiple IP Addresses, then this 
#   operator has multiple consecutive entries.
#
#################################################################

"""Usage: vowifi_scanner <operators_filename> <output_filename>"""

__version__ = '0.2.0'

import argparse, random, dns.resolver
import ikev2.ikev2_class as ikev2
import logging
logging.getLogger("scapy3k.runtime").setLevel(logging.ERROR)
from scapy3k.all import *

# --------------------------// Globals /___________________________
csv_separator = "\t"
  
# def nslookupv4(operator_url):
#   """performs a dns query for the data contained in operator"""
#   try:
#     dns_query_result = socket.gethostbyname(operator_url)
#   except:
#     dns_query_result = "none"
#   return dns_query_result

def nslookup(operator_url):
    """"Performs DNS lookup for A (IPv4) and AAAA (IPv6) records"""
    dnsres = dns.resolver.Resolver()  # create a new instance named 'myResolver'
    records = []
    try:
        ansv4 = dnsres.query(operator_url, "A")
        for record in ansv4:
            records.append(record.address)
        ansv6 = dnsres.query(operator_url, "AAAA")
        for record in ansv6:
            records.append(record.address)
    except:
        pass
    return records


def respondsToPing(address):
    '''Checks if the machine at "address" responds to ICMP Echo requests'''
    responds_to_ping = 'No'
    if(':' in address):
        icmp_sender = sr1(IPv6(dst = address) / ICMPv6EchoRequest(data="HELLO"), timeout = 5, verbose = 0)
    else:
        icmp_sender = sr1(IP(dst = address)/ ICMP() / "HELLO", timeout = 5, verbose = 0)
    if icmp_sender != None:
        responds_to_ping = 'Yes'
    else:
        if icmp_sender != None:
            print(icmp_sender.summary())
    return responds_to_ping


def iterateoperatorsfile(fn_mobileoperators, fn_output):
    """Iterate the operators file checking for ePDG DNS records. If records are found, then check whether the
     entry responds to ICMP ECHO requests.
     The result for each operator is output as lines in fn_output with format:
        MNC \t MCC \t country name \t Operator name \t IPv4v6 address \t Yes/No to question 'responds to ping?'
     fn_output is a csv file with tabs as 'separator'"""
    global csv_separator
    num_lines = 0
    op_file = open(fn_mobileoperators, "r")
    out_file = open(fn_output, "w")
    for line in op_file:
        num_lines +=1
        csv_line = ""
        operator = line.split(csv_separator)
        if len(operator) == 3:
            mcc = operator[0][:3]
            mnc = operator[0][3:].strip()
            operator[2] = operator[2].strip("\n")
            if(len(mnc) < 3):
                if(len(mnc) < 2):
                    mnc = "00" + mnc
                else:
                    mnc = "0" + mnc
            operator_url = "epdg.epc.mnc" + mnc + ".mcc" + mcc + ".pub.3gppnetwork.org"
            dns_query_result = nslookup(operator_url)
            if len(dns_query_result) > 0 :
                for record in dns_query_result:
                    responds_to_ping = respondsToPing(record)
                    if(':' in record): # ikev2 class does not support IPv6
                        sa_resp_length = 0
                    else:
                        ikev2_pack = ikev2.epdg_ikev2(record, random.randrange(50000, 55000), 500)
                        sa_resp_length = ikev2_pack.sa_init()
                    csv_line = mnc + csv_separator + mcc + csv_separator + operator[2] + csv_separator + operator[1] + csv_separator + record + csv_separator + responds_to_ping + csv_separator + str(sa_resp_length)
                    out_file.write(csv_line + "\n")
                    print(csv_line)
            else:
                csv_line = mnc + csv_separator + mcc + csv_separator + operator[2] + csv_separator + operator[1] + csv_separator + 'none' + csv_separator + 'No' + csv_separator + '0'
                out_file.write(csv_line + "\n")
                print(csv_line)
    #       if(num_lines > 10): break
    last_line = "Number of operators checked = %d" % num_lines
    out_file.write(last_line)
    op_file.close()
    out_file.close()
  
  
def main(operators_file, out_file):
  iterateoperatorsfile(operators_file, out_file)
  

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('operators_file', type = str, help = 'File with list of operators and their data')
    parser.add_argument('out_file', type = str, help = 'output file (CVS)')
    args = parser.parse_args()
    main(args.operators_file, args.out_file)
#!/usr/bin/env python
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

import argparse, binascii, dns.resolver
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
load_contrib('ikev2')

__author__ = "Juan Noguera"
__date__ = "22-jun-2015"
__lastupdate__ = "16-feb-2018"
__license__ = "GPL"

# --------------------------// Globals /___________________________
csv_separator = "\t"

def RandString(length=10):
    '''Generates a random string of any legth (10 characters by default)'''
    valid_letters='ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    return ''.join((random.choice(valid_letters) for i in range(length)))


def ikelookup(server_address):
    '''Checks whether it is possible to establish SA to a server.'''
    key_exchange = binascii.unhexlify('bb41bb41cfaf34e3b3209672aef1c51b9d52919f1781d0b4cd889d4aafe261688776000c3d9031505aefc0186967eaf5a7663725fb102c59c39b7a70d8d9161c3bd0eb445888b5028ea063ba0ae01f5b3f30808a6b6710dc9bab601e4116157d7f58cf835cb633c64abcb3a5c61c223e9332538bfc9f282cb62d1f00f4ee8802')
    nonce = binascii.unhexlify('8dfcf8384c5c32f1b294c64eab69f98e9d8cf7e7f352971a91ff6777d47dffed')
    nat_detection_source_ip = binascii.unhexlify('e64c81c4152ad83bd6e035009fbb900406be371f')
    nat_detection_destination_ip = binascii.unhexlify('28cd99b9fa1267654b53f60887c9c35bcf67a8ff')
    transform_1 = IKEv2_payload_Transform(next_payload = 'Transform', transform_type = 'Encryption', transform_id = 12, length = 12, key_length = 128) 
    transform_2 = IKEv2_payload_Transform(next_payload = 'Transform', transform_type = 'PRF', transform_id = 2)
    transform_3 = IKEv2_payload_Transform(next_payload = 'Transform', transform_type = 'Integrity', transform_id = 2)
    transform_4 = IKEv2_payload_Transform(next_payload = 'last', transform_type = 'GroupDesc', transform_id = 2)
    if(':' in server_address):
        packet = IPv6(dst = server_address)
    else:
        packet = IP(dst = server_address, proto = 'udp')
    packet = packet /\
           UDP(dport = 500) /\
           IKEv2(init_SPI = RandString(8), next_payload = 'SA', exch_type = 'IKE_SA_INIT', flags='Initiator') /\
           IKEv2_payload_SA(next_payload = 'KE', prop = IKEv2_payload_Proposal(trans_nb = 4, trans = transform_1 / transform_2 / transform_3 / transform_4, )) /\
           IKEv2_payload_KE(next_payload = 'Nonce', group = '1024MODPgr', load = key_exchange) /\
           IKEv2_payload_Nonce(next_payload = 'Notify', load = nonce) /\
           IKEv2_payload_Notify(next_payload = 'Notify', type = 16388, load = nat_detection_source_ip) /\
           IKEv2_payload_Notify(next_payload = 'None', type = 16389, load = nat_detection_destination_ip)
    ans = sr1(packet, timeout = 3, verbose = 0)
    if ans == None:
        return 0
    else:
        return len(ans)
    

  
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
                    sa_resp_length = ikelookup(record)
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
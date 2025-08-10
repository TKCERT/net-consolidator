#!/usr/bin/python3

from netaddr import *
import os
import argparse
import re
from argparse import RawTextHelpFormatter

# Parse command line options
############################
description=r"""

 _   _      _         ____                      _ _     _       _             
| \ | | ___| |_      / ___|___  _ __  ___  ___ | (_) __| | __ _| |_ ___  _ __ 
|  \| |/ _ \ __|____| |   / _ \| '_ \/ __|/ _ \| | |/ _` |/ _` | __/ _ \| '__|
| |\  |  __/ ||_____| |__| (_) | | | \__ \ (_) | | | (_| | (_| | || (_) | |   
|_| \_|\___|\__|     \____\___/|_| |_|___/\___/|_|_|\__,_|\__,_|\__\___/|_|   
                                                                              
                      Merge and subtract IP lists

Manually consolidating, merging or subtracting huge, overlapping IP lists is a difficult task. This tool
provides those functions and processes files with IP ranges. In addition, the tool supports the following features:

* Resulting IP networks are merged in CIDR notation while duplicates are removed
* Accepts the following IP notations: 192.168.1.1/32 | 192.168.1.1 | 192.168.1.1-192.168.1.2

EXAMPLES
--------

Following examples are given for specific scenarios:

* Consolidating of duplicates and hosts in IP lists (e.g. one subnet already includes parts of a different given subnet )
  EXAMPLE: --fileIpAddresses <text_file_with_ip_addresses>

* Perform plausibility checks (e.g. the subnet size should not exceed /20)
  EXAMPLE: --fileIpAddresses <text_file_with_ip_addresses> --plausibilityChecks True --subnetSize 20

* Return the IP address delta of two IP lists (e.g. ip_list_added - ip_list_already_scanned = delta)
  EXAMPLE: --fileIpAddresses <text_file_with_ip_addresses_unscanned> --fileIpSubtracts <text_file_with_ip_addresses_scanned>

* Exclude specific IP addresses from the IP list (e.g. should explicitely not be scanned)
  EXAMPLE: --fileIpAddresses <text_file_with_ip_addresses_main> --fileIpSubtracts <text_file_with_ip_addresses_exclude>

* Split given IP ranges in equally sized slices (e.g. 10 times 500 IP addresses)
  EXAMPLE: --fileIpAddresses <text_file_with_ip_addresses> --splitIpRangeInSlices 10

PARAMETER
---------

"""

parser = argparse.ArgumentParser(description=description, formatter_class=RawTextHelpFormatter)
parser.add_argument('-f', '--fileIpAddresses', help='text file with ip addresses per line (format: 192.168.0.1, 192.168.0.1/24, 192.168.0.1-192.168.0.10)', default='')
parser.add_argument('-s', '--fileIpSubtracts', help='(optional) text file with ip addresses per line to subtract from the fileIpAddresses')
parser.add_argument('-p', '--plausibilityChecks', help='(optional) enable plausibility checks (e.g. subnet size)')
parser.add_argument('-n', '--subnetSize', help='(optional) size of the network in CIDR (e.g. 24 for /24) for plausibility checks')
parser.add_argument('-t', '--splitIpRangeInSlices', help='(optional) split IP networks in equally sized slices (e.g. 10 times 500 IP addresses')
args = parser.parse_args()

# check: parameter fileIpAddresses is a file
if args.fileIpAddresses:
  if not os.path.isfile(args.fileIpAddresses):
    print('[!] "' + args.fileIpAddresses + '" is not a valid file.', True)
  else:
    fileIpAddr = args.fileIpAddresses

  # check: parameter fileIpSubtracts is a file
  if args.fileIpSubtracts:
    if not os.path.isfile(args.fileIpSubtracts):
      print('[!] "' + args.fileIpSubtracts + '" is not a valid file.', True)
    else:
      fileIpSub = args.fileIpSubtracts

# check: parameter fileIpAddresses is mandatory
else:
  print('[!] No "--fileIpAddresses, -f" parameter was provided')
  parser.print_help()
  exit()

# Merge IP ranges so that no duplicates are existing anymore
############################################################
def mergeIpRanges( fileIpAddr ):
    """
    @type  fileIpAddr:	Filename
    @param fileIpAddr:	File with IP addresses
    @rtype:		IPSet()
    @return:		List of merged IP ranges
    """
    ip_list = readIpFile ( fileIpAddr )
    ip_list_merge = cidr_merge(ip_list)
    return ip_list_merge

# Helper function: Read IP addresses from a file (one IP per line)
####################################################################
def readIpFile ( ipFile ):
    """ 
    @type  ipFile:  	Filename
    @param ipFile:  	File with IP addresses
    @rtype:             IPSet()
    @return:            List of IP ranges
    """
    # init return value
    ip_list = IPSet()

    # iterate over each line in the IP address file
    with open( ipFile ) as f:
        content = f.readlines()
        # remove whitespace characters like `\n` at the end of each line
        content = [x.strip() for x in content] 
        for line in content:
            # update the list with fetched ip objects
            ip_list.update(getValidIpObject( line ))
    return ip_list

# Get valid IP based on string patterns
# Format: CIDR (192.168.0.1/24) + Ranges (192.168.1.1-192.168.1.255)
####################################################################
def getValidIpObject( line_with_ip ):
    """ 
    @type  line_with_ip: String
    @param line_with_ip: IP address(es) as a String (e.g. 192.168.0.1-192.168.0.2)
    @rtype:              IPSet()
    @return:             List of IP ranges
    """
    # temporary IPSet for IP objects like IP ranges
    valid_ip_list = IPSet()

    # Regexp definitions for parsing the ip address from a string representation
    # source: https://www.regular-expressions.info/ip.html and modified to ip-ip
    # regexp for case 192.168.0.1/24 | 192.168.0.1/8 | 192.168.0.1
    regexp_ip = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:|/[0-9]{1,2})[ |]*$')
    # regexp for case 192.168.1.1-192.168.1.255
    regexp_ip_range = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)( *)-( *|)(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(|.*)$',re.DOTALL)
    regexp_ip_separate = re.compile(r'(.*)-(.*)',re.DOTALL)

    # Check: normal ip (192.168.1.1/24, 192.168.1.1)
    if regexp_ip.match ( line_with_ip ):
        valid_ip_list.add(IPNetwork(line_with_ip))
    # Check: ip range (192.168.1.1-192.168.1.2)
    elif regexp_ip_range.match( line_with_ip ):
        # returns a dict
        ips = regexp_ip_separate.findall(line_with_ip)
        ip1 = ips[0][0]
        ip2 = ips[0][1]
        # cleanup empty characters
        ip1 = ip1.replace(' ','')
        ip2 = ip2.replace(' ','')
        # append the ip range
        iprange = IPRange(ip1, ip2)
        for ipnetwork in iprange.cidrs():
            valid_ip_list.add(ipnetwork)
    else:
        print("[!] Not a valid IP address in the text file:" + line_with_ip)
        print("[*] Stopping now!")
        exit()
    return valid_ip_list

# Plausibility checks
#####################
def checkIpOnPlausibility( ip ):
    """ 
    @type  ip:      String
    @param ip:      IP address or IP network (e.g. 192.168.0.1/24)
    @rtype:         Boolean
    @return:        If the IP passed the plausibility checks (passed, not passed) 
    """
    # check for parameter subnetsize
    regexp_ip_subnet_check = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:|/([0-9]{1,2}))[ |]*$')
    if args.subnetSize:
        subnetSize = int(args.subnetSize)
    else:
        subnetSize = 22

    subnetRegexGroup = regexp_ip_subnet_check.findall( str(ip) )
    if int(subnetRegexGroup[0]) > subnetSize:
        return True
    else:
        print("[!] IP did not pass the checks for subnet size (>%s): %s" % (subnetSize, ip) )
        return False
    return True

# Subtract IP ranges for delta between IP network A and B
#########################################################
def subtractIpRanges( fileIpAddr, fileIpSub ):
    """ 
    @type  fileIpAddr:  String
    @param fileIpAddr:  Filename of a file with IP addresses
    @type  fileIpSub:   String
    @param fileIpSub:   Filename of a file with IP addresses
    @rtype:             IPSet()
    @return:            List of IP ranges
    """
    # parse the files for IP addresses
    ip_list_unscanned = readIpFile ( fileIpAddr )
    ip_list_scanned = readIpFile ( fileIpSub )	
    # Subtract the ip lists
    ip_list_toscan = ip_list_unscanned - ip_list_scanned
    # Merge the result ip list
    ip_list_toscan_merge = cidr_merge(ip_list_toscan)
    return ip_list_toscan_merge

# Split IP ranges into slices each of the same size
#####################################################
def splitIpRanges( numberOfSlices, ip_list ):
    """ 
    @type  numberOfSlices: String
    @param numberOfSlices: The number of resulting slices of IP ranges
    @type  ip_list:   	   IPSet()
    @param ip_list:        List of IP Networks
    @rtype:                None
    @return:               None
    """
    # number of all IP addresses
    totalCount = 0
    for ip_range in ip_list:
        totalCount = totalCount + ip_range.size
    print("[*] Totalcount:\t", totalCount)

    # slice in equal parts
    slice_size = int(totalCount/int(numberOfSlices))
    print("[*] Slice size:\t", slice_size)

    # iterate over the ip ranges and over each ip
    buffer_size = 0
    bucket = IPSet()
    list_of_slices = []

    for ip_range in ip_list:
        for ip in ip_range:

            # Fill the bucket with single ip addresses - update the buffer size
            bucket.add(ip)
            buffer_size = buffer_size + 1

            # check: slice is full
            if buffer_size == slice_size:
                # save this slice and reset
                buffer_size = 0
                list_of_slices.append(bucket)
                bucket = IPSet()

    # check: save the last slice (e.g. bucket not completely full)
    if buffer_size != 0:
        list_of_slices.append(bucket)
                 
    # print all ip ranges
    for bucket_id in range(0,len(list_of_slices)):
        # init
        bucket = list_of_slices[bucket_id]

        print("\n\n[*] Bucket # ", bucket_id, " - bucket size ", bucket.size)
        for cidr in bucket.iter_cidrs():
            print(cidr)

            

# Main
######

# Case: Substracting IP ranges in file2 from file1
if args.fileIpSubtracts:
  ip_list = subtractIpRanges(fileIpAddr, fileIpSub)

  # Check plausibility
  if args.plausibilityChecks:
    for ip in ip_list:
      if not ( checkIpOnPlausibility( '%s' % ip )): 
        print ("[*] IP list did not pass the plausibility checks ...")
        exit()

  if args.splitIpRangeInSlices:
    splitIpRanges( args.splitIpRangeInSlices, ip_list )

  if not args.splitIpRangeInSlices:
    # Print result list
    for ip in ip_list:
        print('%s' % ip)
  exit()


# Case: Only Merging IP ranges
elif args.fileIpAddresses:
  ip_list = mergeIpRanges(fileIpAddr)

  # Check plausibility
  if args.plausibilityChecks:
    for ip in ip_list:
      if not ( checkIpOnPlausibility( '%s' % ip )): 
        print ("[*] IP list did not pass the plausibility checks ...")
        exit()

  if args.splitIpRangeInSlices:
    splitIpRanges( args.splitIpRangeInSlices, ip_list )

  if not args.splitIpRangeInSlices:
    # Print result list
    for ip in ip_list:
        print('%s' % ip)
  exit()

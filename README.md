# Net-Consolidator: Consolidate, merge and subtract IP lists
Manually consolidating, merging or subtracting huge, overlapping IP lists is a difficult task. This tool
provides those functions and processes files with IP ranges. In addition, the tool supports the following features:

* Resulting IP networks are merged in CIDR notation while duplicates are removed
* Accepts the following IP notations: 192.168.1.1/32 | 192.168.1.1 | 192.168.1.1-192.168.1.2

# Examples
Consolidating of duplicates and hosts in IP lists (e.g. one subnet already includes parts of a different given subnet )

```EXAMPLE: --fileIpAddresses <text_file_with_ip_addresses>```

Perform plausibility checks (e.g. the subnet size should not exceed /20)

```EXAMPLE: --fileIpAddresses <text_file_with_ip_addresses> --plausibilityChecks True --subnetSize 20```

Return the IP address delta of two IP lists (e.g. ip_list_added - ip_list_already_scanned = delta)

```EXAMPLE: --fileIpAddresses <text_file_with_ip_addresses_unscanned> --fileIpSubtracts <text_file_with_ip_addresses_scanned>```

Exclude specific IP addresses from the IP list (e.g. should explicitely not be scanned)

```EXAMPLE: --fileIpAddresses <text_file_with_ip_addresses_main> --fileIpSubtracts <text_file_with_ip_addresses_exclude>```

Split given IP ranges in equally sized slices (e.g. 10 times 500 IP addresses)

```EXAMPLE: --fileIpAddresses <text_file_with_ip_addresses> --splitIpRangeInSlices 10```

Compare IP ranges by identifying matches of IP list A (fileIpAddresses) in IP list B (fileIpSubtracts)

```EXAMPLE: --fileIpAddresses <text_file_with_ip_addresses> --fileIpSubtracts --compareIpRanges True```

# Parameters
```
  -h, --help            show this help message and exit
  -f FILEIPADDRESSES, --fileIpAddresses FILEIPADDRESSES
                        text file with ip addresses per line (format: 192.168.0.1, 192.168.0.1/24, 192.168.0.1-192.168.0.10)
  -s FILEIPSUBTRACTS, --fileIpSubtracts FILEIPSUBTRACTS
                        text file with ip addresses per line to subtract from the fileIpAddresses
  -p PLAUSIBILITYCHECKS, --plausibilityChecks PLAUSIBILITYCHECKS
                        (optional) enable plausibility checks (e.g. subnet size)
  -n SUBNETSIZE, --subnetSize SUBNETSIZE
                        (optional) size of the network in CIDR (e.g. 24 for /24) for plausibility checks
  -t SPLITIPRANGEINSLICES, --splitIpRangeInSlices SPLITIPRANGEINSLICES
                        (optional) split IP networks in equally sized slices (e.g. 10 times 500 IP addresses
  -c COMPAREIPRANGES, --compareIpRanges COMPAREIPRANGES
                        (optional) mode to compare the IP files by identifying matches from flag -f in flag -s
```

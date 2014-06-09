README check_ospf.py
v0.1

usage: check_ospf.py [-h] [--version] [--debug] [-r RID] [-i IP] [-n NUMBER]
                     SNMP_COMMUNITY HOST

Icinga (Nagios) plugin that checks the status of OSPF neighbors. Default
behaviour is that if any OSPF neighbors are detected, the check will return
the OK string. Command line arguments can be passed to match a certain
neighbor Router ID or interface IP to look for. The check returns OK if the
neighbor state is 2WAY or FULL.

positional arguments:
  SNMP_COMMUNITY        the SNMP community string of the remote device
  HOST                  the IP of the remote host you want to check

optional arguments:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  --debug               debug output
  -r RID, --rid RID     OSPF Router ID (only one please)
  -i IP, --ip IP        OSPF neighbor IP (multiple IP's should be separated by
                        a comma)
  -n NUMBER, --number NUMBER
                        Minimum number of OSPF neighbors required (overrides
                        --ip)

Written in Python 3.

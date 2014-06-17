check_ospf.py
=====================
v0.22

usage: check_ospf.py [-h] [--version] [--debug] [-r RID] [-i IP] [-n NUMBER]
                     SNMP_COMMUNITY HOST

Icinga (Nagios) plugin that checks the status of OSPF neighbors on a Cisco IOS
router. The check returns OK if the neighbor state is 2WAY or FULL. Without
any optional arguments, returns OK if any OSPF neighbors are detected.
Optional arguments can be passed to match a specific neighbor Router ID (RID)
or interface IP to look for. In that case a CRITICAL will be generated if that
specific neighbor is down. In case multiple IP's or RID's are provided, a
WARNING is generated if any of them is not 2WAY or FULL. If you set both IP's
and RID's, only the IP's will be checked.

positional arguments:
  SNMP_COMMUNITY        the SNMP community string of the remote device
  HOST                  the IP of the remote host you want to check

optional arguments:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  --debug               debug output
  -r RID, --rid RID     OSPF neighbor router ID (multiple possible separated
                        by a comma and in-between quotes)
  -i IP, --ip IP        OSPF neighbor IP (multiple possible separated by a
                        comma and in-between quotes)
  -n NUMBER, --number NUMBER
                        Minimum number of OSPF neighbors required (overrides
                        --ip )

Written in Python 3.
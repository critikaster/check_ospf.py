#!/usr/bin/env python3

'''
Icinga (Nagios) plugin that checks the status of OSPF neighbors on a Cisco IOS router.
Default behaviour is that if any OSPF neighbors are detected, the check will return the OK string.
Command line arguments can be passed to match an RID, or one or more interface IP's to look for.
The check returns OK if the neighbor state is 2WAY or FULL.
Supports SNMP version 2c only at the moment.
'''

__version__ = 'v0.1'
__author__ = 'raoul@node00.nl'

import sys
import argparse
import subprocess
import traceback
import re


def ok(msg):
    print('OK:', msg)
    sys.exit(0)


def warning(msg):
    print('WARNING:', msg)
    sys.exit(1)


def critical(msg):
    print('CRITICAL:', msg)
    sys.exit(2)


def unknown(msg):
    print('UNKNOWN:', msg)
    sys.exit(3)


def error(msg):
    print('ERROR:', msg)
    sys.exit(3)


def check_ospf(snmp_check_values):

    ospf_states = {
        1   :   'DOWN',
        2   :   'ATTEMPT',
        3   :   'INIT',
        4   :   '2WAY',
        5   :   'EXSTART',
        6   :   'EXCHANGE',
        7   :   'LOADING',
        8   :   'FULL'
    }

    ### DEBUG OUTPUT

    if snmp_check_values['debug']:
        print('\n // DEBUG snmp_check_values\n')
        for key,value in sorted(snmp_check_values.items()):
            print(' {:20} {}'.format(key, value))
        print('\n // DEBUG ospf_states\n')
        for key, value in sorted(ospf_states.items()):
            print(' {}: {}'.format(key, value))

    ### GET DATA

    ## Run snmpwalk commands

    try:

        # snmpwalk: get OSPF neighbor interface IP's (read: next-hops)
        command_output_ospf_ip = subprocess.check_output(
            [
                'snmpwalk', '-v', '2c', '-c',
                snmp_check_values['community'],
                snmp_check_values['host'],
                snmp_check_values['ospfNbrIpAddr']
            ]
        )

        # snmpwalk: get OSPF neighbor router  ID's
        command_output_ospf_rid = subprocess.check_output(
            [
                'snmpwalk', '-v', '2c', '-c',
                snmp_check_values['community'],
                snmp_check_values['host'],
                snmp_check_values['ospfNbrRtrId']
            ]
        )

        # snmpwalk: get OSPF neighbor states
        command_output_ospf_state = subprocess.check_output(
            [
                'snmpwalk', '-v', '2c', '-c',
                snmp_check_values['community'],
                snmp_check_values['host'],
                snmp_check_values['ospfNbrState']
            ]
        )

    except:

        msg = 'Something went wrong with subprocess command \'snmpwalk\''
        msg += '\nIs the host ' + snmp_check_values['host'] + ' reachable?'
        msg += '\nIs it configured to accept SNMP polls from this host?'
        msg += '\nIs SNMP community string \'' + snmp_check_values['community'] + '\' valid?'

        error(msg)

    ## Parse snmpwalk commands

    try:

        # Parse snmpwalk output to lists

        # Parse command output: OSPF neighbor router interface IP's
        command_output_ospf_ip_list = command_output_ospf_ip.decode().split('\n')
        # Parse command output: OSPF router ID's
        command_output_ospf_rid_list = command_output_ospf_rid.decode().split('\n')
        # Parse command output: OSPF router states
        command_output_ospf_state_list = command_output_ospf_state.decode().split('\n')

        # Save all info to dictionary
        ospf_neighbor_data = {}

        # Parse lists to dictionary

        ## Get router IP's

        count = 1
        for item in command_output_ospf_ip_list:
            # If you try to use this plugin on a non-Cisco IOS router this happens
            if 'No Such Object available on this agent at this OID' in item:
                msg = 'SNMP OID not found: 1.3.6.1.2.1.14.10.1.1 (ospfNbrIpAddr). \
                Are you sure this is a Cisco IOS router?'
                error(msg)
            # Start building dictionary
            neighbor_name = 'Neighbor' + str(count).zfill(2)
            count += 1
            chunks = item.split()
            if len(chunks) == 4:
                ip_address = chunks[3]
                # Create a dictionary with 'NeighborX' as a key and relephant info as a list of values
                ospf_neighbor_data[neighbor_name] = ['Neighbor IP', ip_address]

        ## Get router ID's

        for item in command_output_ospf_rid_list:
            # Add to dictionary:
            # Match previously acquired ip_address to snmp_oid_id_ospfNbrRtrId ..
            # .. get current key and RID, save RID to current key
            chunks = item.split()
            if len(chunks) == 4:
                snmp_oid_id_ospfNbrRtrId = chunks[0]
                rtr_id = chunks[3]
                for key, value in ospf_neighbor_data.items():
                    ip_address = value[1]
                    # Look for the IP address string in the snmp_oid_id_ospfNbrRtrId string, which could look like:
                    # SNMPv2-SMI::mib-2.14.10.1.1.172.29.244.30.0
                    # or
                    # 1.3.6.1.2.1.14.10.1.1.172.29.244.30.0
                    result = re.search(ip_address, snmp_oid_id_ospfNbrRtrId)
                    if result:
                        ospf_neighbor_data[key].append('RID')
                        ospf_neighbor_data[key].append(rtr_id)

        ## Get OSPF neighbor states

        for item in command_output_ospf_state_list:
            chunks = item.split()
            if len(chunks) == 4:
                snmp_oid_id_ospfNbrState = chunks[0]
                neighbor_state = chunks[3]
                for key, value in ospf_neighbor_data.items():
                    ip_address = value[1]
                    result = re.search(ip_address, snmp_oid_id_ospfNbrState)
                    if result:
                        ospf_neighbor_data[key].append('State')
                        ospf_neighbor_data[key].append(neighbor_state)

        ### DEBUG OUTPUT

        if snmp_check_values['debug']:

            print('\n // DEBUG ospf_neighbor_data\n')
            print(' {:15}  {}'.format('Name', 'Data'))
            print(' {:15}  {}'.format('-----', '-------------------------'))
            for key, value in sorted(ospf_neighbor_data.items()):
                print(' {:15} {}'.format(key, value))
            print()

    # Catch own sys.exit in case it was called and exit gracefully
    except SystemExit:
        raise

    # On all other exceptions quit with an error and return traceback to stdout
    except:
        traceback.print_exc(file=sys.stdout)
        msg = 'Something went wrong parsing data. Probably wrong SNMP OID for this device.'
        error(msg)

    ### EVALUATE DATA

    ## RID: Check for specified RID

    if snmp_check_values['rid']:
        for key, value in ospf_neighbor_data.items():
            for item in value:
                idx = value.index(item)
                # Make sure the RID is found (idx = 3), not the next-hop IP (idx = 1)
                if snmp_check_values['rid'] in item and idx == 3:
                    # Check for OSPF state 2WAY or FULL
                    if value[5] == '4' or value[5] == '8':
                        msg = 'Found OSPF neighbor with RID ' + snmp_check_values['rid'] + ' and state ' \
                              + ospf_states[int(value[5])] + ' | ospf_rid_found=1'
                        ok(msg)
                    else:
                        msg = 'Found OSPF neighbor with RID ' + snmp_check_values['rid'] + ' but neighbor state is ' \
                              + ospf_states[int(value[5])] + ' | ospf_rid_found=0'
                        critical(msg)

        msg = 'OSPF neighbor not found: ' + snmp_check_values['rid'] + ' | ospf_rid_found=0'
        critical(msg)

    ## IP: Check for specified next-hop IP

    # In case multiple IP's are provided
    ip_address_list = []

    if snmp_check_values['ip_address']:

        # Check if ip_address contains multiple IP's separated by comma's
        if ',' in snmp_check_values['ip_address']:
            # Separate IP's by comma
            ip_address_list_raw = snmp_check_values['ip_address'].split(',')
            # Strip whitespace from IP's
            for item in ip_address_list_raw:
                # Make sure results are strings (not lists) by using index 0
                ip_address_list.append(item.split()[0])
                #print('item ', item)

        # If there's a list of IP's, continue to next code block, don't run this one
        if not ip_address_list:

            # In case of only one IP:
            for key, value in ospf_neighbor_data.items():
                for item in value:
                    idx = value.index(item)
                    # Make sure the next-hop IP is found (idx = 1), not the RID (idx = 3)
                    if snmp_check_values['ip_address'] in item and idx == 1:
                        # Check for OSPF state 2WAY or FULL
                        if value[5] == '4' or value[5] == '8':
                            msg = 'Found OSPF neighbor with IP ' + snmp_check_values['ip_address'] + ' and state ' + \
                                  ospf_states[int(value[5])] + ' | ospf_neighbor_ip_found=1'
                            ok(msg)
                        else:
                            msg = 'Found OSPF neighbor with IP ' + snmp_check_values['ip_address'] + ' and state ' + \
                                  ospf_states[int(value[5])] + ' | ospf_neighbor_ip_found=1'

            msg = 'OSPF neighbor IP not found: ' + snmp_check_values['ip_address'] + ' | ospf_neighbor_ip_found=0'
            critical(msg)


    ## DEFAULT: If any data has been collected:

    if ospf_neighbor_data.keys():

        ospf_neighbors_checked = len(ospf_neighbor_data.keys())

        # In case a minimum number of neighbors was set (this will override given IP(s) if set):
        if snmp_check_values['min_neighbors']:
            if snmp_check_values['min_neighbors'] <= ospf_neighbors_checked:

                # Amount of neighbors checks out, now check if OSPF neighbors have state 2WAY or FULL
                ospf_neighbor_states_warning = []

                for key, value in ospf_neighbor_data.items():

                    # If not 2WAY or FULL create warning message
                    if not value[5] == '4' and not value[5] == '8':
                        warning_msg = 'OSPF neigbor IP ' + value[1] + ' and RID ' + value[3] + ' has state ' + \
                                      ospf_states[int(value[5])]
                        ospf_neighbor_states_warning.append(warning_msg)
                    # If any warning was detected, generate warning output
                    if ospf_neighbor_states_warning:
                        warning(warning_msg)

                # No warnings detected
                msg = str(ospf_neighbors_checked) + ' OSPF neighbors detected (Required: ' + \
                      str(snmp_check_values['min_neighbors']) +') | ' + 'ospf_neighbors_checked=' + \
                      str(ospf_neighbors_checked)
                ok(msg)

            if snmp_check_values['min_neighbors'] > ospf_neighbors_checked:
                msg = str(ospf_neighbors_checked) + ' OSPF neighbors detected (Required: ' + \
                      str(snmp_check_values['min_neighbors']) +') | ' + 'ospf_neighbors_checked=' + \
                      str(ospf_neighbors_checked)
                critical(msg)

        # Default behaviour follows: if any neighbor was found, rejoice ..
        # .. But do check if OSPF neighbors have state 2WAY or FULL
        msg_ospf_state_warning = ''
        ospf_neighbors_down = 0
        ospf_neighbors_evaluated = 0

        for key, value in ospf_neighbor_data.items():

            # If multiple IP's were provided, then:
            if ip_address_list:
                # Check current IP against given IP's
                if value[1] in ip_address_list:

                    # If not 2WAY or FULL create warning message ..
                    if not value[5] == '4' and not value[5] == '8':

                        # If encountered before, add separator // to string
                        if msg_ospf_state_warning:
                            msg_ospf_state_warning += ' // '
                        warning_msg = 'OSPF neigbor IP ' + value[1] + ' and RID ' + value[3] + ' has state ' + \
                                      ospf_states[int(value[5])]
                        msg_ospf_state_warning += warning_msg
                        ospf_neighbors_down += 1

                    # .. else, if indeed 2WAY or FULL, just count it
                    ospf_neighbors_evaluated += 1

            else:
                # If not 2WAY or FULL create warning message ..
                if not value[5] == '4' and not value[5] == '8':

                    # If encountered before, add separator  // to string
                    if msg_ospf_state_warning:
                        msg_ospf_state_warning += ' // '
                    warning_msg = 'OSPF neigbor IP ' + value[1] + ' and RID ' + value[3] + ' has state ' + \
                                  ospf_states[int(value[5])]
                    msg_ospf_state_warning += warning_msg
                    ospf_neighbors_down += 1

                # .. else, if indeed 2WAY or FULL, just count it
                ospf_neighbors_evaluated += 1

        # If any warning was detected, generate warning output
        if msg_ospf_state_warning:
            msg = msg_ospf_state_warning + ' | ospf_neighbors_evaluated=' + \
                  str(ospf_neighbors_evaluated - ospf_neighbors_down)
            warning(msg)

        # No warnings detected
        msg = str(ospf_neighbors_evaluated) + ' OSPF neighbors detected | ospf_neighbors_evaluated=' + \
              str(ospf_neighbors_evaluated)
        ok(msg)

    else:
        msg = 'No OSPF neighbors detected.'
        warning(msg)


def main():

    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description='Icinga (Nagios) plugin that checks the status of OSPF neighbors on a Cisco IOS router.\
        Default behaviour is that if any OSPF neighbors are detected, the check will return the OK string.\
        Command line arguments can be passed to match a certain neighbor Router ID or interface IP to look for.\
        The check returns OK if the neighbor state is 2WAY or FULL.',
        epilog='Written in Python 3.'
    )
    parser.add_argument('--version', action='version', version=__version__)
    parser.add_argument('--debug', action='store_true', help='debug output')
    parser.add_argument('SNMP_COMMUNITY', type=str, help='the SNMP community string of the remote device')
    parser.add_argument('HOST', type=str, help='the IP of the remote host you want to check')
    parser.add_argument('-r', '--rid', type=str, help='OSPF Router ID (only one please)')
    parser.add_argument('-i', '--ip', type=str, help='OSPF neighbor IP (multiple IP\'s should be separated by a comma)')
    parser.add_argument('-n', '--number', type=int, help='Minimum number of OSPF neighbors required (overrides --ip)')
    args = parser.parse_args()

    # Default values
    snmp_check_values = {
        'community'                 : args.SNMP_COMMUNITY,
        'host'                      : args.HOST,
        'ospfNbrIpAddr'             : '1.3.6.1.2.1.14.10.1.1',
        'ospfNbrRtrId'              : '1.3.6.1.2.1.14.10.1.3',
        'ospfNbrState'              : '1.3.6.1.2.1.14.10.1.6',
        'rid'                       : None,
        'ip_address'                : None,
        'min_neighbors'             : None,
        'debug'                     : False
    }

    # Debug mode enabled?
    if args.debug:
        snmp_check_values['debug'] = True

    # RID set?
    if args.rid:
        snmp_check_values['rid'] = args.rid

    # Neighbor IP set?
    if args.ip:
        snmp_check_values['ip_address'] = args.ip

    # Minimum amount of OSPF neighbors set?
    if args.number:
        snmp_check_values['min_neighbors'] = args.number

    # Check OSPF status
    check_ospf(snmp_check_values)


if __name__ == '__main__':
    main()


# Copyright (c) 2014, raoul@node00.nl
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


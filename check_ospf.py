#!/usr/bin/env python3

'''
        Icinga (Nagios) plugin that checks the status of OSPF neighbors on a Cisco IOS Router.

        The check returns OK if the neighbor state is 2WAY or FULL.
        Without any optional arguments, returns OK if any OSPF neighbors are detected.

        Optional arguments can be passed to match a specific neighbor Router ID (RID) or interface IP to look for.
        In that case a CRITICAL will be generated if that specific neighbor is down.

        In case multiple IP\'s or RID\'s are provided, a WARNING is generated if any of them is not 2WAY or FULL.
        If you set both IP\'s and RID\'s, only the IP\'s will be checked.
'''

__version__ = 'v0.21'
__author__ = 'raoul@node00.nl'

import sys
import argparse
import subprocess
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

    # Save all gathered data to dictionary
    ospf_neighbor_data = {}

    ### DEBUG OUTPUT

    if snmp_check_values['debug']:
        print('\n // DEBUG snmp_check_values\n')
        for key,value in sorted(snmp_check_values.items()):
            print(' {key:20} {value}'.format(**locals()))
        print('\n // DEBUG ospf_states\n')
        for key, value in sorted(ospf_states.items()):
            print(' {key}: {value}'.format(**locals()))

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

        # Parse command output: OSPF neighbor router interface IP's
        command_output_ospf_ip_list = command_output_ospf_ip.decode().split('\n')
        # Parse command output: OSPF router ID's
        command_output_ospf_rid_list = command_output_ospf_rid.decode().split('\n')
        # Parse command output: OSPF router states
        command_output_ospf_state_list = command_output_ospf_state.decode().split('\n')

        ## Validate SNMP output

        # If you try to use this plugin on a non-Cisco IOS router, this happens
        for item in command_output_ospf_ip_list:
            if 'No Such Object available on this agent at this OID' in item:
                msg = 'SNMP OID not found: 1.3.6.1.2.1.14.10.1.1 (ospfNbrIpAddr). \
                \nAre you sure this is a Cisco IOS router?'
                error(msg)

        ## Parse lists to dictionary

        ## Parse router IP's

        count = 1
        for item in command_output_ospf_ip_list:
            # Start building dictionary
            neighbor_name = 'Neighbor' + str(count).zfill(2)
            count += 1
            chunks = item.split()
            if len(chunks) == 4:
                ip_address = chunks[3]
                # Create a dictionary with 'NeighborX' as a key and relephant info as a list of values
                ospf_neighbor_data[neighbor_name] = ['Neighbor IP', ip_address]

        ## Parse router ID's

        for item in command_output_ospf_rid_list:
            # Match ip_address to value ospfNbrRtrId, get key, save ospfNbrRtrId to key
            chunks = item.split()
            if len(chunks) == 4:
                # Search for ip_address in ospfNbrRtrId
                for key, value in ospf_neighbor_data.items():
                    result = re.search(value[1], chunks[0])
                    if result:
                        ospf_neighbor_data[key].append('RID')
                        ospf_neighbor_data[key].append(chunks[3])

        ## Parse OSPF neighbor states

        for item in command_output_ospf_state_list:
            chunks = item.split()
            if len(chunks) == 4:
                for key, value in ospf_neighbor_data.items():
                    result = re.search(value[1], chunks[0])
                    if result:
                        ospf_neighbor_data[key].append('State')
                        ospf_neighbor_data[key].append(chunks[3])

        ### DEBUG OUTPUT

        if snmp_check_values['debug']:

            print('\n // DEBUG ospf_neighbor_data\n')
            print(' {:15}  {}'.format('Name', 'Data'))
            print(' {:15}  {}'.format('-----', '-------------------------'))
            for key, value in sorted(ospf_neighbor_data.items()):
                print(' {key:15} {value}'.format(**locals()))
            print()


        ### EVALUATE DATA USING USER INPUT

        msg_ospf_state_warning = ''
        ospf_neighbors_down = 0
        ospf_neighbors_up = 0
        ospf_neighbors_evaluated = 0
        ospf_neighbors_total = len(ospf_neighbor_data.keys())

        # Check if specified IP's/RID's are actually found
        neighbors_found_set = set()
        neighbors_to_check_set = set()

        for key, value in ospf_neighbor_data.items():

            current_ip = value[1]
            current_rid = value[3]
            ospf_status = int(value[5])

            ## IP: Check for specified IP(s)

            if snmp_check_values['ip']:
                for item in snmp_check_values['ip']:
                    neighbors_to_check_set.add(item)
                    # item is one of the IP's from user input
                    if item == current_ip:
                        neighbors_found_set.add(item)
                        # If not 2WAY or FULL create warning message
                        if not ospf_status == 4 and not ospf_status == 8:
                            # If encountered before, add separator // to string
                            if msg_ospf_state_warning:
                                msg_ospf_state_warning += ' // '

                            warning_msg = 'OSPF neigbor IP ' + current_ip + ' and RID ' + current_rid + ' has state ' + \
                                          ospf_states[ospf_status]

                            msg_ospf_state_warning += warning_msg
                            ospf_neighbors_down += 1
                            ospf_neighbors_evaluated += 1

                        # .. else, if 2WAY or FULL neighbor detected, just count it
                        if ospf_status == 4 or ospf_status == 8:
                            ospf_neighbors_up += 1
                            ospf_neighbors_evaluated += 1



            ## RID: Check for specified RID(s)

            elif snmp_check_values['rid']:
                for item in snmp_check_values['rid']:
                    neighbors_to_check_set.add(item)
                    # item is one of the IP's from user input
                    if item == current_rid:
                        neighbors_found_set.add(item)
                        # If not 2WAY or FULL create warning message
                        if not ospf_status == 4 and not ospf_status == 8:
                            # If encountered before, add separator // to string
                            if msg_ospf_state_warning:
                                msg_ospf_state_warning += ' // '

                            warning_msg = 'OSPF neigbor IP ' + current_ip + ' and RID ' + current_rid + ' has state ' + \
                                          ospf_states[ospf_status]

                            msg_ospf_state_warning += warning_msg
                            ospf_neighbors_down += 1
                            ospf_neighbors_evaluated += 1

                        # .. else, if 2WAY or FULL neighbor detected, just count it
                        if ospf_status == 4 or ospf_status == 8:
                            ospf_neighbors_up += 1
                            ospf_neighbors_evaluated += 1


            else:
                # If not 2WAY or FULL create warning message
                if not ospf_status == 4 and not ospf_status == 8:
                    # If encountered before, add separator // to string
                    if msg_ospf_state_warning:
                        msg_ospf_state_warning += ' // '

                    warning_msg = 'OSPF neigbor IP ' + current_ip + ' and RID ' + current_rid + ' has state ' + \
                                  ospf_states[ospf_status]

                    msg_ospf_state_warning += warning_msg
                    ospf_neighbors_down += 1
                    ospf_neighbors_evaluated += 1

                # .. else, if 2WAY or FULL neighbor detected, just count it
                if ospf_status == 4 or ospf_status == 8:
                    ospf_neighbors_up += 1
                    ospf_neighbors_evaluated += 1

        ### EVALUATE RESULTS AND GENERATE OUTPUT

        # Spelling check
        extra_s = ''
        if ospf_neighbors_up > 1:
            extra_s = 's'

        # Totals
        msg_totals = ' (' + str(ospf_neighbors_up) + ' neighbor' + extra_s + ' up out of ' + str(ospf_neighbors_evaluated) + \
                     ' checked, ' + str(ospf_neighbors_total) + ' detected)'

        # Perf data
        msg_perfdata = ' | ospf_neighbors=' + str(ospf_neighbors_up)

        # WARNING: Warnings detected
        if msg_ospf_state_warning:
            warning(msg_ospf_state_warning + msg_totals + msg_perfdata)

        # CRITICAL: Not all neighbours found
        if snmp_check_values['min_neighbors'] > ospf_neighbors_up:
            msg = str(ospf_neighbors_up) + ' OSPF neighbor' + extra_s + ' detected (Required: ' + \
                  str(snmp_check_values['min_neighbors']) + ')'
            critical(msg + msg_totals + msg_perfdata)

        # CRITICAL: Specified neighbor not found
        neighbors_not_found_set = neighbors_to_check_set.difference(neighbors_found_set)

        if not len(neighbors_not_found_set) == 0:
            msg = 'Could not find:'
            for item in neighbors_not_found_set:
                msg += ' ' + item
            critical(msg + msg_totals + msg_perfdata)

        # OK
        msg = str(ospf_neighbors_up) + ' OSPF neighbor' + extra_s + ' in state 2WAY or FULL'
        ok(msg + msg_totals + msg_perfdata)

    # Catch own sys.exit in case it was called and exit gracefully
    except SystemExit:
        raise

    # On all other exceptions quit with a traceback and error
    except:
        msg = 'Something went wrong parsing data. Prolly wrong SNMP OID for this device. Unless it\'s something else.'
        error(msg)


def main():

    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description='Icinga (Nagios) plugin that checks the status of OSPF neighbors on a Cisco IOS router.\
        The check returns OK if the neighbor state is 2WAY or FULL.\
        Without any optional arguments, returns OK if any OSPF neighbors are detected.\
        Optional arguments can be passed to match a specific neighbor Router ID (RID) or interface IP to look for.\
        In that case a CRITICAL will be generated if that specific neighbor is down.\
        In case multiple IP\'s or RID\'s are provided, a WARNING is generated if any of them is not 2WAY or FULL.\
        If you set both IP\'s and RID\'s, only the IP\'s will be checked.',
        epilog='Written in Python 3.'
    )
    parser.add_argument('--version', action='version', version=__version__)
    parser.add_argument('--debug', action='store_true', help='debug output')
    parser.add_argument('SNMP_COMMUNITY', type=str, help='the SNMP community string of the remote device')
    parser.add_argument('HOST', type=str, help='the IP of the remote host you want to check')
    parser.add_argument('-r', '--rid', type=str, help='OSPF neighbor router ID (multiple possible separated by a comma \
    and in-between quotes)')
    parser.add_argument('-i', '--ip', type=str, help='OSPF neighbor IP (multiple possible separated by a comma \
    and in-between quotes)')
    parser.add_argument('-n', '--number', type=int, help='Minimum number of OSPF neighbors required (overrides --ip )')
    args = parser.parse_args()

    # Default values
    snmp_check_values = {
        'community'                 : args.SNMP_COMMUNITY,
        'host'                      : args.HOST,
        'ospfNbrIpAddr'             : '1.3.6.1.2.1.14.10.1.1',
        'ospfNbrRtrId'              : '1.3.6.1.2.1.14.10.1.3',
        'ospfNbrState'              : '1.3.6.1.2.1.14.10.1.6',
        'rid'                       : None,
        'ip'                : None,
        'min_neighbors'             : None,
        'debug'                     : False
    }

    # Debug mode enabled?
    if args.debug:
        snmp_check_values['debug'] = True

    # RID set?
    if args.rid:
        rid_list = [args.rid]
        # Check if multiple RID's are given
        if ',' in args.rid:
            rid_list = []
            # Separate IP's by comma
            rid_list_raw = args.rid.split(',')
            # Strip whitespace from IP's
            for item in rid_list_raw:
                # Make sure results are strings (not lists) by using index 0
                rid_list.append(item.split()[0])

        snmp_check_values['rid'] = rid_list

    # Neighbor IP set?
    if args.ip:
        ip_address_list = [args.ip]
        # Check if multiple IP's are given
        if ',' in args.ip:
            ip_address_list = []
            # Separate IP's by comma
            ip_address_list_raw = args.ip.split(',')
            # Strip whitespace from IP's
            for item in ip_address_list_raw:
                # Make sure results are strings (not lists) by using index 0
                ip_address_list.append(item.split()[0])

        snmp_check_values['ip'] = ip_address_list

    # Minimum amount of OSPF neighbors set?
    if args.number:
        snmp_check_values['min_neighbors'] = args.number
    else:
        snmp_check_values['min_neighbors'] = 0


    # Check OSPF status
    check_ospf(snmp_check_values)


if __name__ == '__main__':
    main()
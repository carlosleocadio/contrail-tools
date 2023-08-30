#!/usr/bin/env python

"""
nh-rpf-checker.py: Retrieve all programmed flows on a given vrouter and analyse if
any flow is having Source NH mismatch - causing RPF failure and consequent packet drop.
The script should be run from undercloud VM - in RHOSP environments
No other type of clouds are supported by this tool at the moment.

Usage:
  nh-rpf-checker.py -s | --single <vrouter>
  nh-rpf-checker.py -a | --all
  nh-rpf-checker.py -f | --file
  nh-rpf-checker.py -h | --help
  nh-rpf-checker.py --version

Options:
  -h --help     Show this screen.
  --version     Show version.
  --keep        Keep logs. Persistent mode. Log files will not be deleted after each run.
  -a --all      Run checker against all vRouters (retrieved from undercloud)
    

"""

__author__      = "Carlos Leocadio"
__copyright__   = "Copyright (c) 2021 Juniper Networks, Inc. All rights reserved."
__version__     = "v0.9.0"

import sys
import os
import shutil
from lxml import etree
from distutils import util
import paramiko
import logging
import uuid
import argparse
import json
import time
from collections import defaultdict

## curl -s -k --key $SERVER_KEYFILE --cert $SERVER_CERTFILE https://localhost:8085/Snh_FetchAllFlowRecords  |  xmllint --format -
## SERVER_KEYFILE=/etc/contrail/ssl/private/server-privkey.pem
## SERVER_CERTFILE=/etc/contrail/ssl/certs/server.pem
## curl -s -k --key /etc/contrail/ssl/private/server-privkey.pem --cert /etc/contrail/ssl/certs/server.pem https://localhost:8085/Snh_FetchAllFlowRecords  |  xmllint --format -
## curl -s -k --key /etc/contrail/ssl/private/server-privkey.pem --cert /etc/contrail/ssl/certs/server.pem https://localhost:8085/Snh_KDropStatsReq |  xmllint --format -


def cli_menu():
    parser = argparse.ArgumentParser(description='Snh_FetchAllFlowRecords Flow NH Analyser')
    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument("-a", "--all",
                       help="Execute against all vRouters (retrieved from undercloud)",
                       action="store_true")

    group.add_argument("-s", "--single",
                       metavar='<vrouter>',
                       help="Execute against a single vRouter, specified by its hostname (compute node)",
                       action="store")

    group.add_argument("-f", "--file",
                       metavar='<file>',
                       help="Parse file with data from 'Snh_FetchAllFlowRecords' introspect",
                       action="store")

    parser.add_argument("-k", "--keep",
                        metavar='<logs_path>',
                        default="/tmp",
                        help="Keep logs. Persistent mode. Introspect XML files will not be deleted after each run. (default: /tmp)",
                        action="store")

    return parser.parse_args()


def create_ssh_session(target_node_addr, user, key=None):
    logging.debug("Opening SSH Session {} " .format(target_node_addr))
    client_ssh = paramiko.SSHClient()
    client_ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client_ssh.connect(hostname=target_node_addr, username=user, key_filename=key)
    return client_ssh

def get_next_flow_record_set(xmlfile):
    parser = etree.XMLParser()
    tree = etree.parse(xmlfile, parser=parser)
    root = tree.getroot()

    for t in root.iter('flow_key'):
        if t.text != "0-0-0-0-0-0.0.0.0-0.0.0.0":
            return t.text
        else:
            return None


def main():

    # a list of the target vRouters to fetch Snh_FetchAllFlowRecords data from
    # when using the program in single mode, will hold a single entry
    target_vrouters = []

    # create a list to hold the names of all XML files transfered and that
    # need to be parsed for each vRouter - key
    vrouter_xml = defaultdict(list)

    args = cli_menu()

    if args.all:
        stream = os.popen('openstack server list -f json')
        output = stream.read()
        json_servers_info = json.loads(output)
        for i in json_servers_info:
            if 'Compute' in i["Flavor"]:
                target_vrouters.append(i["Name"] + ".ctlplane")
    elif args.single:
        target_vrouters.append(args.single)
    elif args.file:
        # parse file mode, not implemented yet
        print("File mode - not implemented yet")
        exit(1)

    # setup logging to file and stdout also
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s %(levelname)-8s %(message)s',
                        filename='/tmp/nh-rpf-checker.log',
                        filemode='w')

    logging.getLogger("paramiko").setLevel(logging.ERROR)

    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    # set a format which is simpler for console use
    formatter = logging.Formatter('%(name)-12s: %(levelname)-8s %(message)s')
    # tell the handler to use this format
    console.setFormatter(formatter)
    # add the handler to the root logger
    logging.getLogger().addHandler(console)

    logging.info('nh-rpf-checker - Started')
    
    # generate unique run id
    run_id = uuid.uuid4()
    logging.info('Run ID = {}' .format(run_id))

    # create a folder to store files XML files collected
    logs_folder = "nh-rpf-checker-" + str(run_id)
    logs_path = os.path.join(args.keep, logs_folder)
    os.mkdir(logs_path)
    logging.FileHandler(os.path.join(logs_path, "nh-rpf-checker.log"))
    logging.info('Log folder created: {}' .format(logs_path))
    
    # key required for SSH access to CC nodes
    key_file_ssh = '/home/stack/.ssh/id_rsa'

    # open ssh session
    username = "heat-admin"

    command = "sudo curl -s -k --key /etc/contrail/ssl/private/server-privkey.pem --cert /etc/contrail/ssl/certs/server.pem https://localhost:8085/Snh_FetchAllFlowRecords -o $(hostname -s)_flowrecords_0.xml"

    for vrouter in target_vrouters:
        logging.info('Querying vRouter {}' .format(vrouter))
        ssh_client = create_ssh_session(vrouter, username, key_file_ssh)
        flow_rid = 0

        while True:
            # run request on target host via ssh session and close session after
            logging.debug('Generating XML trace file on {} - flow record {}' .format(vrouter, flow_rid))
            ssh_client.exec_command(command)
            transport = ssh_client.get_transport()
            # fetch the file generated by the execution of previous command
            sftp = paramiko.SFTPClient.from_transport(transport)
            remote_filepath = "/home/heat-admin/" + vrouter.replace('.ctlplane', '') + "_flowrecords_" + str(flow_rid) + ".xml"
            filename = vrouter.replace('.ctlplane', '') + "_flowrecords_" + str(flow_rid) + ".xml"
            localpath = os.path.join(args.keep, logs_path, filename)
            vrouter_xml[vrouter.replace('.ctlplane', '')].append(localpath)
            time.sleep(0.4)
            logging.debug('Transfering file {} \n\t\t\t to {}' .format(remote_filepath, localpath))
            sftp.get(remote_filepath,localpath)
            #delete file on remote after transfer - keep setup clean
            logging.debug('Deleting file on remote {}' .format(remote_filepath))
            ###sftp.remove(remote_filepath)

            # get field NextFlowRecordsSet of last file transfered
            fnext = get_next_flow_record_set(localpath)
            if fnext:
                flow_rid+=1
                logging.debug('Next Flow Record Set: {} ' .format(fnext))
                command = "sudo curl -s -k --key /etc/contrail/ssl/private/server-privkey.pem --cert /etc/contrail/ssl/certs/server.pem " + \
                    "https://localhost:8085/Snh_NextFlowRecordsSet?x=" + fnext + \
                    " -o $(hostname -s)_flowrecords_" + str(flow_rid) + ".xml"
            else:
                command = "sudo curl -s -k --key /etc/contrail/ssl/private/server-privkey.pem --cert /etc/contrail/ssl/certs/server.pem https://localhost:8085/Snh_FetchAllFlowRecords -o $(hostname -s)_flowrecords_0.xml"
                break

        
        logging.debug("Closing SFTP/SSH Session {} " .format(vrouter))
        ##sftp.close()
        ssh_client.close()


    # parse all files in the list
    # this iteritems method is for p2.x
    # on p3.x is items()
    logging.info('#### Parsing All XML Files ####')
    for vrouter, files_to_parse in vrouter_xml.iteritems():
        nflows = 0
        invalid_flows = 0
        for f in files_to_parse:
            parser = etree.XMLParser()
            tree = etree.parse(f, parser=parser)
            root = tree.getroot()

            for flow in root.iter('SandeshFlowData'):
                nflows+=1
                for c in flow.iter():
                    if c.tag == 'flow_handle':
                        flow_id = int(c.text)
                    elif c.tag == 'rpf_nh':
                        rpf_nh = int(c.text)
                    elif c.tag == 'src_ip_nh':
                        src_ip_nh = int(c.text)
                    elif c.tag == 'enable_rpf':
                        rpf_enabled = util.strtobool(c.text)

                if rpf_enabled and rpf_nh != src_ip_nh:
                    invalid_flows+=1
                    logging.info('vRouter: {} - Mismatch NH detected for flow ID {} - Src NH: {} - Expected: {}' .format(vrouter, flow_id, src_ip_nh, rpf_nh))
            
        logging.info('vRouter: {} - Total #Flows {} - Invalid Flows (RPF) {}' .format(vrouter, nflows, invalid_flows))

    shutil.move("/tmp/nh-rpf-checker.log", os.path.join(logs_path, "nh-rpf-checker.log"))



if __name__ == "__main__":
    main()

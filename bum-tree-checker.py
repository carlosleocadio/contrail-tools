#!/usr/bin/env python

import argparse
import re
from xml.dom import minidom
from collections import defaultdict
import paramiko
import logging
import json
import openstack
from networkx import DiGraph, is_isomorphic, is_strongly_connected, weakly_connected_components

__author__ = "Carlos Leocadio"
__copyright__ = "Copyright (c) 2022 Carlos Leocadio"
__license__ = "MIT"
__version__ = "1.0.2"

"""
bum-tree-checker.py: checks BUM tree graph connectivity using data from
Contrail Controllers (3) and compares the tree programmed on vRouters using CLI.
In order to accomplish that, it retrieves Network and Port objects information from Openstack,
so it assumes Openstack API is reachable and the environment variables needed for authorization
are set.

optional arguments:
  -h, --help            show this help message and exit
  -n NETID, --netid NETID
                        Virtual Network Object UUID
  -a, --all             Check all VN objects
  -c CONTROLLERS [CONTROLLERS ...], --controllers CONTROLLERS [CONTROLLERS ...]
                        List of Contrail Controller addresses
  -d, --debug           Enable debug logging
"""

#setup logging - Global
logging.basicConfig(format='%(levelname)s %(message)s')
log = logging.getLogger('bum-tree-checker')


## Graph logic auxiliar methods
def build_graph_from_matrix(matrix):
    G = DiGraph()
    for k,v in matrix.items():
        for i in v:
            G.add_edge(k, i)
    return G

# find missing edges on weakly connected Directed graph
def find_missing_edges(graph):
    missing_e = [(e[1], e[0]) for e in graph.edges() if (e[1], e[0]) not in graph.edges()]
    return missing_e

# compare Graphs A and B edges, returning list of edges
# in A missing in B
def compare_edges_graphs(graph_a, graph_b):
    missing_edges_in_b = []
    edges_a = graph_a.edges()
    edges_b = graph_b.edges()
    missing_edges_in_b = [e for e in edges_a if e not in edges_b]
    return missing_edges_in_b


def getElementsByTagName_safe(xml_elem, tag):
    n = None
    try:
        n = xml_elem.getElementsByTagName(tag)[0].childNodes[0].nodeValue
    except IndexError:
        pass
    return n

# takes XML from Snh_ItfReq and returns vhost0 interface - id 1 - IP address
def get_vhost0(itf_xml):
    itf_elements = itf_xml.getElementsByTagName('ItfSandeshData')
    for e in itf_elements:
        itf_id = getElementsByTagName_safe(e, 'index')
        if itf_id == '1': 
            vhost0_addr = getElementsByTagName_safe(e, 'ip_addr')
            return vhost0_addr

# takes XML from Snh_ItfReq and returns all vifs belonging to net
def get_vifs_attached_net(portids_list, vrf_name, itf_xml):
    vifs = []
    itf_elements = itf_xml.getElementsByTagName('ItfSandeshData')
    for e in itf_elements:
        itf_id = getElementsByTagName_safe(e, 'index')
        itf_uuid = getElementsByTagName_safe(e, 'uuid')
        itf_active = getElementsByTagName_safe(e, 'active')
        itf_vrf = getElementsByTagName_safe(e, 'vrf_name')
        
        ## vrf_name is not unique, and Port UUID needs to be used to confirm
        ## via Openstack if the Interface Element belongs to our Network
        ## network_ports.keys() are all the ports belonging to our network
        
        if itf_uuid in portids_list: 
            if itf_vrf == vrf_name and itf_active == 'Active':
                log.debug("Saving Vif {} " .format(itf_id))
                vifs.append(itf_id)
            else:
                log.error("Skipping UUID {} - Vif {} - State {} - VRF Name {}" .format(itf_uuid, itf_id, itf_active, itf_vrf))
   
    log.debug("Vifs Array {} ".format(vifs))
    return vifs


def extract_mcast_tree_cc(connections, xml_f):
    #get levelX_forwarders for xml_f extracted from cc
    for i in range(2):
        level_string_tag = ''.join(['level', str(i), '_forwarders' ])
        log.debug("Extract Mcast Tree - Level String - {}" .format(level_string_tag))
        li_forwarders = xml_f.getElementsByTagName(level_string_tag)

        # if there are no leveX_forwarders, we can just skip this level
        if not li_forwarders: 
            log.error("Empty - Level String - {}" .format(level_string_tag))
            continue

        fwd_elements = li_forwarders.item(0).getElementsByTagName('ShowMulticastForwarder')

        for e in fwd_elements:
            fwd_addr = e.getElementsByTagName('address')[0].childNodes[0].nodeValue
            log.debug('\n\tForwarder Address {}' .format(fwd_addr))
            links_section = e.getElementsByTagName('links').item(0)
            link_elements = links_section.getElementsByTagName('ShowMulticastTreeLink')
            for l in link_elements:
                link_addr = l.getElementsByTagName('address')[0].childNodes[0].nodeValue
                log.debug("\t Link {}" .format(link_addr))
                connections[fwd_addr].append(link_addr)
            nb_link_elements = e.getElementsByTagName('list').item(0).getAttribute('size')
            log.debug('Number of Link Elements {}' .format(nb_link_elements))

    return connections



def open_ssh_channel(host, user):
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, username=user)
    return client


def run_cmd_remote(client, cmd):
    stdin, stdout, stderr = client.exec_command(cmd)
    status = stdout.channel.recv_exit_status()

    if status >= 0: 
        result = stdout.read()

    return status, result



def cli_menu():
    parser = argparse.ArgumentParser(
        description='bum-tree-checker.py: script to check BUM tree graph connectivity')

    net_option = parser.add_mutually_exclusive_group(required=True)

    net_option.add_argument('-n', '--netid',
                        help="Virtual Network Object UUID",
                        action="store")
    
    net_option.add_argument('-a', '--all',
                        help="Check all VN objects",
                        action='store_true')

    parser.add_argument('-c', '--controllers',
                        help="List of Contrail Controller addresses",
                        nargs='+',
                        default=[],
                        required=True)

    parser.add_argument('-d', '--debug',
                        help="Enable debug logging",
                        action="store_const", dest="loglevel", const=logging.DEBUG,
                        default=logging.INFO)

    return parser.parse_args()



def main():
    args = cli_menu()

    log.setLevel(args.loglevel)
    log.info("Starting bum-tree-checker.py")

    # List of Contrail Controller addresses
    ccs_list = args.controllers
    if len(ccs_list) != 3:
        log.info("Controllers list size must be 3")
        exit(2)

    # Numver of Networks
    total_networks = 0

    # Number of Networks verified
    total_networks_verified = 0

    # List of Network UUIDs with problematic BUM trees detected
    broken_trees = []

    # virtual network uuid
    net_uuid = ''

    # to get vrf from vif --get output
    vrf_pattern = re.compile(r'^\s+Vrf:(?P<vrf>\d+)', re.MULTILINE)

    # to get nh from rt --get output
    nh_pattern = re.compile(r'Index\s+DestMac\s+Flags\s+Label\/VNID\s+Nexthop\s+Stats\s\d+\s+ff:ff:ff:ff:ff:ff\s+\w+\s+\d+\s+(?P<nh>\d+)\s+\d+', re.MULTILINE)

    # to get legs on VRF 0 from nh --get output
    vrf0_leg_pattern = re.compile(r'Oif:0\sLen:\d+\sData:.*\s+Sip:(?P<sip>(?:[0-9]{1,3}\.){3}[0-9]{1,3})\sDip:(?P<dip>(?:[0-9]{1,3}\.){3}[0-9]{1,3})', re.MULTILINE)

    # dict with list of peers for each multicast forwarder as per Controllers 
    connections = defaultdict(list)

    # dict with list of peers according to vRouter CLI
    connections_vrouter = defaultdict(list)

    # dict with list of interface ids per compute
    vifs_per_compute = defaultdict()

    # dict to map compute hostname to vhost0 IP
    vhost0_ips = defaultdict()

    log.info("Connecting to Openstack API...")
    conn = openstack.connect()

    if not args.all:
        network_objs = []
        network_objs.append(conn.network.find_network(args.netid))
    else:
        # a generator of network objects
        network_objs = conn.network.networks()

    # key is Network ID and value is a list of Port UUIDs
    port_ids_by_network = defaultdict(list)

    # key is Port UUID - value is IP and binding host tuple
    network_ports_attributes = defaultdict()

    # a generator for all port objects in Openstack
    port_objs = conn.network.ports()
    for p in port_objs:
        if p.status == 'ACTIVE':
            port_ids_by_network[p.network_id].append(p.id)
            network_ports_attributes[p.id] = (p.fixed_ips, p.binding_host_id.split(".")[0])


    #now run the BUM tree verification procedure for each N network_obj - with N >= 1
    for network_obj in network_objs:

        # clear variables
        connections.clear()
        connections_vrouter.clear()
        vifs_per_compute.clear()
        vhost0_ips.clear()
        
        total_networks+=1
        
        net_uuid = network_obj.id
        log.info("Checking BUM tree for Network {} : {} " .format(total_networks, net_uuid))

        if len(network_obj.subnet_ids) > 1:
            log.warning("Network {} has more than 1 subnet - {}\n\
                Code execution will proceed. We only care about Network UUID and ports that belong to that Network.\
                Contrail considers all subnets of a given VN belong to the same VRF." .format(net_uuid, network_obj.subnet_ids))
        
            # the subnet object is not relevant - ignore - Contrail only uses VN to define the VRF Name
            subnet_obj = conn.network.find_subnet(network_obj.subnet_ids[0])
            log.debug("Subnet: {} " .format(subnet_obj))
        
        elif len(network_obj.subnet_ids) == 0:
            log.error("No subnets found on Network {}" .format(net_uuid))


        if network_obj.project_id:
            project_obj = conn.identity.find_project(network_obj.project_id)
            log.debug("Project: {} " .format(project_obj))
        else:
            log.error("No Project ID found on Network {}" .format(net_uuid))
            continue
        
        # We actually don't use domain_obj, because we assume all are under 'default-domain'
        if project_obj.domain_id:
            domain_obj = conn.identity.find_domain(project_obj.domain_id)
            log.debug("Domain: {} " .format(domain_obj))

        ##vrf_name = domain_obj.name + ':' + project_obj.name + ':' + network_obj.name + ':' + subnet_obj.name
        ##vrf_name = 'default-domain:NIMS_Core_RTL_REF:N_InternalOAM:N_InternalOAM'
        ## TODO: verify why the vrf_name is constructed this way
        vrf_name = ':'.join(['default-domain', project_obj.name, network_obj.name, network_obj.name])

        log.info("Network UUID {} is {} " .format(net_uuid, vrf_name))

        log.info("CCs {} " .format(ccs_list))

        cmd_string = ''.join(["sudo curl -s -k\
            --key /etc/contrail/ssl/private/server-privkey.pem\
            --cert /etc/contrail/ssl/certs/server.pem\
            https://127.0.0.1:8083/Snh_ShowMulticastManagerDetailReq?x=", vrf_name, ".ermvpn.0"])

        # connect to each CC and extract local Mcast tree
        for c in ccs_list:
            client = open_ssh_channel(c, 'heat-admin')
            status, result = run_cmd_remote(client, cmd_string)
            client.close()

            if status >= 0: 
                xml_dom = minidom.parseString(result)
                pretty_xml_as_string = xml_dom.toprettyxml(encoding='UTF-8')
                log.debug("XML file CC {}\n{} " .format(c, pretty_xml_as_string))
                log.info("Extracting Mcast tree from Controller {} " .format(c))
                extract_mcast_tree_cc(connections, xml_dom)
            else:
                log.error("Status Error while reading Mcast tree from {} " .format(c))


        if len(connections) == 0:
            log.error("Unable to create connections matrix from Controllers - Skipping")
            continue
        else:
            log.info("Connections Matrix from Controllers")
            for k,v in connections.items():
                log.info("{} - {} " .format(k, json.dumps(v)))

  
        # at this point in code, we have the full connections matrix as programmed in the controllers

        """
        now we need to find out what computes have interfaces on the virtual network with ID matching net_uuid
        assuming 'source overcloudrc' is already performed, we can use openstack client to get list of all ports
        """

        if len(port_ids_by_network[net_uuid]) > 0: 
            log.info("Listing Ports belonging to Network {}\n {}" .format(net_uuid, port_ids_by_network[net_uuid]))
        else: 
            log.error("There are no ports on Network {} - Subnet {} - Skipping" .format(net_uuid, subnet_obj.id))
            continue
        
        # extract binding_hosts set while logging the ports in the network
        binding_hosts_set = []

        for p_id in port_ids_by_network[net_uuid]:
            t = network_ports_attributes[p_id]
            log.debug("Port ID {} - Fixed IPs - {} - Binding host {}" .format(p_id, t[0], t[1]))
            if t[1] not in binding_hosts_set: binding_hosts_set.append(t[1])
        
        
        log.info("Total number of ports on Network {} is {}" .format(net_uuid, len(port_ids_by_network[net_uuid])))

        log.info("Binding Hosts Set {}" .format(binding_hosts_set))
        

        ## now, connect to each compute in binding_hosts_set via SSH and get the Vif ID belonging to --net from introspect
        cmd_string = "sudo curl -s -k \
                    --key /etc/contrail/ssl/private/server-privkey.pem\
                    --cert /etc/contrail/ssl/certs/server.pem\
                    https://127.0.0.1:8085/Snh_ItfReq"

        log.debug("curl CMD string {} " .format(cmd_string))
        for c in binding_hosts_set:
            client = open_ssh_channel('.'.join([c,'ctlplane']), 'heat-admin')
            status, result = run_cmd_remote(client, cmd_string)
            client.close()

            if status >= 0: 
                xml_dom = minidom.parseString(result)
                pretty_xml_as_string = xml_dom.toprettyxml(encoding='UTF-8')
                log.debug("Fetching Interfaces XML file from Compute {}\n{} " .format(c, pretty_xml_as_string))
                vifs_per_compute[c] = get_vifs_attached_net(port_ids_by_network[net_uuid], vrf_name, xml_dom)
                vhost0_ips[c] = get_vhost0(xml_dom)
            else:
                log.error("Status Error while reading ItfReq from {} " .format(c))

        log.info("Listing Vif IDs per Compute")
        total_vifs_counter = 0
        for k,v in vifs_per_compute.items():
            log.info("Compute {} [{}] - VIFs {} " .format(k, vhost0_ips[k], v))
            total_vifs_counter += len(v)
        
        log.info("Total number of VIFs found {} - And Total number of Port objects is {} " .format(total_vifs_counter, len(port_ids_by_network[net_uuid])))

        if total_vifs_counter != len(port_ids_by_network[net_uuid]):
            log.error("Mismatch between number of VIFs found and Total of Port Objects - Skipping")
            continue
    

        ### now, we need to SSH into each compute in binding_hosts_set to get rt and nh info
        ### for the broadcast L2 address


        for c,vifs in vifs_per_compute.items():
            client = open_ssh_channel('.'.join([c,'ctlplane']), 'heat-admin')
            for v in vifs:
                cmd_a = ''.join(['sudo docker exec contrail_vrouter_agent vif --get ', v])
                status, result = run_cmd_remote(client, cmd_a)

                if status >= 0:
                    match = re.search(vrf_pattern, result)
                    vrf = match.group('vrf')
                    log.debug("VRF {}" .format(vrf))

                cmd_b = ''.join(['sudo docker exec contrail_vrouter_agent rt --get ff:ff:ff:ff:ff:ff --vrf ', vrf, ' --family bridge'])
                status, result = run_cmd_remote(client, cmd_b)

                if status >= 0:
                    match = re.search(nh_pattern, result)
                    nh = match.group('nh')
                    log.debug("NH {}" .format(nh))

                cmd_c = ''.join(['sudo docker exec contrail_vrouter_agent nh --get ', nh])
                status, result = run_cmd_remote(client, cmd_c)

                if status >= 0:
                    match_list = re.findall(vrf0_leg_pattern, result)
                    for t in match_list:
                        log.debug("sip {} dip {} " .format(t[0], t[1]))
                        if t[1] not in connections_vrouter[t[0]]:
                            connections_vrouter[t[0]].append(t[1])
            
            client.close()

        log.info("Connections Matrix from vRouter CLI")
        for k,v in connections_vrouter.items():
            log.info("{} - {} " .format(k, json.dumps(v)))

        
        
        '''
        Finally, use the connection matrixes to build two graphs - Graph C (Controllers) and Graph V (vRouter)
        Graph MUST be Directional with e(i,j) = e(j,i) 
        Apply graph theory to evaluate isomorphism and graph partitioning
        '''

        C = build_graph_from_matrix(connections)
        V = build_graph_from_matrix(connections_vrouter)

        log.info("Are C (Controllers) and V (vRouter) graphs isomorphic (?) -> {}" .format(is_isomorphic(C,V)))
        # If C and V are isomorphic we can stop code execution... but for now let's proceed with analysis 

        # C Graph analysis
        log.debug("C Nodes: {}" .format(C.nodes()))
        log.debug("C Edges: {}" .format(C.edges()))

        if not is_strongly_connected(C):
            # this will only return missing edge if the edge is missing in one direction but present on the other
            # asusming link symmetry in directional graph
            # for a given Node A, if there is a edge E1 to Node B then there will be a symetrical edge E2 linking B to A
            missing_edges = find_missing_edges(C)
            if len(missing_edges) > 0:
                log.info("C Missing edges {} " .format(missing_edges))
            else:
                log.info("Unable to determine missing edge in C - there are weakly connected edges - proceed with verification")     

            log.info("Graph C is weakly connected - subgraphs are {}" .format(list(weakly_connected_components(C))))
        else:
            log.info("Graph C is strongly connected")


        # V Graph analysis
        log.debug("V Nodes: {}" .format(V.nodes()))
        log.debug("V Edges: {}" .format(V.edges()))
        if not is_strongly_connected(V): 
            missing_edges = find_missing_edges(V)
            if len(missing_edges) > 0:
                log.info("V Missing edges {} " .format(missing_edges))
            else:
                log.info("Unable to determine missing edge in V - there are weakly connected edges - proceed with verification")     

            if len(list(weakly_connected_components(V))) > 1:
                log.info("Graph V weakly connected components [subgraphs] {}" .format(list(weakly_connected_components(V))))
                missing_edges_in_v = compare_edges_graphs(C,V)
                log.info("Missing Edges in V present in C {}" .format(missing_edges_in_v))
        else:
            log.info("Graph V is strongly connected")

        total_networks_verified+=1
            
        # exit code logic
        if is_strongly_connected(C) and is_strongly_connected(V) and is_isomorphic(C,V):
            log.info("OK BUM tree for Network: {} " .format(net_uuid))
        else:
            log.info("NOK BUM tree for Network: {} " .format(net_uuid))
            broken_trees.append(net_uuid)

    log.info("### END ###")
    log.info("Total Networks detected {}\nTotal Networks verified {}\nTotal broken BUM trees detected {}\nNetworks with broken BUM tree {}" .format(total_networks, total_networks_verified, len(broken_trees), broken_trees))

if __name__ == "__main__":
    main()

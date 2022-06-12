#!/usr/bin/env python

import argparse
import re
import prettytable
from xml.dom import minidom
from collections import defaultdict
import paramiko
import logging
import json
import openstack
import networkx as nx

__author__ = "Carlos Leocadio"
__copyright__ = "Copyright (c) 2022 Carlos Leocadio"
__license__ = "MIT"
__version__ = "0.9.0"

"""
bum-tree-checker.py: checks BUM tree graph connectivity using data from
Contrail Controllers (3) and compares the tree programmed on vRouters.
The script also retrieves Network and Port objects information from Openstack,
so it assumes Openstack API is reachable and the env vars needed for auth are set

optional arguments:
  -h, --help            show this help message and exit
  -n NET, --net NET     VRF Description string <a:b:c:d> format
  -c CONTROLLERS [CONTROLLERS ...], --controllers CONTROLLERS [CONTROLLERS ...]
                        List of Contrail Controller addresses
  -d, --debug           Enable debug logging
"""

#setup logging - Global
logging.basicConfig(format='%(levelname)s %(message)s')
log = logging.getLogger('bum-tree-checker')


## Graph logic auxiliar methods
def build_graph_from_matrix(matrix):
    G = nx.DiGraph()

    for k,v in matrix.items():
        for i in v:
            G.add_edge(k, i)

    return G

# find missing edges on weakly connected Directed graph
def find_missing_edges(graph):
    missing_e = []
    #determine the missing edge
    for e in graph.edges():
        # for each edge (i,j), edge (j,i) must be present in list
        if (e[1], e[0]) not in graph.edges():
            #print("Missing edge is {} " .format((e[1], e[0])))
            missing_e.append((e[1], e[0]))  
    return missing_e

# compare Graphs A and B edges, returning list of edges
# in A missing in B
def compare_edges_graphs(graph_a, graph_b):
    missing_edges_in_b = []
    edges_a = graph_a.edges()
    edges_b = graph_b.edges()
    for e in edges_a:
        if e not in edges_b: missing_edges_in_b.append(e)
    return missing_edges_in_b

####

def getElementsByTagName_safe(xml_elem, tag):
    n = None
    try:
        n = xml_elem.getElementsByTagName(tag)[0].childNodes[0].nodeValue
    except IndexError:
        #print('Empty Node Value for tag', tag)
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
def get_vifs_attached_net(net, itf_xml):
    vifs = []
    itf_elements = itf_xml.getElementsByTagName('ItfSandeshData')
    for e in itf_elements:
        itf_id = getElementsByTagName_safe(e, 'index')
        itf_vrf = getElementsByTagName_safe(e, 'vrf_name')

        if itf_vrf == net: vifs.append(itf_id)

    return vifs

def extract_mcast_tree_cc(connections, xml_f):

    #get levelX_forwarders for xml_f extracted from cc
    for i in range(2):
        level_string_tag = 'level'+ str(i) + '_forwarders'
        log.debug("Extract Mcast Tree - Level String - {}" .format(level_string_tag))
        li_forwarders = xml_f.getElementsByTagName(level_string_tag)

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

def run_cmd_remote(host, cmd):
    client = paramiko.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, username='heat-admin')
    stdin, stdout, stderr = client.exec_command(cmd)
    status = stdout.channel.recv_exit_status()

    if status >= 0: 
        result = stdout.read()
        log.debug("Result {} " .format(result))

    client.close()
    return status, result

def cli_menu():
    parser = argparse.ArgumentParser(
        description='bum-tree-checker.py: script to check BUM tree graph connectivity')

    parser.add_argument('-n', '--net',
                        help="VRF Description string <a:b:c:d> format",
                        action="store",
                        required=True)

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
    
    # VRF from vif_report.py table
    vrf_name = args.net

    # List of Contrail Controller addresses
    ccs_list = args.controllers
    if len(ccs_list) != 3:
        log.info("Controllers list size must be 3")
        exit(2)

    # dict with list of peers for each multicast forwarder as per Controllers
    connections = defaultdict(list)

    # dict with list of peers according to vRouter CLI
    connections_vrouter = defaultdict(list)

    # dict with list of interface ids per compute
    vifs_per_compute = defaultdict()

    # dict to map compute hostname to vhost0 IP
    vhost0_ips = defaultdict()

    log.info("VRF {} parsed - CCs {} " .format(vrf_name, ccs_list))

    cmd_string = "sudo curl -s -k \
        --key /etc/contrail/ssl/private/server-privkey.pem\
        --cert /etc/contrail/ssl/certs/server.pem\
        https://127.0.0.1:8083/Snh_ShowMulticastManagerDetailReq?x="\
        + vrf_name +".ermvpn.0"

    log.debug("curl CMD string {} " .format(cmd_string))

    # connect to each CC and extract local tree
    for c in ccs_list:
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(c, username='heat-admin')
        stdin, stdout, stderr = client.exec_command(cmd_string)
        status = stdout.channel.recv_exit_status()

        if status >= 0: 
            xml_dom = minidom.parse(stdout)
            pretty_xml_as_string = xml_dom.toprettyxml(encoding='UTF-8')
            log.debug("XML file CC {}\n{} " .format(c, pretty_xml_as_string))

        client.close()
        log.info("Extracting Mcast tree from Controller {} " .format(c))
        extract_mcast_tree_cc(connections, xml_dom)
        
    
    log.info("Connections Matrix from Controllers")
    for k,v in connections.items():
        log.info("{} - {} " .format(k, json.dumps(v)))


    # at this point in code, we have the full connections matrix as programmed in the controllers

    """
    now we need to find out what computes have interfaces connected to the VRF (--net)
    assuming 'source overcloudrc' is already performed, we can use openstack client to get list of all ports
    
    <domain>:<project>:<network>:<subnet>
    and I am assuming
    <network> == <subnet>
    net = "default-domain:ngnp_E2E:ngnp-tdcn-m2m-dpe-e2e-ch2:ngnp-tdcn-m2m-dpe-e2e-ch2"
    """

    log.info("Connecting to Openstack API...")
    conn = openstack.connect()

    network_ports = []

    # get the network object
    networks_list = conn.network.networks()
    for n in networks_list:
        if n.name == args.net.split(':')[2]:
            _network = n
            break

    # log network id
    log.info("Network ID {}" .format(_network.id))

    # use the network object to get the subnet id
    log.info("Subnet ID {}" .format(_network.subnet_ids[0]))


    # get subnet object using id
    if len(_network.subnet_ids) > 1: exit(3)
    subnet = conn.network.find_subnet(_network.subnet_ids[0])
    log.debug("Subnet details {}" .format(subnet))

    # now, retrieve all ports belonging to _network (ports_list is a generator)
    ports_list = conn.network.ports()

    for p in ports_list:
        if p.network_id == _network.id:
            #print("Port ID %s - Fixed IPs %s - Host %s" % (p.id, p.fixed_ips, p.binding_host_id))
            #build a list of tuples (port ID, Fixed IPs, Binding Host)
            network_ports.append((p.id, p.fixed_ips, p.binding_host_id.split(".")[0]))

    log.info("Listing Ports belonging to Network {} " .format(_network.id))
    # extract binding_hosts set while logging the ports in the network
    binding_hosts_set = []
    for t in network_ports:
        log.info("Port ID {} - Fixed IPs - {} - Binding host {}" .format(t[0], t[1], t[2]))
        if t[2] not in binding_hosts_set: binding_hosts_set.append(t[2])
    log.info("Total number of ports on Network {} is {}" .format(_network.id, len(network_ports)))

    log.info("Binding Hosts Set {}" .format(binding_hosts_set))
    


    ## now, connect to each compute in binding_hosts_set via SSH and get the Vif ID belonging to --net from introspect
    cmd_string = "sudo curl -s -k \
                --key /etc/contrail/ssl/private/server-privkey.pem\
                --cert /etc/contrail/ssl/certs/server.pem\
                https://127.0.0.1:8085/Snh_ItfReq"

    log.debug("curl CMD string {} " .format(cmd_string))
    for c in binding_hosts_set:
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(c+'.ctlplane', username='heat-admin')
        stdin, stdout, stderr = client.exec_command(cmd_string)
        status = stdout.channel.recv_exit_status()

        if status >= 0: 
            xml_dom = minidom.parse(stdout)
            pretty_xml_as_string = xml_dom.toprettyxml(encoding='UTF-8')
            log.debug("Interfaces XML file from Compute {}\n{} " .format(c, pretty_xml_as_string))

        client.close()
        vifs_per_compute[c] = get_vifs_attached_net(args.net, xml_dom)

        vhost0_ips[c] = get_vhost0(xml_dom)

    log.info("Listing Vif IDs per compute")
    for k,v in vifs_per_compute.items():
        log.info("Compute {} - vifs {} " .format(k, v))

    log.info("Listing vhost0 IP addresses per compute")
    for k,v in vhost0_ips.items():
        log.info("Compute {} - {} " .format(k, v))


    ### now, we need to SSH into each compute in binding_hosts_set to get rt and nh info
    ### for the broadcast L2 address

    # to get vrf from vif --get output
    vrf_pattern = re.compile(r'^\s+Vrf:(?P<vrf>\d+)', re.MULTILINE)

    # to get nh from rt --get output
    nh_pattern = re.compile(r'Index\s+DestMac\s+Flags\s+Label\/VNID\s+Nexthop\s+Stats\s\d+\s+ff:ff:ff:ff:ff:ff\s+\w+\s+\d+\s+(?P<nh>\d+)\s+\d+', re.MULTILINE)

    # to get legs on VRF 0 from nh --get output
    vrf0_leg_pattern = re.compile(r'Oif:0\sLen:\d+\sData:.*\s+Sip:(?P<sip>(?:[0-9]{1,3}\.){3}[0-9]{1,3})\sDip:(?P<dip>(?:[0-9]{1,3}\.){3}[0-9]{1,3})', re.MULTILINE)

    for c,vifs in vifs_per_compute.items():
        for v in vifs:
            cmd_a = 'sudo docker exec contrail_vrouter_agent vif --get ' + v
            status, result = run_cmd_remote(c+'.ctlplane', cmd_a)

            if status >= 0:
                match = re.search(vrf_pattern, result)
                vrf = match.group('vrf')
                log.debug("VRF {}" .format(vrf))

            cmd_b = 'sudo docker exec contrail_vrouter_agent rt --get ff:ff:ff:ff:ff:ff --vrf ' + vrf + ' --family bridge'
            status, result = run_cmd_remote(c+'.ctlplane', cmd_b)

            if status >= 0:
                match = re.search(nh_pattern, result)
                nh = match.group('nh')
                log.debug("NH {}" .format(nh))

            cmd_c = 'sudo docker exec contrail_vrouter_agent nh --get ' + nh
            status, result = run_cmd_remote(c+'.ctlplane', cmd_c)

            if status >= 0:
                match_list = re.findall(vrf0_leg_pattern, result)
                for t in match_list:
                    log.debug("sip {} dip {} " .format(t[0], t[1]))
                    if t[1] not in connections_vrouter[t[0]]:
                        connections_vrouter[t[0]].append(t[1])


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

    log.info("Are C (Controllers) and V (vRouter) graphs isomorphic (?) -> {}" .format(nx.is_isomorphic(C,V)))
    # If C and V are isomorphic we can stop code execution... but for now let's proceed with analysis 

    # C Graph analysis
    log.debug("C Nodes: {}" .format(C.nodes()))
    log.debug("C Edges: {}" .format(C.edges()))

    if not nx.is_strongly_connected(C):
        # this will only return missing edge if the edge is missing in one direction but present on the other
        # asusming link symmetry in directional graph
        missing_edges = find_missing_edges(C)
        if len(missing_edges) > 0:
            log.info("C Missing edges {} " .format(missing_edges))
        else:
            log.info("Unable to determine missing edge in C - there are weakly connected edges - proceed with verification")     

        log.info("Graph C is weakly connected - subgraphs are {}" .format(list(nx.weakly_connected_components(C))))
    else:
        log.info("Graph C is strongly connected")


    # V Graph analysis
    log.debug("V Nodes: {}" .format(V.nodes()))
    log.debug("V Edges: {}" .format(V.edges()))
    if not nx.is_strongly_connected(V): 
        missing_edges = find_missing_edges(V)
        if len(missing_edges) > 0:
            log.info("V Missing edges {} " .format(missing_edges))
        else:
            log.info("Unable to determine missing edge in V - there are weakly connected edges - proceed with verification")     

        if len(list(nx.weakly_connected_components(V))) > 1:
            log.info("Graph V Weakly connected components [subgraphs] {}" .format(list(nx.weakly_connected_components(V))))
            missing_edges_in_v = compare_edges_graphs(C,V)
            log.info("Missing Edges in V present in C {}" .format(missing_edges_in_v))

    else:
        log.info("Graph V is strongly connected")



if __name__ == "__main__":
    main()

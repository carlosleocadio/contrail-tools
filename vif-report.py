#!/usr/bin/env python

import sys
import libvirt
import prettytable
from xml.dom import minidom
import requests
from requests.packages import urllib3
from collections import defaultdict


__author__ = "Carlos Leocadio"
__copyright__ = "Copyright (c) 2022 Carlos Leocadio"
__license__ = "MIT"
__version__ = "0.9.0"

"""
vif-report.py generates a table formated output with information related with
all the Virtual Network Interfaces (Ports) present on the compute node, and
the attributes of those VMIs - "VIF", "TAP", "VRF", "MAC", "IP", "AAP". 
Instances information is also included - Virtual Machines running on KVM/Qemu

The information used to build the report is retrieved from vRouter Agent via introspect port 
and from the hypervisor using libvirt module.
"""

# avoid InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

## Relevant info: https://libvirt.org/html/libvirt-libvirt-domain.html#virDomainState
libvirt_state_names = {
    libvirt.VIR_DOMAIN_RUNNING: "running",
    libvirt.VIR_DOMAIN_BLOCKED: "idle",
    libvirt.VIR_DOMAIN_PAUSED: "paused",
    libvirt.VIR_DOMAIN_SHUTDOWN: "in shutdown",
    libvirt.VIR_DOMAIN_SHUTOFF: "shut off",
    libvirt.VIR_DOMAIN_CRASHED: "crashed",
    libvirt.VIR_DOMAIN_NOSTATE: "no state"
}

libvirt_shutoff_reasons = {
    libvirt.VIR_DOMAIN_SHUTOFF_UNKNOWN: "unknown",
    libvirt.VIR_DOMAIN_SHUTOFF_SHUTDOWN: "normal shutdown",
    libvirt.VIR_DOMAIN_SHUTOFF_DESTROYED: "forced poweroff",
    libvirt.VIR_DOMAIN_SHUTOFF_CRASHED:	"domain crashed",
    libvirt.VIR_DOMAIN_SHUTOFF_MIGRATED: "migrated",
    libvirt.VIR_DOMAIN_SHUTOFF_SAVED: "saved to a file",
    libvirt.VIR_DOMAIN_SHUTOFF_FAILED: "failed to start",
    libvirt.VIR_DOMAIN_SHUTOFF_FROM_SNAPSHOT: "restored from a snapshot"
}

libvirt_shutdown_reason = {
    libvirt.VIR_DOMAIN_SHUTDOWN_UNKNOWN: "unknown",
    libvirt.VIR_DOMAIN_SHUTDOWN_USER: "user request"
}

libvirt_running_reason = {
    libvirt.VIR_DOMAIN_RUNNING_UNKNOWN: "unknown",
    libvirt.VIR_DOMAIN_RUNNING_BOOTED: "normal boot",
    libvirt.VIR_DOMAIN_RUNNING_MIGRATED: "migrated",
    libvirt.VIR_DOMAIN_RUNNING_RESTORED: "state file restored",
    libvirt.VIR_DOMAIN_RUNNING_FROM_SNAPSHOT: "snapshot restored",
    libvirt.VIR_DOMAIN_RUNNING_UNPAUSED: "returned from paused",
    libvirt.VIR_DOMAIN_RUNNING_MIGRATION_CANCELED: "returned from migration",
    libvirt.VIR_DOMAIN_RUNNING_SAVE_CANCELED: "returned from failed save process",
    libvirt.VIR_DOMAIN_RUNNING_WAKEUP: "returned from pmsuspended due to wakeup event",
    libvirt.VIR_DOMAIN_RUNNING_CRASHED: "resumed from crashed",
    libvirt.VIR_DOMAIN_RUNNING_POSTCOPY: "running in post-copy migration mode"
}

def getElementsByTagName_safe(xml_elem, tag):
    n = None
    try:
        n = xml_elem.getElementsByTagName(tag)[0].childNodes[0].nodeValue
    except IndexError:
        #print('Empty Node Value for tag', tag)
        pass
    
    return n


domains_table = prettytable.PrettyTable()
domains_table.title = "Domains Report for "
domains_table.field_names = ["ID", "State", "Reason", "UUID", "Name", "Nova Name"]

domain_vifs_table = prettytable.PrettyTable()
domain_vifs_table.field_names = ["VIF", "TAP", "VRF", "MAC", "IP", "AAP"]

vrfs_table = prettytable.PrettyTable()
vrfs_table.field_names = ["VRF ID", "Description"]

conn = None

contrail_key = "/etc/contrail/ssl/private/server-privkey.pem" 
contrail_cert = "/etc/contrail/ssl/certs/server.pem"
cert = (contrail_cert, contrail_key)
url1 = "https://localhost:8085/Snh_VrfListReq"
url2 = "https://localhost:8085/Snh_ItfReq"

req1 = requests.get(url1, cert=cert, verify=False)
req2 = requests.get(url2, cert=cert, verify=False)

vrf_xml = minidom.parseString(req1.text)

itf_xml = minidom.parseString(req2.text)

# key is VRF description and value VRF ID
vrf_name_to_id = defaultdict(int)


vrf_elements = vrf_xml.getElementsByTagName('VrfSandeshData')
for e in vrf_elements:
    vrf_name = e.getElementsByTagName('name')[0].childNodes[0].nodeValue #this might be wrong, I don't know why it is showing 4 fields
    vrf_id = e.getElementsByTagName('ucindex')[0].childNodes[0].nodeValue #this might be wrong
    vrf_name_to_id[vrf_name] = vrf_id
    vrfs_table.add_row([int(vrf_id), vrf_name])

vrfs_table.sortby = "VRF ID"
print(vrfs_table.get_string())


# dictionary to map VM UUID with VIFs list
vm_uuid_to_vifs = defaultdict(list)

# list of tuples to store vif properties
# (id, name, ip, mac, vrf, vm_uuid, )
vif_details = defaultdict(list)

# key is VM UUID value KVM Domain Number
vm_uuid_to_domain = defaultdict(int)


itf_elements = itf_xml.getElementsByTagName('ItfSandeshData')
for e in itf_elements:
    itf_id = getElementsByTagName_safe(e, 'index')
    itf_name = getElementsByTagName_safe(e, 'name')
    itf_ip = getElementsByTagName_safe(e, 'ip_addr')
    itf_mac = getElementsByTagName_safe(e, 'mac_addr')
    itf_vrf = getElementsByTagName_safe(e, 'vrf_name')
    itf_vm_uuid = getElementsByTagName_safe(e, 'vm_uuid')
    itf_vm_name = getElementsByTagName_safe(e, 'vm_name')

    #extract AAP
    # for now I am assuming aap_ip_addr is just one, but that is wrong
    aap_ip_addr = '-'
    aaps_list_element = e.getElementsByTagName('allowed_address_pair_list')
    for elem in aaps_list_element:
        staticrt_elements = elem.getElementsByTagName('StaticRouteSandesh')
        for elem in staticrt_elements:
            aap_ip_addr = getElementsByTagName_safe(elem, 'ip_addr')

    vm_uuid_to_vifs[itf_vm_uuid].append(itf_id)
    itf_details = (itf_name, itf_ip, itf_mac, itf_vrf, itf_vm_uuid, itf_vm_name, aap_ip_addr)
    vif_details[itf_id].extend(itf_details)


try:
    conn = libvirt.openReadOnly("qemu:///system")
except libvirt.libvirtError as e:
    print(repr(e))
    exit(1)


domains = conn.listAllDomains(0)

if len(domains) != 0:
    for d in domains:
        domain_xml = minidom.parseString(d.XMLDesc(0))
        nova_name = domain_xml.getElementsByTagName('nova:name')[0].childNodes[0].nodeValue
        state, reason = d.state()
        if state is libvirt.VIR_DOMAIN_SHUTOFF:
            reason = libvirt_shutoff_reasons[reason]
        elif state is libvirt.VIR_DOMAIN_RUNNING:
            reason = libvirt_running_reason[reason]
        domains_table.add_row([d.ID(), libvirt_state_names[state], reason, d.UUIDString(), d.name(), nova_name])
        vm_uuid_to_domain[d.UUIDString()] = int(d.ID())

domains_table.sortby = "ID"
print("")
print(domains_table.get_string(title='Domains Report'))

# Now we need to create an Interfaces table for each Domain/guest
# "VIF" | "TAP" | "VRF" | "MAC" | "IP" | "AAP"

print("")
for k,v in sorted(vm_uuid_to_domain.items(), key=lambda v: v[1]):
    title = "Domain " + str(v) + " Interfaces | Instance UUID " + k 
    print(title)
    domain_vifs_table.clear_rows()
    domain_vifs = vm_uuid_to_vifs[k]
    for vif in domain_vifs:
        vif_details_list = vif_details[vif]
        domain_vifs_table.add_row([int(vif), vif_details_list[0], vrf_name_to_id[vif_details_list[3]], vif_details_list[2], vif_details_list[1], vif_details_list[6]])

    domain_vifs_table.sortby = "VIF"
    print(domain_vifs_table.get_string(title=title))
    print("")

conn.close()
exit(0)

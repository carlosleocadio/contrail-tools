#!/usr/bin/env python

__author__ = "Carlos Leocadio"
__copyright__ = "Copyright (c) 2022 Carlos Leocadio"
__license__ = "MIT"
__version__ = "0.7.0"

"""
vr-dpdk-cpu-affinity.py: retrieves current affinity CPU settings of vRouter DPDK
process and threads, presenting the output in a formatted table.

Usage:
  vr-dpdk-cpu-affinity.py -s | --service <service_cpus> 
  vr-dpdk-cpu-affinity.py -c | --control <control_cpus>
  vr-dpdk-cpu-affinity.py -h | --help
  vr-dpdk-cpu-affinity.py --version

Options:
  -h --help     Show this screen.
  --version     Show version.
  --check       Prints current CPU affinity for vRouter DPDK process/threads
  --set         Set new CPU affinity according to the arguments <service_cpus> <control_cpus>    
"""

import argparse
import subprocess
import logging
import prettytable
import psutil
import itertools
import re
from collections import defaultdict
import docker

def cli_menu():
    parser = argparse.ArgumentParser(
        description='vr-dpdk-cpu-affinity.py: By default, retrieves current affinity CPU settings of vRouter DPDK process and threads.\
            Can also be used to change settings for Control or Service threads')

    parser.add_argument("-s", "--service",
                    default=None,
                    help="Set new CPU affinity for vRouter DPDK Service threads",
                    type=str
                    )
    parser.add_argument("-c", "--control",
                    default=None,
                    help="Set new CPU affinity for vRouter DPDK Control threads",
                    type=str
                    )

    return parser.parse_args()


def run_check_output(cmd):
    if isinstance(cmd, str):
        cmd = cmd.split() 

    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        return (out, True)
    except subprocess.CalledProcessError as e:
        logging.error("Error %s exec cmd %s  " % (e, cmd))
        return (None, False)


def get_proc(proc_name):
    for proc in psutil.process_iter():
        if proc_name in proc.name():
            return proc
    return None


def compare_affinity_lists(l):
    r = 0
    itr = iter(l)
    for a,b in zip(l[:-1], l[1:]):
        if a != b:
            r+=1
    
    return r

def merge_lists_and_extract_set(l):
    m = []
    for i in l:
        m = m + i
    return list(set(m))



def expand_range(cpus_range):
    l2 = [i.split('-') for i in cpus_range.split(',')]
    l3 = [range(int(i[0]),int(i[1])+1) if len(i) == 2 else [int(i[0])] for i in l2]
    final_l = []
    for i in l3:
        final_l += i
    return sorted(final_l)

def get_vif0_numa_node():
    out, flag = run_check_output('vif --get 0')
    pci_pattern = re.compile(r'vif0\/0\s+PCI:\s(?P<pci_addr>\b(0{0,4}:\d{2}:\d{2}.\d:?\w*))', re.MULTILINE)
    match_pci_addr = re.search(pci_pattern, str(out))
    if flag and match_pci_addr:
        pci_addr = match_pci_addr.group('pci_addr')
    else:
        return None
    
    pci_numa_node_file = '/sys/bus/pci/devices/' + pci_addr + '/numa_node'
    with open(pci_numa_node_file) as f:
        vif0_numa_node = f.readlines()
    
    return int(vif0_numa_node[0].rstrip())
        

def read_file(full_path):
    try:
        with open(full_path, 'r') as f:
            content = f.read()
    except IOError as e:
        content = None
        print("%s file not found" % full_path)
    return content
    

def extract_nova_cpu_list(nova_conf):
    nova_cpu_pattern = re.compile(r'^vcpu_pin_set\s?=\s?(.*)', re.MULTILINE)
    nova_cpu = re.search(nova_cpu_pattern, nova_conf)
    nova_cpus_list = []
    if nova_cpu:
        nova_cpu_set_string = nova_cpu.group(1)
        nova_cpus_list = expand_range(nova_cpu_set_string)
    return nova_cpus_list
    

class CpuInfo:

    def __init__(self):
        # key - logic CPU ID
        # attributes to store Core, Socket, Node - extracted from lscpu
        # isolation - extracted from cmdline/tuned configuration
        # proc - list of processes running on this core
        # vrule - list of violated rules by current settings in this core
        # phy - true or false (false means it is a HT core)
        self.data = defaultdict(dict)
        self._initialize_data()
        self.ht_enabled = False
        self._is_ht_enabled()
        self.numa_nodes = []
        self._set_numa_nodes()

        
    def _initialize_data(self):
        out, flag = run_check_output('lscpu -p')
        # build a dict.
        # key is logical CPU number value (Core, Node [numa])
        if flag:
            for l in out.splitlines():
                l = l.decode()
                if l[0] != '#':
                    x = str(l).split(',')
                    self.data[int(x[0])]['core'] = int(x[1])
                    self.data[int(x[0])]['socket'] = int(x[2])
                    self.data[int(x[0])]['numa'] = int(x[3])

            # set phy attribute during initialization
            for cpuid in self.data.keys():
                if self.is_phy(cpuid): self.data[cpuid]['phy'] = True
                else: self.data[cpuid]['phy'] = False

    def is_phy(self,cpuid):
        cpu_details = self.data.get(cpuid)
        if cpu_details['core'] == cpuid: return True
        else: return False

    # return the PHY core for a given HT cpuid
    def get_phy_for_ht(self, ht_cpuid):
        for c, attrs in self.data.items():
            if ht_cpuid == c and attrs['core'] != ht_cpuid:
                return attrs['core']
    
    # return the HT for a given PHY 
    def get_ht_for_phy(self, phy_cpuid):
        for c, attrs in self.data.items():
            if phy_cpuid != c and attrs['core'] == phy_cpuid:
                return c
    
    def get_numa(self, cpuid):
        return self.data.get(cpuid).get('numa')

    # return true/false 
    def _is_ht_enabled(self):
        ht_pattern = re.compile(r'Thread\(s\)\sper\score:\s+(?P<nthreads>\d+)', re.MULTILINE)
        out, flag = run_check_output('lscpu')
        match_ht = re.search(ht_pattern, str(out))
        if flag and int(match_ht.group('nthreads')) > 1: self.ht_enabled = True
        else: self.ht_enabled = False
    
    def _set_numa_nodes(self):
        # determine number of NUMA nodes
        for k,v in self.data.items():
            if v.get('numa') not in self.numa_nodes:
                self.numa_nodes.append(v.get('numa'))

    def update_violated_rules(self, cpuid, rule_update):
        vrule = self.data.get(cpuid).get('vrule')
        if vrule is None:
            vrule = rule_update + ' '
        elif rule_update in vrule:
            return
        else:
            vrule += rule_update + ' '
        self.data[cpuid]['vrule'] = vrule


def main():

    PROC_LEGEND = {
        'A' : "vRouter Agent thread",
        'S' : "vRouter DPDK Service thread",
        'C' : "vRouter DPDK Control thread",
        'P' : "vRouter DPDK Processing/Forwarding thread",
        'N' : "Nova"
    }

    RULES = {
        'a' : "DPDK Processing/Forwarding threads must run on dedicated (not shared with any other process) and isolated cores (not managed by scheduler)",
        'b' : "DPDK Processing/Forwarding threads must all run on same NUMA as the one used by fabric NIC",
        'c' : "DPDK Processing/Forwarding threads cannot use Core 0 and HT sibling - these cores should be available for OS/Kernel tasks",
        'd' : "DPDK Processing/Forwarding threads, on HT-enabled environments, affinity must include both PHY and HT cores",
        'e' : "DPDK Service threads should run on two dedicated and isolated cores - one PHY core and corresponding HT - and on the same NUMA node as Processing/Forwarding threads",
        'f' : "DPDK Control threads should run on two dedicated and isolated cores - one PHY core and corresponding HT - and on the same NUMA node as Processing/Forwarding threads",
        'g' : "Nova cores, used to schedule workloads (VMs) are dedicated and isolated"
    }

    CTRL_THREADS = ['rte_mp_handle', 'rte_mp_async', 'eal-intr-thread']
    SRVC_THREADS = ['lcore-slave-1', 'lcore-slave-2', 'lcore-slave-8', 'lcore-slave-9']

    VR_DPDK_PROC_NAME = "contrail-vrouter-dpdk"
    VR_AGENT_PROC_NAME = "contrail-vrouter-agent"

    logging.basicConfig(level=logging.INFO, format='%(levelname)-8s %(message)s')
    logging.info('vr-dpdk-cpu-affinity - Started')

    args = cli_menu()

    vr_dpdk_proc = get_proc(VR_DPDK_PROC_NAME)
    if vr_dpdk_proc:
        logging.info("contrail-vrouter-dpdk PID: {}" .format(vr_dpdk_proc.pid))

    vr_agent_proc = get_proc(VR_AGENT_PROC_NAME)
    if vr_agent_proc:
        logging.info("contrail-vrouter-agent PID: {}" .format(vr_agent_proc.pid))


    ## CPU Info object
    cpu_info = CpuInfo()

    # create a dict with pid and Process for vRouter DPDK
    dpdk_proc_by_pid = {}

    # list containing the affinity settings [in list format] of all vRouter Agent threads
    agent_threads_affinity_lists = []
    cpus_agent = []

    # control threads - Process objects
    ctrl_ts = []
    # list containing the affinity settings [in list format] of all control threads
    ctrl_threads_affinity_lists = []
    cpus_dpdk_ctrl = []

    # service threads - Process objects
    srvc_ts = []
    # list containing the affinity settings [in list format] of all service threads
    srv_threads_affinity_lists = []
    cpus_dpdk_srv = []

    # forwarding threads - Process objects
    fwd_ts = []
    # list containing the affinity settings [in list format] of all fw threads
    fwd_threads_affinity_lists = []
    cpus_dpdk_fwd = []

    # vif0 NUMA node
    vif0_numa = get_vif0_numa_node()
    logging.info("vRouter Interface VIF 0 on NUMA Node {}" .format(vif0_numa))

    # Isolated CPU cores
    cpus_isolated = []

    # Nova CPU cores
    nova_cpus_list = []


    #### CPU isolation verification
    # either we have the isolation in cmdline isolcpus= 
    # or enforced by tuned
    # Check if cpu_partitioning profile is active_profile in tuned
    # if it is, then assume tuned is enforcing cpu isolation
    # else
    # check cmdline for cpuisolation settings


    tuned_active_profile = read_file('/etc/tuned/active_profile')
    
    if tuned_active_profile and 'cpu-partitioning' in tuned_active_profile:
        tuned_config = read_file('/etc/tuned/cpu-partitioning-variables.conf')

        if tuned_config:
            #print("tuned profile: %s" % tuned_content)
            tuned_isol_pattern = re.compile(r'^isolated_cores=(.*)', re.MULTILINE)
            match_isol = re.search(tuned_isol_pattern, tuned_config)
            if match_isol:
                isolcpus_string = match_isol.group(1)
                logging.info("Isolcpus configuration found in tuned {}" .format(isolcpus_string))
                cpus_isolated = expand_range(isolcpus_string)
        else:
            logging.info("Unable to get tuned cpu-partitioning configuration")


    else:
        cmdline_content = read_file('/proc/cmdline')
        if 'isolcpus' in cmdline_content:
            logging.info('isolcpus in cmdline')
        else:
            logging.info('isolcpus configuration not present in cmdline')

    if cpus_isolated:
        if max(cpus_isolated) > max(cpu_info.data.keys()):
            logging.info("Error in tuned isolated_cores parameter - highest CPU ID configured in tuned doesn't exist in this setup")

    
    for cpuid, attrs in cpu_info.data.items():
        # initialize isolated attribute according to cpus_isolated list - set to False by default
        if cpuid in cpus_isolated: attrs['isolated'] = True
        else: attrs['isolated'] = False
        

    #########################
    ## Get cores used by Nova
    ## get the details from /etc/nova/nova.conf file inside nova-compute container
    ## TODO what if there is no such container? improve this logic here to make it more
    ## generic. Eventually nova might not even be present, for instance in k8s environments

    # Connect to docker/podman and check if there is a running container name nova.

    client = docker.from_env()
    containers = client.containers.list()
    nova_containerized = False
    for c in containers:
        try:
            c_name = c.attrs['Config']['Labels']['container_name']
        except KeyError:
            pass
        if 'nova_compute' in c_name:
            #found nova_compute container
            nova_containerized = True
            break

    # bad approach
    if nova_containerized:
        out, flag = run_check_output('docker exec nova_compute cat /etc/nova/nova.conf')
    else:

        out = read_file('/etc/nova/nova.conf')


    if  nova_containerized and flag:
        nova_cpus_list = extract_nova_cpu_list(out)
    else:
        nova_cpus_list = extract_nova_cpu_list(out)

    if len(nova_cpus_list) > 0:
        logging.info("Nova vCPU List {} " .format(nova_cpus_list))
    else:
        logging.error('Unable to find Nova vCPU List on configuration file')


    #########################


    for t in vr_agent_proc.threads():
        p = psutil.Process(t.id)
        agent_threads_affinity_lists.append(p.cpu_affinity())

    r = compare_affinity_lists(agent_threads_affinity_lists)
    if r:
        logging.warning("Mismatch detected in vRouter Agent Threads affinity settings - some are using different affinity than others")

    cpus_agent = merge_lists_and_extract_set(agent_threads_affinity_lists)

    for t in vr_dpdk_proc.threads():
        p = psutil.Process(t.id)
        dpdk_proc_by_pid[t.id] = p
        if p.name() in SRVC_THREADS:
            srvc_ts.append(p)
            srv_threads_affinity_lists.append(p.cpu_affinity())
        elif p.name() in CTRL_THREADS:
            ctrl_ts.append(p)
            ctrl_threads_affinity_lists.append(p.cpu_affinity())
        elif t.id != vr_dpdk_proc.pid:
            fwd_ts.append(p)
            fwd_threads_affinity_lists.append(p.cpu_affinity())


    # check if all service threads are having the same CPU affinity settings
    r = compare_affinity_lists(srv_threads_affinity_lists)
    if r:
        logging.warning("Mismatch detected in Service Threads affinity settings - some are using different affinity than others")

    cpus_dpdk_srv = merge_lists_and_extract_set(srv_threads_affinity_lists)

    # check if all control threads are having the same CPU affinity settings
    r = compare_affinity_lists(ctrl_threads_affinity_lists)
    if r:
        logging.warning("Mismatch detected in Control Threads affinity settings - some are using different affinity than others")

    cpus_dpdk_ctrl = merge_lists_and_extract_set(ctrl_threads_affinity_lists)



    # Rule A check - check if any Control/Service or Agent thread is using core assigned for Forwarding thread
    # and confirm whether such cores are isolated
    cpus_dpdk_fwd = merge_lists_and_extract_set(fwd_threads_affinity_lists)
    for cpuid in cpus_dpdk_fwd:
        if cpuid in merge_lists_and_extract_set([cpus_dpdk_srv + cpus_dpdk_ctrl + cpus_agent]) or not cpu_info.data.get(cpuid).get('isolated'):
            cpu_info.update_violated_rules(cpuid, 'a')

    # Rule B check - mark as rule violation those Forwarding threads running on Cores
    # that don't belong to vif0 NUMA node
    for cpuid in cpus_dpdk_fwd:
        if cpu_info.get_numa(cpuid) != vif0_numa:
            cpu_info.update_violated_rules(cpuid, 'b')

    
    # Rule C check - Core 0 and its sibling can't be used by Forwarding threads
    # on NUMA 0 - Core 0 and its HT shouldn't be used by any vRouter services or Nova
    # and should also not be an isolated core
    core0_id = 0
    if cpu_info.ht_enabled:
    # to make sure this doesn't break in future for different cpu topologies
    # let's not assume sibling of core 0 is Id 1. Instead fetch it from cpu_info
        core0_ht = cpu_info.get_ht_for_phy(core0_id)
        forbiden_cores_rule_c = [core0_id, core0_ht]
    else:
        # only look for core 0
        forbiden_cores_rule_c = [core0_id]
    
    for cpuid in cpus_dpdk_fwd:
        if cpuid in forbiden_cores_rule_c:
            cpu_info.update_violated_rules(cpuid, 'c')

    for cpuid in forbiden_cores_rule_c:
        if cpu_info.data.get(cpuid).get('isolated'): cpu_info.update_violated_rules(cpuid, 'c')

    
    # Rule D check - when a PHY core is used by a fordwarding thread, its HT-pair must also be used for such (and vice-versa)
    phy_cores_fwd = []
    ht_cores_fwd = []
    for cpuid in cpus_dpdk_fwd:
        if cpu_info.is_phy(cpuid): phy_cores_fwd.append(cpuid)
        else: ht_cores_fwd.append(cpuid)
    
    for cpuid in phy_cores_fwd:
        ht_core = cpu_info.get_ht_for_phy(cpuid)
        if ht_core and ht_core not in ht_cores_fwd:
            cpu_info.update_violated_rules(cpuid, 'd')
    
    for cpuid in ht_cores_fwd:
        phy_core = cpu_info.get_phy_for_ht(cpuid)
        if phy_core and phy_core not in phy_cores_fwd:
            cpu_info.update_violated_rules(cpuid, 'd')


    # Rule E check - service threads need two dedicated and isolated cores (1 core and HT) 
    # on the same NUMA as Forwarding threads
    # TODO confirm isolation
    if len(cpus_dpdk_srv) > 2:
        logging.warning("Service Threads affinity size is {} - recommended 2" .format(len(cpus_dpdk_srv)))
    for cpuid in cpus_dpdk_srv:
        #if cpuid is outside vif0 numa, mark as violation of rule E
        if cpu_info.get_numa(cpuid) != vif0_numa:
            cpu_info.update_violated_rules(cpuid, 'e')
        #if a CPU PHY is being used for Service, the HT must also be
        if (cpu_info.get_ht_for_phy(cpuid) or cpu_info.get_phy_for_ht(cpuid)) not in cpus_dpdk_srv:
            cpu_info.update_violated_rules(cpuid, 'e')

    # Rule F check - service threads need two dedicated and isolated cores (1 core and HT) 
    # on the same NUMA as Forwarding threads
    # TODO confirm isolation
    if len(cpus_dpdk_ctrl) > 2:
        logging.warning("Control Threads affinity size is {} - recommended 2" .format(len(cpus_dpdk_ctrl)))
    for cpuid in cpus_dpdk_ctrl:
        #if cpuid is outside vif0 numa, mark as violation of rule E
        if cpu_info.get_numa(cpuid) != vif0_numa:
            cpu_info.update_violated_rules(cpuid, 'f')
        if (cpu_info.get_ht_for_phy(cpuid) or cpu_info.get_phy_for_ht(cpuid)) not in cpus_dpdk_ctrl:
            cpu_info.update_violated_rules(cpuid, 'f')


    ### UPDATE MASTER TABLE with PROC DATA
    for cpuid, d in cpu_info.data.items():
        proc = d.get('proc')
        if proc is None:
            proc = ''

        if cpuid in cpus_agent:
            proc += 'A ' #Agent
        if cpuid in cpus_dpdk_srv:
            proc += 'S ' #Service
        if cpuid in cpus_dpdk_ctrl:
            proc += 'C ' #Control
        if cpuid in cpus_dpdk_fwd:
            proc += 'P ' #Processing/Forwarding/Poll
        if cpuid in nova_cpus_list:
            proc += 'N ' #Nova

        d['proc'] = proc

    ### BUILD MASTER TABLE FOR DATA PRESENTATION

    master_table = prettytable.PrettyTable()
    out, flag = run_check_output(['hostname'])
    master_table.title = "Host: {}".format(str(out.strip()))
    # table columns are dynamic, depending on HT capability and number of NUMAs
    # base building block is per NUMA is | CPU ID (PHY) | Isolated | PROC | CPU ID (HT) | Isolated | PROC |
    for numa in cpu_info.numa_nodes:
        #numa 0 and numa 1
        phy_cpus = []
        phy_proc = []
        phy_isolated = []
        phy_vrules = []
        ht_cpus = []
        ht_proc = []
        ht_isolated = []
        ht_vrules = []
        for cpuid, d in cpu_info.data.items():
            if d['numa'] is numa:
                if d['phy']:
                    phy_cpus.append(cpuid)
                    phy_proc.append(d.get('proc')[:-1])
                    phy_isolated.append(d.get('isolated'))
                    phy_vrules.append(d.get('vrule'))
                else:
                    ht_cpus.append(cpuid)
                    ht_proc.append(d.get('proc')[:-1])
                    ht_isolated.append(d.get('isolated'))
                    ht_vrules.append(d.get('vrule'))

        s = "NUMA " + str(numa) + " - CPU ID (PHY)"
        master_table.add_column(s, phy_cpus)
        master_table.add_column("Isol.", phy_isolated)
        master_table.add_column("Proc.", phy_proc)
        master_table.add_column("V. Rules", phy_vrules)
        master_table.add_column("CPU ID (HT)", ht_cpus)
        master_table.add_column("Isol.", ht_isolated)
        master_table.add_column("Proc.", ht_proc)
        master_table.add_column("V. Rules", ht_vrules)
        
        #define a column separator for clarity
        if numa is not max(range(2)):
            master_table.add_column("*", ['*'] * len(phy_cpus))

    print(master_table)

    print("\nProcess labels:")
    for k,v in PROC_LEGEND.items():
        print('{} - {} ' .format(k,v))
    
    rules_keys = RULES.keys()
    print("\nConfiguration rules: ")
    for k in sorted(rules_keys):
        print('{} - {} ' .format(k,RULES.get(k)))


if __name__ == "__main__":
    main()




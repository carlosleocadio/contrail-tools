#!/usr/bin/env python

__author__ = "Carlos Leocadio"
__copyright__ = "Copyright (c) 2022 Carlos Leocadio"
__license__ = "MIT"
__version__ = "0.9.5"

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
import re
from collections import defaultdict
import docker

#setup log - Global
logging.basicConfig(format='%(levelname)s %(message)s')
log = logging.getLogger('vr-dpdk-cpu-affinity')


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
    parser.add_argument('-d', '--debug',
                        help="Enable debug logging",
                        action="store_const", dest="loglevel", const=logging.DEBUG,
                        default=logging.INFO)
                        
    return parser.parse_args()


def run_check_output(cmd):
    if isinstance(cmd, str):
        cmd = cmd.split() 

    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        return (out, True)
    except subprocess.CalledProcessError as e:
        log.error("Error %s exec cmd %s  " % (e, cmd))
        return (None, False)


def get_proc(proc_name):
    # type: (psutil.Process) -> psutil.Process
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


## Extract information from vif 0 output
# The fabric interface will usually be a bond of 2 Slave Interfaces
# Both slabe interfaces must belong to the same Card (PCI BUS) and
# the PCI BUS must be on the same NUMA as the Forwarding/Processing threads
# Get vif 0 output; confirm vif 0 output is present; extract slave pci info;
# get numa for each slave pci; return numa node id for slaves
def get_vif0_numa_node():
    out, flag = run_check_output('vif --get 0')
    #pci_pattern = re.compile(r'vif0\/0\s+PCI:\s(?P<pci_addr>\b(0{0,4}:\d{2}:\d{2}.\d:?\w*))', re.MULTILINE)
    slave_pattern = re.compile(r'Slave\sInterface\((?P<slave_id>\d+)\):\s(?P<pci_addr>\b(0{0,4}:\w{2}:\w{2}.\d:?\w*))', re.MULTILINE)

    # lookup for slaves info
    slave_numa_nodes = []
    match_slave_pci_addr = re.findall(slave_pattern, str(out))
    if flag and match_slave_pci_addr:
        for match_slave in match_slave_pci_addr:
            slave_pci_addr = match_slave[1]
            slave_pci_numa_node_file = ''.join(['/sys/bus/pci/devices/', slave_pci_addr ,'/numa_node']) 
            with open(slave_pci_numa_node_file) as f:
                numa_id = int(f.readlines()[0].rstrip())
                log.info("VIF 0 Slave {} - PCI {} - NUMA {} " .format(match_slave[0], match_slave[1], numa_id))
                slave_numa_nodes.append(numa_id)
    else:
        return None

    return slave_numa_nodes
        

def read_file(full_path):
    try:
        with open(full_path, 'r') as f:
            content = f.read()
    except IOError as e:
        content = None

    if content and (len(content) == 1) and (content[0] == '\n'):
        log.warning("File {} is empty" .format(full_path))
        content = None

    return content
    

def extract_nova_cpu_list(nova_conf):
    nova_cpu_pattern = re.compile(r'^vcpu_pin_set\s?=\s?(.*)', re.MULTILINE)
    nova_cpu = re.search(nova_cpu_pattern, nova_conf)
    nova_cpus_list = []
    if nova_cpu:
        nova_cpu_set_string = nova_cpu.group(1)
        nova_cpus_list = expand_range(nova_cpu_set_string)
    return nova_cpus_list
    
def extract_cpu_isol_config(file_path, regex_pattern):
    config = read_file(file_path)
    cpus_isolated = []

    if config:
        isol_pattern = re.compile(regex_pattern, re.MULTILINE)
        match_isol = re.search(isol_pattern, config)
        if match_isol:
            isolcpus_string = match_isol.group(1)
            log.info("Isolcpus configuration found in {} - {}" .format(file_path, isolcpus_string))
            cpus_isolated = expand_range(isolcpus_string)
    else:
        log.error("Unable to read {}" .format(file_path))

    return cpus_isolated


## Utility method will produce and show a table with current 
# CPU affinity for a given Process object
def show_process_affinity_table(proc_obj):
    # type: (psutil.Process) -> None
    output_table = prettytable.PrettyTable()
    output_table.field_names = ["PID/SPID", "Proc. Name", "CPU Affinity"]

    for thread in proc_obj.threads():
        p = psutil.Process(thread.id)
        output_table.add_row([thread.id, p.name(), p.cpu_affinity()])
    
    output_table.sortby = "PID/SPID"
    log.info("Current Affinity Table for Process {}\n{}" .format(proc_obj, output_table))

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
    
    # return numa id for cpuid
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

    service_cpus = None
    control_cpus = None

    args = cli_menu()

    log.setLevel(args.loglevel)
    log.info("Starting vr-dpdk-cpu-affinity.py v{} " .format(__version__))

    # TODO add validation for service_cpus and control_cpus passed as argument
    # to ensure the user is setting a valid affinity according to the rules/guidelines
    if args.service:
        service_cpus = expand_range(args.service)
        log.info("Service CPUs: {}" .format(service_cpus))

    if args.control:
        control_cpus = expand_range(args.control)
        log.info("Control CPUs: {}" .format(control_cpus))

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
    NOVA_COMP_PROC_NAME = "nova-compute"
    TUNED_PROC_NAME = "tuned"

    vr_dpdk_proc = get_proc(VR_DPDK_PROC_NAME)
    if vr_dpdk_proc:
        log.info("contrail-vrouter-dpdk PID: {}" .format(vr_dpdk_proc.pid))
        show_process_affinity_table(vr_dpdk_proc)
    else:
        log.error("Unable to detect {} process" .format(VR_DPDK_PROC_NAME))

    vr_agent_proc = get_proc(VR_AGENT_PROC_NAME)
    if vr_agent_proc:
        log.info("contrail-vrouter-agent PID: {}" .format(vr_agent_proc.pid))
        show_process_affinity_table(vr_agent_proc)
    else:
        log.error("Unable to detect {} process" .format(VR_AGENT_PROC_NAME))

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

    # Method returns a list of NUMA nodes IDs of vif 0 slave interfaces 
    vif0_numa = get_vif0_numa_node()
    if len(set(vif0_numa)) > 1:
        log.error("Both VIF 0 Slave Interfaces must belong to the same NUMA")
    else:
        vif0_numa = vif0_numa[0]
        log.info("vRouter Interface VIF 0 on NUMA Node {}" .format(vif0_numa))

    # Isolated CPU cores
    cpus_isolated = []

    # Nova CPU cores
    nova_cpus_list = []


    ## CPU isolation verification
    # In some setups Tuned is used to configure cpu-partitioning
    # allowing a set of isolated and a set of housekeeping CPUs.
    # If Tuned is not present, then assume isolation is enforced using
    # isolcpus parameter from boot args [cmdline] which will reflect
    # on /sys/devices/system/cpu/isolated

    tuned_active_profile = read_file('/etc/tuned/active_profile')
    
    if tuned_active_profile and 'cpu-partitioning' in tuned_active_profile:
        cpus_isolated = extract_cpu_isol_config('/etc/tuned/cpu-partitioning-variables.conf', r'^isolated_cores=(.*)')
    else:
        cpus_isolated_file = read_file('/sys/devices/system/cpu/isolated')
        if cpus_isolated_file:
            cpus_isolated = expand_range(cpus_isolated_file)
    
    
    if len(cpus_isolated) > 0:
        log.debug("Isolated CPUs List {} " .format(cpus_isolated))
        if max(cpus_isolated) > max(cpu_info.data.keys()):
            log.error("Error in isolated CPUs configuration - highest CPU ID doesn't exist in this setup")
        else:
            # initialize isolated attribute according to cpus_isolated list - set to False by default
            for cpuid, attrs in cpu_info.data.items():
                if cpuid in cpus_isolated: attrs['isolated'] = True
                else: attrs['isolated'] = False
    else:
        log.error("Unable to detect CPU Isolation configuration")



    ## CPU pstate needs to be disabled - check status
    # /sys/devices/system/cpu/intel_pstate/status
    # if the file is not present, then p state driver is not loaded
    # possible values of status are: passive, active and off
    pstate = read_file('/sys/devices/system/cpu/intel_pstate/status')
    if pstate and 'active' in pstate:
        log.error("Intel CPU P-State scaling driver is Active - should be disabled")
    else:
        log.info("Intel CPU P-State scaling driver status - {}" .format(pstate))


    
    ## Check no_hz and rcu_nocbs
    # /sys/devices/system/cpu/nohz_full
    # nohz_full and rcu_nocbs should match
    nohz = read_file('/sys/devices/system/cpu/nohz_full')
    #if nohz:
    #    print(nohz)
        

    #########################
    ## Get cores used by Nova Compute service from /etc/nova/nova.conf
    ## For containerized service, read configuration file inside nova-compute container
    ## If container is not present, then service runs directly on host
    ## TODO add support for k8s orchestrator 
    ## TODO add option to connect to podman instead of docker

    # Check if nova-compute service is running
    nova_proc = get_proc(NOVA_COMP_PROC_NAME)
    if nova_proc:
        log.info("nova-compute PID: {}" .format(nova_proc.pid))

        client = docker.from_env()
        containers = client.containers.list()
        nova_containerized = False
        c_name = ''
        for c in containers:
            try:
                c_name = c.attrs['Config']['Labels']['container_name']
            except KeyError:
                pass
            if 'nova_compute' in c_name:
                #found nova_compute container
                nova_containerized = True
                break

        if nova_containerized:
            out, flag = run_check_output('docker exec nova_compute cat /etc/nova/nova.conf')
        else:
            out = read_file('/etc/nova/nova.conf')


        if  nova_containerized and flag:
            nova_cpus_list = extract_nova_cpu_list(out)
        else:
            nova_cpus_list = extract_nova_cpu_list(out)

        if len(nova_cpus_list) > 0:
            log.debug("Nova vCPU List {} " .format(nova_cpus_list))
        else:
            log.error('Unable to find Nova vCPU List on configuration file')
    
    else:
        log.warning("nova-compute service not found")


    #########################


    for t in vr_agent_proc.threads():
        p = psutil.Process(t.id)
        agent_threads_affinity_lists.append(p.cpu_affinity())

    r = compare_affinity_lists(agent_threads_affinity_lists)
    if r:
        log.warning("Mismatch detected in vRouter Agent Threads affinity settings - some are using different affinity than others")

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
        log.warning("Mismatch detected in Service Threads affinity settings - some are using different affinity than others")

    cpus_dpdk_srv = merge_lists_and_extract_set(srv_threads_affinity_lists)

    # check if all control threads are having the same CPU affinity settings
    r = compare_affinity_lists(ctrl_threads_affinity_lists)
    if r:
        log.warning("Mismatch detected in Control Threads affinity settings - some are using different affinity than others")

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
        log.warning("Service Threads affinity size is {} - recommended 2" .format(len(cpus_dpdk_srv)))
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
        log.warning("Control Threads affinity size is {} - recommended 2" .format(len(cpus_dpdk_ctrl)))
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

    #### MASTER TABLE PRESENTED WITH CURRENT SETTINGS #####
    ## force exit here - the remaining code is not yet finished
    exit(1)

    ### CODE BELOW WILL ALLOW CPU AFFINITY CHANGES ON SERVICE AND CONTROL THEADS IN RUNTIME

    if service_cpus is None and control_cpus is None:
        log.info('vr-dpdk-cpu-affinity.py - Ended - no changed performed')
        exit(1)

    else:
        if service_cpus is not None:
            log.info("Changing PIDs {} - Service Threads - affinity to {}" .format(srvc_ts, service_cpus))
            for st in srvc_ts:
                log.debug("Setting Service Thread PID {} affinity to {}" .format(st.id, service_cpus))
                st.cpu_affinity(service_cpus)

        if control_cpus is not None:
            log.info("Changing PIDs {} - Control Threads - affinity to {}" .format(ctrl_ts, control_cpus))
            for ct in ctrl_ts:
                log.debug("Setting Control Thread PID {} affinity to {}" .format(ct.id, control_cpus))
                ct.cpu_affinity(control_cpus)



if __name__ == "__main__":
    main()
#!/usr/bin/env python

from subprocess import Popen, PIPE
import re
from datetime import datetime
import sys
import numpy as np
import matplotlib.pyplot as plt
import argparse
import pandas as pd
from pandas.core.frame import DataFrame
import seaborn as sns
import logging

import plot_lacp_txrx_deltas_tor

__author__      = "Carlos Leocadio"
__copyright__ = "Copyright (c) 2021 Carlos Leocadio"
__license__ = "MIT"
__version__ = "1.0.0"


def print_dataframe(df, nrows):
    pd.set_option('display.max_rows', nrows)
    print(df)
    pd.reset_option('display.max_rows')

def cli_menu():
    parser = argparse.ArgumentParser(description="Parse and plot LACP RX TX events - Timer and PMD")
    parser.add_argument("-f", "--file", type=str, default=None, required=True, help='vRouter DPDK logs to parse (required)')
    parser.add_argument("--start", type=str, default=None, required=False, help='Start date filter (optional) - format: "YYYY-MM-DD HH:MM:SS,sss"')
    parser.add_argument("--end", type=str, default=None, required=False, help='End date filter (optional) - format: "YYYY-MM-DD HH:MM:SS,sss"')
    parser.add_argument("--tor", type=str, default=None, required=False, help='Comma-separated list of ToR ppmd logs to parse and include in the plot (optional)')
    parser.add_argument("-d", "--debug", action="store_const", required=False, dest="loglevel", const=logging.DEBUG, default=logging.INFO, help='Set logging loglevel to DEBUG - default INFO')
    return parser.parse_args()


def check_dt_between_filter(start_dt, end_dt, dt):
    # this means we are not filtering entries within a specific time interval
    if start_dt is None and end_dt is None: return None

    if start_dt is not None and end_dt is not None:
        if dt >= start_dt and dt <= end_dt: return dt
        else: return None
    elif start_dt is not None and end_dt is None:
        if dt >= start_dt: return dt
        else: return None
    elif start_dt is None and end_dt is None:
        if dt <= end_dt: return dt
        else: return None
    else: return None



def main(args):

    args = cli_menu()

    logging.basicConfig(stream=sys.stdout, level=args.loglevel, format='%(message)s')
    logging.info('Starting {}' .format(sys.argv[0]))

    # counter for the total number of lines read
    lines_counter = 0

    enable_tor_parser = True

    # enable date range filtering - start and end args required
    enable_dt_filtering = False

    # RX data
    # RX Bond PMD events datetime objects list - per port ID
    lacp_rx_bond_events_by_portId = {}
    lacp_rx_bond_events_by_portId[0] = []
    lacp_rx_bond_events_by_portId[1] = []
    # RX Bond PMD events deltas
    lacp_rx_bond_deltas_by_portId = {}
    lacp_rx_bond_deltas_by_portId[0] = []
    lacp_rx_bond_deltas_by_portId[1] = []
    # RX Timer events datetime objects list - per port ID
    lacp_rx_timer_events_by_portId = {}
    lacp_rx_timer_events_by_portId[0] = []
    lacp_rx_timer_events_by_portId[1] = []
    # RX Timer events deltas
    lacp_rx_timer_deltas_by_portId = {}
    lacp_rx_timer_deltas_by_portId[0] = []
    lacp_rx_timer_deltas_by_portId[1] = []

    # TX data
    # TX Bond PMD events datetime objects list - per port ID
    lacp_tx_bond_events_by_portId = {}
    lacp_tx_bond_events_by_portId[0] = []
    lacp_tx_bond_events_by_portId[1] = []
    # TX Bond PMD events deltas
    lacp_tx_bond_deltas_by_portId = {}
    lacp_tx_bond_deltas_by_portId[0] = []
    lacp_tx_bond_deltas_by_portId[1] = []
    # TX Timer events datetime objects list - per port ID
    lacp_tx_timer_events_by_portId = {}
    lacp_tx_timer_events_by_portId[0] = []
    lacp_tx_timer_events_by_portId[1] = []
    # TX Timer events deltas
    lacp_tx_timer_deltas_by_portId = {}
    lacp_tx_timer_deltas_by_portId[0] = []
    lacp_tx_timer_deltas_by_portId[1] = []

    # Rx ring failures
    rx_ring_fail_events_by_portId = {}
    rx_ring_fail_events_by_portId[0] = []
    rx_ring_fail_events_by_portId[1] = []

    # CB call delay
    cb_call_delay_events = []
    cb_call_delay_values = []

    # CB Proc delay
    cb_proc_delay_events = []
    cb_proc_delay_values = []

    #just for tests
    filename = "/Users/cleocadio/Documents/Service Requests/2021-0421-0037/NBG994_lacp_issue_july18/overcloudamg-compdpdk22hw1-2.nbg994.poc.dcn.telekom.de/containers/contrail/dpdk/contrail-vrouter-dpdk.log.6"
    #filename = "/Users/cleocadio/Documents/Service Requests/2021-0421-0037/BU_test_dpdk_random_issue_27th_July.logs"
    #filename = args.file

    if args.tor is not None:
        #tor_log_files = args.tor.split(",")
        tor_log_files = ["/Users/cleocadio/Documents/Service Requests/2021-0421-0037/CFTS-TOR_LOGS_July18_nbg994jusw1t221_222/221/ppm-ukern-log-20210718183406.txt", "/Users/cleocadio/Documents/Service Requests/2021-0421-0037/CFTS-TOR_LOGS_July18_nbg994jusw1t221_222/221/ppm-ukern-log-20210718190801.txt", "/Users/cleocadio/Documents/Service Requests/2021-0421-0037/CFTS-TOR_LOGS_July18_nbg994jusw1t221_222/221/ppm-ukern-log-20210718194157.txt"]

    # timestamp logs format
    dt_format = '%Y-%m-%d %H:%M:%S,%f'

    dt_start_filter = None
    if args.start is not None:
        try:
            dt_start_filter = datetime.strptime(args.start, dt_format)
        except ValueError:
            logging.info("ERROR: start date invalid format. Use YYYY-MM-DD HH:MM:SS,sss")
            exit(2)

    dt_end_filter = None
    if args.end is not None:
        try:
            dt_end_filter = datetime.strptime(args.end, dt_format)
        except ValueError:
            logging.info("ERROR: End date invalid format. Use YYYY-MM-DD HH:MM:SS,sss")
            exit(2)

    if args.start or args.end: enable_dt_filtering = True


    # Rx Machine Timer
    # 2021-07-26 20:25:36,422 bond_mode_8023ad_periodic_cb(1301) - LACP Rx - Timer, seq:529261 slave:0
    # 2021-07-26 20:25:36,422 bond_mode_8023ad_periodic_cb(1301) - LACP Rx - Timer, seq:529260 slave:1
    re_lacp_rx_timer = re.compile(r'(?P<datetime_str>(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2}),(\d{3}))\s+bond_mode_8023ad_periodic_cb\(\d+\)\s-\sLACP\sRx\s-\sTimer,\sseq:(?P<seq_num>(\d+))\sslave:(?P<slave_num>(\d{1}))') 
    
    # Tx Machine Timer
    # 2021-07-23 18:37:44,996 tx_machine(865) - LACP Tx - Timer, seq:853 slave:0
    # 2021-07-23 18:37:45,296 tx_machine(865) - LACP Tx - Timer, seq:854 slave:1
    re_lacp_tx_timer = re.compile(r'(?P<datetime_str>(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2}),(\d{3}))\stx_machine\(\d+\)\s-\sLACP\sTx\s-\sTimer,\sseq:(?P<seq_num>(\d+))\sslave:(?P<slave_num>(\d{1}))')
    
    # Tx Bond PMD
    # 2021-07-23 18:37:43,497 bond_ethdev_tx_burst_8023ad(1394) - LACP Tx - Bond PMD, seq:850 slave:1
    # 2021-07-23 18:37:44,097 bond_ethdev_tx_burst_8023ad(1394) - LACP Tx - Bond PMD, seq:851 slave:0
    re_lacp_tx_bond = re.compile(r'(?P<datetime_str>(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2}),(\d{3}))\sbond_ethdev_tx_burst_8023ad\(\d+\)\s-\sLACP\sTx\s-\sBond\sPMD,\sseq:(?P<seq_num>(\d+))\sslave:(?P<slave_num>(\d{1}))')
    
    # Rx Bond PMD
    # 2021-07-23 18:37:44,408 bond_mode_8023ad_handle_slow_pkt(1711) - LACP Rx - Bond PMD, seq:770 slave:1
    # 2021-07-23 18:37:44,408 bond_mode_8023ad_handle_slow_pkt(1711) - LACP Rx - Bond PMD, seq:771 slave:0
    re_lacp_rx_bond = re.compile(r'(?P<datetime_str>(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2}),(\d{3}))\sbond_mode_8023ad_handle_slow_pkt\(\d+\)\s-\sLACP\sRx\s-\sBond\sPMD,\sseq:(?P<seq_num>(\d+))\sslave:(?P<slave_num>(\d{1}))')
    
    # Rx Enqueue Ring fail
    # 2021-07-24 03:38:31,872 show_warnings(472) - Slave 0: failed to enqueue LACP packet into RX ring.
    re_rx_enq_fail = re.compile(r'(?P<datetime_str>(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2}),(\d{3}))\sshow_warnings\(\d+\)\s-\sSlave\s(?P<slave_num>(\d{1})):\sfailed\sto\senqueue\sLACP\spacket\sinto\sRX\sring.')

    # Periodic CB call delay report 
    # 2021-07-24 13:04:47,862 rte_eth_bond_8023ad_periodic_cb_call_histogram(315) - Warning: Periodic CB function called after 207ms
    re_cb_call_delay = re.compile(r'(?P<datetime_str>(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2}),(\d{3}))\srte_eth_bond_8023ad_periodic_cb_call_histogram\(\d+\)\s-\sWarning:\sPeriodic\sCB\sfunction\scalled\safter\s(?P<cb_call_delay>(\d+))ms')
    
    # Periodic CB processing time report
    # 2021-07-23 18:45:47,094 rte_eth_bond_8023ad_periodic_cb_processing_time_histogram(289) - Warning: Periodic CB processing time was 59ms
    re_cb_proc_delay = re.compile(r'(?P<datetime_str>(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2}):(\d{2}),(\d{3}))\srte_eth_bond_8023ad_periodic_cb_processing_time_histogram\(\d+\)\s-\sWarning:\sPeriodic\sCB\sprocessing\stime\swas\s(?P<cb_proc_delay>(\d+))ms')


    with open(filename) as f:
        lines = f.readlines()
        lines = [x.strip() for x in lines]

    for l in lines:
        lines_counter+=1
        #check match for Timer RX LACP
        matchRxTimer = re.match(re_lacp_rx_timer, l)
        #check match for Timer TX LACP
        matchTxTimer = re.match(re_lacp_tx_timer, l)
        #check match for PMD RX LACP
        matchRxBond = re.match(re_lacp_rx_bond, l)
        #check match for PMD TX LACP
        matchTxBond = re.match(re_lacp_tx_bond, l)
        #check match for Rx enqueue ring failure
        matchRxEnqFail = re.match(re_rx_enq_fail, l)
        #check match for CB processing delay
        matchCbProcDelay = re.match(re_cb_proc_delay, l)
        #check match for CB call delay
        matchCbCallDelay = re.match(re_cb_call_delay, l)

        if matchRxTimer is not None:
            dt_obj = datetime.strptime(matchRxTimer.group('datetime_str'), dt_format)
            if enable_dt_filtering: dt_obj = check_dt_between_filter(dt_start_filter, dt_end_filter, dt_obj)
            if dt_obj == None:
                continue
            port_id = int(matchRxTimer.group('slave_num'))

            if len(lacp_rx_timer_events_by_portId[port_id]) == 0:
                # delta is zero to start
                lacp_rx_timer_deltas_by_portId[port_id].append(dt_obj - dt_obj)
            else:
                # calculate delta between current event and previous
                lacp_rx_timer_deltas_by_portId[port_id].append(dt_obj - lacp_rx_timer_events_by_portId[port_id][-1])

            # store current event
            lacp_rx_timer_events_by_portId[port_id].append(dt_obj)
        
        elif matchRxBond is not None:
            dt_obj = datetime.strptime(matchRxBond.group('datetime_str'), dt_format)
            if enable_dt_filtering: dt_obj = check_dt_between_filter(dt_start_filter, dt_end_filter, dt_obj)
            if dt_obj == None:
                continue
            port_id = int(matchRxBond.group('slave_num'))

            if len(lacp_rx_bond_events_by_portId[port_id]) == 0:
                # delta is zero to start
                lacp_rx_bond_deltas_by_portId[port_id].append(dt_obj - dt_obj)
            else:
                # calculate delta between current event and previous
                lacp_rx_bond_deltas_by_portId[port_id].append(dt_obj - lacp_rx_bond_events_by_portId[port_id][-1])

            # store current event
            lacp_rx_bond_events_by_portId[port_id].append(dt_obj)

        elif matchTxTimer is not None:
            dt_obj = datetime.strptime(matchTxTimer.group('datetime_str'), dt_format)
            if enable_dt_filtering: dt_obj = check_dt_between_filter(dt_start_filter, dt_end_filter, dt_obj)
            if dt_obj == None:
                continue
            port_id = int(matchTxTimer.group('slave_num'))

            if len(lacp_tx_timer_events_by_portId[port_id]) == 0:
                # delta is zero to start
                lacp_tx_timer_deltas_by_portId[port_id].append(dt_obj - dt_obj)
            else:
                # calculate delta between current event and previous
                lacp_tx_timer_deltas_by_portId[port_id].append(dt_obj - lacp_tx_timer_events_by_portId[port_id][-1])

            # store current event
            lacp_tx_timer_events_by_portId[port_id].append(dt_obj)

        elif matchTxBond is not None:
            dt_obj = datetime.strptime(matchTxBond.group('datetime_str'), dt_format)
            if enable_dt_filtering: dt_obj = check_dt_between_filter(dt_start_filter, dt_end_filter, dt_obj)
            if dt_obj == None:
                continue
            port_id = int(matchTxBond.group('slave_num'))

            if len(lacp_tx_bond_events_by_portId[port_id]) == 0:
                # delta is zero to start
                lacp_tx_bond_deltas_by_portId[port_id].append(dt_obj - dt_obj)
            else:
                # calculate delta between current event and previous
                lacp_tx_bond_deltas_by_portId[port_id].append(dt_obj - lacp_tx_bond_events_by_portId[port_id][-1])

            # store current event
            lacp_tx_bond_events_by_portId[port_id].append(dt_obj)
        
        elif matchRxEnqFail is not None:
            dt_obj = datetime.strptime(matchRxEnqFail.group('datetime_str'), dt_format)
            if enable_dt_filtering: dt_obj = check_dt_between_filter(dt_start_filter, dt_end_filter, dt_obj)
            if dt_obj == None:
                continue
            port_id = int(matchRxEnqFail.group('slave_num'))
            rx_ring_fail_events_by_portId[port_id].append(dt_obj)

        elif matchCbCallDelay is not None:
            dt_obj = datetime.strptime(matchCbCallDelay.group('datetime_str'), dt_format)
            if enable_dt_filtering: dt_obj = check_dt_between_filter(dt_start_filter, dt_end_filter, dt_obj)
            if dt_obj == None:
                continue
            call_delay_ms = int(matchCbCallDelay.group('cb_call_delay'))
            cb_call_delay_events.append(dt_obj)
            cb_call_delay_values.append(np.timedelta64(call_delay_ms, 'ms'))
        
        elif matchCbProcDelay is not None:
            dt_obj = datetime.strptime(matchCbProcDelay.group('datetime_str'), dt_format)
            if enable_dt_filtering: dt_obj = check_dt_between_filter(dt_start_filter, dt_end_filter, dt_obj)
            if dt_obj == None:
                continue
            proc_delay_ms = int(matchCbProcDelay.group('cb_proc_delay'))
            cb_proc_delay_events.append(dt_obj)
            cb_proc_delay_values.append(np.timedelta64(proc_delay_ms, 'ms'))

        else:
            logging.debug("Line #{} ignored: {}" .format(lines_counter, l))

    logging.info("Parsing completed - total number of lines in file {}" .format(lines_counter))

    
    # Run ToR Switch log parser and retrieve dataframes for LACP related events
    if enable_tor_parser:
        df_tor_rx, df_tor_tx, tor_plot_title = plot_lacp_txrx_deltas_tor.main(['--file', tor_log_files[0], '--no-plot'])
        if args.loglevel == logging.DEBUG: print_dataframe(df_tor_tx, len(df_tor_tx))

    print("here!")

    # Create DataFrames
    df_rx_bond_p0 = pd.DataFrame({'Time': lacp_rx_bond_events_by_portId[0], 'Delta': lacp_rx_bond_deltas_by_portId[0]})
    df_rx_bond_p1 = pd.DataFrame({'Time': lacp_rx_bond_events_by_portId[1], 'Delta': lacp_rx_bond_deltas_by_portId[1]})

    df_rx_timer_p0 = pd.DataFrame({'Time': lacp_rx_timer_events_by_portId[0], 'Delta': lacp_rx_timer_deltas_by_portId[0]})
    df_rx_timer_p1 = pd.DataFrame({'Time': lacp_rx_timer_events_by_portId[1], 'Delta': lacp_rx_timer_deltas_by_portId[1]})

    df_tx_bond_p0 = pd.DataFrame({'Time': lacp_tx_bond_events_by_portId[0], 'Delta': lacp_tx_bond_deltas_by_portId[0]})
    df_tx_bond_p1 = pd.DataFrame({'Time': lacp_tx_bond_events_by_portId[1], 'Delta': lacp_tx_bond_deltas_by_portId[1]})

    df_tx_timer_p0 = pd.DataFrame({'Time': lacp_tx_timer_events_by_portId[0], 'Delta': lacp_tx_timer_deltas_by_portId[0]})
    df_tx_timer_p1 = pd.DataFrame({'Time': lacp_tx_timer_events_by_portId[1], 'Delta': lacp_tx_timer_deltas_by_portId[1]})

    df_cb_call_delay = pd.DataFrame({'Time': cb_call_delay_events, "CB Call Delay": cb_call_delay_values})
    df_cb_proc_delay = pd.DataFrame({'Time': cb_proc_delay_events, "CB Proc Delay": cb_proc_delay_values})

    if args.loglevel == logging.DEBUG:
        print_dataframe(df_cb_call_delay, len(df_cb_call_delay))
        print_dataframe(df_cb_proc_delay, len(df_cb_proc_delay))

    # now plot

    if enable_tor_parser:
        string_tor_logs = '\n'.join([str(elem) for elem in tor_log_files])

    if enable_tor_parser:
        full_plot_title = 'vRouter - ' + filename + '\n\nToR - ' + string_tor_logs + '\n' + tor_plot_title
    else:
        full_plot_title = 'vRouter - ' + filename

    fig, axes = plt.subplots(nrows=4+int(enable_tor_parser), ncols=2, sharex=True)
    fig.suptitle(full_plot_title, fontsize=11)
    plt.rcParams["figure.figsize"] = [32, 18]
    sns.set()

    vlines_width = 1.5

    # RX P0 plots
    ax_rx_bond_p0 = df_rx_bond_p0.plot(ax=axes[0,0], x="Time", y="Delta", title="Slave 0 Rx Bond", fontsize=11)
    ax_rx_timer_p0 = df_rx_timer_p0.plot(ax=axes[0,1], x="Time", y="Delta", title="Slave 0 Rx Timer", fontsize=11)
    for xc in rx_ring_fail_events_by_portId[0]:
        ax_rx_bond_p0.axvline(xc, color="red", linestyle="--", linewidth=vlines_width, label="Rx Enq. Fail")
        ax_rx_timer_p0.axvline(xc, color="red", linestyle="--", linewidth=vlines_width, label="Rx Enq. Fail")
    
    # RX P1 plots
    ax_rx_bond_p1 = df_rx_bond_p1.plot(ax=axes[1,0], x="Time", y="Delta", title="Slave 1 Rx Bond", fontsize=11)
    ax_rx_timer_p1 = df_rx_timer_p1.plot(ax=axes[1,1], x="Time", y="Delta", title="Slave 1 Rx Timer", fontsize=11)
    for xc in rx_ring_fail_events_by_portId[1]:
        ax_rx_bond_p1.axvline(xc, color="red", linestyle="--", linewidth=vlines_width, label="Rx Enq. Fail")
        ax_rx_timer_p1.axvline(xc, color="red", linestyle="--", linewidth=vlines_width, label="Rx Enq. Fail")

    # TX P0 plot
    ax_tx_bond_p0 = df_tx_bond_p0.plot(ax=axes[2,0], x="Time", y="Delta", title="Slave 0 Tx Bond", fontsize=11)
    ax_tx_timer_p0 = df_tx_timer_p0.plot(ax=axes[2,1], x="Time", y="Delta", title="Slave 0 Tx Timer", fontsize=11)

    # TX P1 plot
    ax_tx_bond_p1 = df_tx_bond_p1.plot(ax=axes[3,0], x="Time", y="Delta", title="Slave 1 Tx Bond", fontsize=11)
    ax_tx_timer_p1 = df_tx_timer_p1.plot(ax=axes[3,1], x="Time", y="Delta", title="Slave 1 Tx Timer", fontsize=11)

    # ToR Plots
    if enable_tor_parser:
        df_tor_tx.plot(ax=axes[4,0], x="Time", y="Delta", title="Tx ToR Events", fontsize=11)
        df_tor_rx.plot(ax=axes[4,1], x="Time", y="Delta", title="Rx ToR Events", fontsize=11)

    # CB Call and Processing delays plot - add to all subplots
    axs = [ax_rx_timer_p0, ax_rx_timer_p1, ax_rx_bond_p0, ax_rx_bond_p1, ax_tx_timer_p0, ax_tx_timer_p1, ax_tx_bond_p0, ax_tx_bond_p1]
    for x in axs:
        if not df_cb_call_delay.empty: df_cb_call_delay.plot(ax=x, x="Time", y="CB Call Delay", color='orange', style='.')
        if not df_cb_proc_delay.empty: df_cb_proc_delay.plot(ax=x, x="Time", y="CB Proc Delay", color='green', style='*')

    # set the legends correctly for all RX plots and remove duplicates
    axs = [ax_rx_bond_p0, ax_rx_timer_p0, ax_rx_bond_p1, ax_rx_timer_p1]
    for ax in axs:
        h,labels = ax.get_legend_handles_labels()
        fixed_labels = dict(zip(labels, h))
        ax.legend(fixed_labels.values(), fixed_labels.keys())
    
    plt.show()

if __name__ == "__main__":
    main(sys.argv[1:])


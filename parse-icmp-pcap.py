from pprint import pprint
from numpy import size
from scapy.all import *
from collections import defaultdict
from matplotlib import pyplot as plt
import pandas as pd
from pandas.core.frame import DataFrame
from datetime import datetime, timedelta
import seaborn as sns
import argparse
from collections import OrderedDict

__copyright__ = "Copyright (c) 2022 Carlos Leocadio"
__license__ = "MIT"
__version__ = "1.0.0"

MAX_WINDOW_MINUTES = 60


def print_dataframe(df, nrows):
    pd.set_option('display.max_rows', nrows)
    print(df)
    pd.reset_option('display.max_rows')

def round_seconds(obj: datetime) -> datetime:
    if obj.microsecond >= 500_000:
        obj += timedelta(seconds=1)
    return obj.replace(microsecond=0)


'''
Plot:
1 - The delta between consecutive ICMP Requests over time
2 - The delta between REQ and REP over time for a given ICMP Id
3 - Add Rate of REQ and REP as a new dataset with y-Axis on the right
4 - average curve
'''

## ICMP Packet Types
ICMP_ECHO_REQ = 8
ICMP_ECHO_REP = 0

def cli_menu():
    parser = argparse.ArgumentParser(description="Parse and plot ICMP REQ/REP")
    parser.add_argument("-f", "--file", type=str, default=None, required=True, help='PCAP File with ICMP packets')
    parser.add_argument("--start", type=str, default=None, required=False, help='Start date filter (optional) - format: "YYYY-MM-DD HH:MM:SS,sss"')
    parser.add_argument("--end", type=str, default=None, required=False, help='End date filter (optional) - format: "YYYY-MM-DD HH:MM:SS,sss"')
    parser.add_argument("--ipa", type=str, default=None, required=True, help='IPv4 A (request originator)')
    parser.add_argument("--ipb", type=str, default=None, required=True, help='IPv4 B (request destination)')
    
    try:
        options = parser.parse_args()
    except:
        parser.print_help()
        sys.exit(0)

    return options


def main(args):

    args = cli_menu()

    i = 0

    max_plot_window = timedelta(minutes=MAX_WINDOW_MINUTES)

    # timestamp logs format
    dt_format = '%Y-%m-%d %H:%M'

    dt_start_filter = None
    dt_end_filter = None

    if args.file:
        pcap_file = args.file

    if args.start is not None:
        try:
            dt_start_filter = datetime.strptime(args.start, dt_format)
        except ValueError:
            logging.info("ERROR: start date invalid format. Use YYYY-MM-DD HH:MM")
            exit(2)

    if args.end is not None:
        try:
            dt_end_filter = datetime.strptime(args.end, dt_format)
        except ValueError:
            logging.info("ERROR: End date invalid format. Use YYYY-MM-DD HH:MM")
            exit(2)

    if args.start or args.end: enable_dt_filtering = True
    else: enable_dt_filtering = False


    IP_A = args.ipa
    IP_B = args.ipb

    # List of IDs of missing ICMP Replies
    icmp_ids_missing_rep = []

    # List of IDs of missing ICMP Requests
    icmp_ids_missing_req = []

    # Account packets per second using an ordered dict
    req_per_second = OrderedDict()
    rep_per_second = OrderedDict()

    ## V3 dicts
    ## these dicts will use (ICMP ID, Seq #) tuple as key
    ## by using OrderedDict the capture time liniarity is kept
    icmp_requests = OrderedDict() ## key is (icmp id, icmp seq) and value is datetime obj
    icmp_replies = OrderedDict()  ## key is (icmp id, icmp seq) and value is datetime obj
    icmp_deltas = OrderedDict()   ## key is (icmp id, icmp seq) and value is delta in ms


    for p in PcapReader(pcap_file):
        icmp = p.getlayer(ICMP)
        if icmp:
            
            ip = p.getlayer(IP)
            dt_obj = datetime.fromtimestamp(p.time)
            ns_int = int(str(p.time).split('.')[1])
            ns_delta = timedelta(microseconds=ns_int)
            dt_obj = dt_obj + ns_delta

            # ignore packets captured ouside our timeframe of interest
            if enable_dt_filtering:
                if dt_obj < dt_start_filter: 
                    #print("skip: " + hex(icmp.id) + " dt = " + str(dt_obj))
                    continue
                elif dt_obj > dt_end_filter:
                    break

            print(icmp.seq)
            
            print("Pkt %d - ICMP Type %s - %s - Src: %s - Dst: %s " % (i, icmp.type, dt_obj, ip.src, ip.dst))
            # ICMP Request sent from A to B
            if icmp.type == ICMP_ECHO_REQ and ip.src == IP_A and ip.dst == IP_B:
                icmp_requests[(icmp.id, icmp.seq)] = dt_obj
                #print("REQ A->B %s at %s " % (icmp.id, dt_obj))
                
                if not req_per_second.get(round_seconds(dt_obj), None):
                    req_per_second[round_seconds(dt_obj)] = 1
                else:
                    req_per_second[round_seconds(dt_obj)] +=  1

            # ICMP Reply from B to A
            elif icmp.type == ICMP_ECHO_REP and ip.src == IP_B and ip.dst == IP_A:
                icmp_replies[(icmp.id, icmp.seq)] = dt_obj
                #print("REP B->A %s at %s " % (icmp.id, dt_obj))
                
                if not rep_per_second.get(round_seconds(dt_obj), None):
                    rep_per_second[round_seconds(dt_obj)] = 1
                else:
                    rep_per_second[round_seconds(dt_obj)] +=  1
            
            # just a counter for the number of ICMP packets in the capture
            i +=1
            #if i == 10:
            #    break

    ## end pcap parsing section
    
    # calculate delay between REQ and REP for same ID
    delays = [] # delays between REQ and REP events
    ids = [] # array of ids aligned with delays
    delay_calculation_timestamp = [] #the timestamp for the REP event
    missing_reply_timestamps = [] #the timestamp for REQ events without Reply
    missing_request_timestamps = [] # the timestamps for REP events without REQ
    out_of_order_reply_timestamps = [] # the timestamp of REP that is captured before REQ

    #now, for each request [dict key] calculate the delta to the reply
    #negative time delta is possible due to capture processing delays,
    #but will be accepted as successful ICMP REQ-REP exchange
    for k_tuple in icmp_requests.keys():
        req_time = icmp_requests.get(k_tuple)
        rep_time = icmp_replies.get(k_tuple)
        if rep_time:
            delta_ms = ( rep_time.timestamp() - req_time.timestamp() ) * 1000 #convert to ms
            icmp_deltas[k_tuple] = delta_ms
        else:
            icmp_ids_missing_rep.append(k_tuple)


    # confirm that for each reply observed, the request is present
    for k_tuple in icmp_replies.keys():
        req_time = icmp_requests.get(k_tuple)
        rep_time = icmp_replies.get(k_tuple)
        if not req_time:
            icmp_ids_missing_req.append(k_tuple)
            #no request for this reply id
            missing_request_timestamps.append(rep_time)


    pprint(icmp_requests)
    pprint(icmp_replies)
    pprint(icmp_deltas)


    print("Missing rep:", icmp_ids_missing_rep)

    print("Missing req:", icmp_ids_missing_req)




    for k_tuple in icmp_requests.keys():
        req_time = icmp_requests.get(k_tuple)
        rep_time = icmp_replies.get(k_tuple)

        if req_time and rep_time:
            delays.append(icmp_deltas.get(k_tuple))
            delay_calculation_timestamp.append(rep_time)
            ids.append(k_tuple)
        elif req_time and not rep_time:
            #no Reply for this req id
            missing_reply_timestamps.append(req_time)


    print("Missing reply timestamps: ", missing_reply_timestamps)

    print("Missing request timestamps: ", missing_request_timestamps)

    for k_tuple, d in icmp_deltas.items():
        if d < 0:
            out_of_order_reply_timestamps.append(icmp_replies.get(k_tuple))


    full_plot_title = 'ICMP Analysis Plots (A Pings B) \n' + pcap_file + "\nIP A = " + IP_A + " -> IP B = " + IP_B

    fig, axes = plt.subplots(nrows=3, ncols=1, sharex=True, gridspec_kw={'height_ratios': [2, 2, 0.5]})
    fig.suptitle(full_plot_title, fontsize=11)
    plt.rcParams["figure.figsize"] = [32, 18]
    sns.set()

    # build dataframe
    # | Timestamp | ID | Delta (ms) |
    df_data = pd.DataFrame({'Time': delay_calculation_timestamp, 'ID' : ids, 'Response Time (ms)': delays})

    print_dataframe(df_data, len(df_data))

    df_data.plot(ax=axes[0], x="Time", y="Response Time (ms)", title="Delta ICMP REQ-REP", fontsize=11)


    axes[1].plot(req_per_second.keys(), req_per_second.values(), color='green', marker='o', linestyle='dashed', linewidth=1, markersize=4, label='# REQ')
    axes[1].plot(rep_per_second.keys(), rep_per_second.values(), color='orange', marker='+', linestyle='dashed', linewidth=1, markersize=4, label='# REP')
    axes[1].grid()


    # put a vertical red line on the timestamp for a REQ with missing REP
    vlines_width = 1
    for e in missing_reply_timestamps:
        axes[2].axvline(e, color="red", linestyle="--", linewidth=vlines_width, label="Missing REP")

    # put a vertical orange line on the timestamp for a REP with missing REQ
    vlines_width = 1
    for e in missing_request_timestamps:
        axes[2].axvline(e, color="orange", linestyle="--", linewidth=vlines_width, label="Missing REQ")

    # put a vertical green line on the timestamp for out of order
    for e in out_of_order_reply_timestamps:
        axes[2].axvline(e, color="green", linestyle="--", linewidth=vlines_width, label="Out-of-order")


    # set the legends correctly for all RX plots and remove duplicates
    for ax in axes:
        h,labels = ax.get_legend_handles_labels()
        fixed_labels = dict(zip(labels, h))
        ax.legend(fixed_labels.values(), fixed_labels.keys())

    plt.show()

    exit(5)


if __name__ == "__main__":
    main(sys.argv[1:])


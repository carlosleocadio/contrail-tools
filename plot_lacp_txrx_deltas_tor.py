#!/usr/bin/env python

from subprocess import Popen, PIPE
import re
from datetime import datetime, timedelta
import sys
import numpy as np
import matplotlib.pyplot as plt
import argparse
import pandas as pd
import seaborn as sns
from pytz import timezone

__author__      = "Carlos Leocadio"
__copyright__ = "Copyright (c) 2021 Carlos Leocadio"
__license__ = "MIT"
__version__ = "0.9.0"


'''
Read logs from Junos QFX for LACP Tx and Rx events.
Plot the delta between two consecutive events of Tx and Rx for a given IFL id.

TX Side
[Sun Jul 18 15:09:49.421] [459110160] ppmd_lacp_send:943 ppmd_lacp_send: Sending packet on LACP PPM interface for IFL 553
DELTA
[Sun Jul 18 15:09:50.423] [459110301] ppmd_lacp_send:943 ppmd_lacp_send: Sending packet on LACP PPM interface for IFL 553


RX side
[Sun Jul 18 15:09:51.272] [459110402] ppmd_lacp_proto_receive:415 ppmd_lacp_proto_receive: absorbed LACP pkt from IFL 553
DELTA
[Sun Jul 18 15:09:52.174] [459110530] ppmd_lacp_proto_receive:415 ppmd_lacp_proto_receive: absorbed LACP pkt from IFL 553

'''

def main(args):

    parser = argparse.ArgumentParser(description="Parse LACP related events on ToR Switch - QFX")
    parser.add_argument("-f", "--file", type=lambda s: [f for f in s.split(',')], help='delimited list input - log1,log2,log3,...', default=None, required=True)
    parser.add_argument("-p", "--plot", action=argparse.BooleanOptionalAction)
    args = parser.parse_args(args)

    files_to_parse = args.file
    print(files_to_parse)

    lines_counter = 0
    lines = []

    lacp_rx_events = []
    lacp_rx_deltas = []

    lacp_tx_events = []
    lacp_tx_deltas = []

    #[Sun Jul 18 15:09:52.174]
    dt_format = '%a %b %d %H:%M:%S.%f'

    ifl_id = 576


    lacp_tx_re = re.compile(r'\[(?P<datetime_str>(\w{3})\s(\w{3})\s(\d{2})\s(\d{2}):(\d{2}):(\d{2}).(\d{3}))\]\s\[\d+]\sppmd_lacp_send:943\sppmd_lacp_send:\sSending\spacket\son\sLACP\sPPM\sinterface\sfor\sIFL\s(?P<ifl_id>\d+)')
    lacp_rx_re = re.compile(r'\[(?P<datetime_str>(\w{3})\s(\w{3})\s(\d{2})\s(\d{2}):(\d{2}):(\d{2}).(\d{3}))\]\s\[\d+\]\sppmd_lacp_proto_receive:415\sppmd_lacp_proto_receive:\sabsorbed\sLACP\spkt\sfrom\sIFL\s(?P<ifl_id>\d+)')

    #files_to_parse = ['/Users/cleocadio/Documents/Service Requests/2021-0421-0037/CFTS-TOR_LOGS_July18_nbg994jusw1t221_222/221/ppm-ukern-log-20210718031802.txt']

    #the order matters, let's keep it in order
    # files_to_parse = [
    #     #'/Users/cleocadio/Documents/Service Requests/2021-0421-0037/CFTS-TOR_LOGS_July18_nbg994jusw1t221_222/221/ppm-ukern-log-20210718180010.txt',
    #     '/Users/cleocadio/Documents/Service Requests/2021-0421-0037/CFTS-TOR_LOGS_July18_nbg994jusw1t221_222/221/ppm-ukern-log-20210718183406.txt',
    #     '/Users/cleocadio/Documents/Service Requests/2021-0421-0037/CFTS-TOR_LOGS_July18_nbg994jusw1t221_222/221/ppm-ukern-log-20210718190801.txt',
    #     '/Users/cleocadio/Documents/Service Requests/2021-0421-0037/CFTS-TOR_LOGS_July18_nbg994jusw1t221_222/221/ppm-ukern-log-20210718194157.txt',
    #     '/Users/cleocadio/Documents/Service Requests/2021-0421-0037/CFTS-TOR_LOGS_July18_nbg994jusw1t221_222/221/ppm-ukern-log-20210718201552.txt',
    #     '/Users/cleocadio/Documents/Service Requests/2021-0421-0037/CFTS-TOR_LOGS_July18_nbg994jusw1t221_222/221/ppm-ukern-log-20210718204947.txt',
    #     '/Users/cleocadio/Documents/Service Requests/2021-0421-0037/CFTS-TOR_LOGS_July18_nbg994jusw1t221_222/221/ppm-ukern-log-20210718212345.txt',
    #     '/Users/cleocadio/Documents/Service Requests/2021-0421-0037/CFTS-TOR_LOGS_July18_nbg994jusw1t221_222/221/ppm-ukern-log-20210718215740.txt',
    #     '/Users/cleocadio/Documents/Service Requests/2021-0421-0037/CFTS-TOR_LOGS_July18_nbg994jusw1t221_222/221/ppm-ukern-log-20210718223135.txt',
    #     '/Users/cleocadio/Documents/Service Requests/2021-0421-0037/CFTS-TOR_LOGS_July18_nbg994jusw1t221_222/221/ppm-ukern-log-20210718230530.txt',
    #     '/Users/cleocadio/Documents/Service Requests/2021-0421-0037/CFTS-TOR_LOGS_July18_nbg994jusw1t221_222/221/ppm-ukern-log-20210718233926.txt'
    #     #'/Users/cleocadio/Documents/Service Requests/2021-0421-0037/CFTS-TOR_LOGS_July18_nbg994jusw1t221_222/221/ppm-ukern-log-20210719001321.txt'
    # ]

    #filename = args.file
    #filename = '/Users/cleocadio/Documents/Service Requests/2021-0421-0037/CFTS-TOR_LOGS_July18_nbg994jusw1t221_222/221/ppm-ukern-log-20210718183406.txt'
    #outputname = args.imagename

    outputname = "NBG994_july26_221tor_test_07_secondtry.png"

    for filename in files_to_parse:
        print("parsing:", filename)
        with open(filename) as f:
            for line in f:
                matchRx = re.match(lacp_rx_re, line)
                matchTx = re.match(lacp_tx_re, line)

                if matchRx is not None and int(matchRx.group('ifl_id')) == ifl_id or matchTx is not None and int(matchTx.group('ifl_id')) == ifl_id:
                    if line.strip() not in lines:
                        #print("adding:", line.strip())
                        lines.append(line.strip())
                    #else:
                    #    print("duplicated:", line.strip())

    
    plot_title = 'Start: '+ lines[0] + '\n' + 'End:' + lines[-1]

    for l in lines:
        lines_counter+=1
        #check match for RX LACP
        matchRx = re.match(lacp_rx_re, l)
        #check match for TX LACP
        matchTx = re.match(lacp_tx_re, l)

        if matchRx is not None:
            #convert timestamp into datetime object
            dtime_obj = datetime.strptime(matchRx.group('datetime_str'), dt_format)

            # ISSUE: tor logs are not having year in the timestamp.
            # datetime object will always get reference to 1900 if not initialized
            # ISSUE 2: ToR logs are in UTC
            dtime_obj = dtime_obj.replace(year = 2021)
            #dtime_obj.replace(tzinfo=timezone('UTC'))
            #dtime_obj = dtime_obj.astimezone(timezone("Europe/Amsterdam"))
            dtime_obj = dtime_obj + timedelta(hours = 2)

            # only consider log entries from relevant IFL
            if int(matchRx.group('ifl_id')) == ifl_id:
                if len(lacp_rx_events) == 0:
                    lacp_rx_deltas.append(dtime_obj - dtime_obj)
                else:
                    lacp_rx_deltas.append(dtime_obj - lacp_rx_events[-1])
                lacp_rx_events.append(dtime_obj)

        elif matchTx is not None:
            #convert timestamp into datetime object
            dtime_obj = datetime.strptime(matchTx.group('datetime_str'), dt_format)
            dtime_obj = dtime_obj.replace(year = 2021)
            #dtime_obj.replace(tzinfo=timezone('UTC'))
            #dtime_obj = dtime_obj.astimezone(timezone("Europe/Amsterdam"))
            dtime_obj = dtime_obj + timedelta(hours = 2)
            
            # only consider log entries from relevant IFL
            if int(matchTx.group('ifl_id')) == ifl_id:
                if len(lacp_tx_events) == 0:
                    lacp_tx_deltas.append(dtime_obj - dtime_obj)
                else:
                    lacp_tx_deltas.append(dtime_obj - lacp_tx_events[-1])
                lacp_tx_events.append(dtime_obj)

        else:
            print("Line with unexpected content")

    print("Finished loading data from file. Total number of lines: ", lines_counter)


    # Create DataFrames
    df_rx_events = pd.DataFrame({'Time': lacp_rx_events, 'Deltas': lacp_rx_deltas})
    df_tx_events = pd.DataFrame({'Time': lacp_tx_events, 'Deltas': lacp_tx_deltas})

    # now plot
    if args.plot: 
        fig, axes = plt.subplots(nrows=2, ncols=1, sharex=True)
        fig.suptitle(plot_title, fontsize=11)
        plt.rcParams["figure.figsize"] = [32, 18]
        sns.set()

        df_rx_events.plot(ax=axes[0], x="Time", y="Deltas", title="Rx Events", fontsize=11)
        df_tx_events.plot(ax=axes[1], x="Time", y="Deltas", title="Tx Events", fontsize=11)
        plt.show()

    # return rx and tx dataframes
    return (df_rx_events, df_tx_events, plot_title)

            
if __name__ == "__main__":
    main(sys.argv[1:])


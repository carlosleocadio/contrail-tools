#!/usr/bin/env python

import matplotlib.cm as cm
import matplotlib.pyplot as plt
import pandas as pd
from datetime import datetime
import re
import argparse
import sys
import logging

__author__ = "Carlos Leocadio"
__copyright__ = "Copyright (c) 2021 Carlos Leocadio"
__license__ = "MIT"
__version__ = "0.9.1"

"""
vr-parse-dropstats.py: script to parse output from vrouter dropstats -log 0,
producing plot and formated tables.


Usage:
  vr-parse-dropstats.py -f | --file <log_file>
  vr-parse-dropstats.py -h | --help
  vr-parse-dropstats.py --version

Options:
  -f --file     Log file to parse (output from dropstats -log X)    
  -h --help     Show this screen
  --version     Show version


Notes: 
Data is parsed and stored in Pandas dataframe - df_master in the following format
Timestamp | Drop reason (must be != NULL) | CPU Core # where the drop happened.
All events recorded with drop reason NULL are ignored.
"""


def cli_menu():

    parser = argparse.ArgumentParser(
        description='vr-parse-dropstats.py: script to parse output from vrouter dropstats -log 0, \
            producing plot and formated tables.')

    parser.add_argument("-f",
                        metavar='<log_file>',
                        help="Log file to parse (output from dropstats -log 0)",
                        action="store")

    parser.add_argument(
        '-d', '--debug',
        help="Enable debug logging",
        action="store_const", dest="loglevel", const=logging.INFO,
        default=logging.INFO,
    )

    if len(sys.argv) == 1:
        parser.print_help()
        parser.exit()

    return parser.parse_args()


def main():

    args = cli_menu()

    if len(sys.argv) > 1 and args.f:
        filename = args.f

    #level=args.loglevel
    logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s')
    log = logging.getLogger('drops')
    log.setLevel(args.loglevel)

    # file content raw, line by line, only for the lines having relevant data
    file_lines = []

    # Data Frame with 3 columns - Timestamp | Drop reason (must be != NULL) | CPU Core
    df_master = pd.DataFrame()

    # dictionary of Data Frames per drop reason
    # key is drop reason, value the dataframe with events for that drop reason
    df_per_drop_reason = {}

    # key is drop reason, value data frame with count of events per second
    df_per_drop_reason_count_sec = {}

    data = []

    cpu_pattern = re.compile(r'Pkt\sDrop\sLog\sfor\sCore\s(?P<cpu>\d+)')
    tstamp_pattern = re.compile(r'sl\sno:\s\d+\s\sEpoch\sTime:\s(?P<epoch>\d+)\sLocal\sTime:(?P<ltime>(.*))')
    drop_pattern = re.compile(r'Packet\sType:\s(?P<pkttype>\d+)\s\sDrop\sreason:\s(?P<dreason>\w+)')

    # Read file line by line, and store only the lines matching one of the key patterns
    # file_lines is a list storing the relevant lines, in order - keeping the order is relevant
    count = 0
    with open(filename) as f:
        for line in f:
            match_cpu = re.search(cpu_pattern, line)
            match_tstamp = re.search(tstamp_pattern, line)
            match_drop = re.search(drop_pattern, line)
            if match_cpu or match_tstamp or match_drop:
                file_lines.append(line)
            count += 1

    log.info("File {} parsed - Total saved lines {} " .format(filename, count))

    invalid_line = 0
    for line in file_lines:
        match_cpu = re.search(cpu_pattern, line)
        match_tstamp = re.search(tstamp_pattern, line)
        match_drop = re.search(drop_pattern, line)
        if match_cpu:
            cpu = match_cpu.group('cpu')
            ltime = None
            reason = None
        elif match_tstamp:
            ltime = match_tstamp.group('ltime')
        elif match_drop:
            reason = match_drop.group('dreason')
        else:
            invalid_line += 1

        if cpu and ltime and reason:
            log.debug("CPU: {} | Time: {} | Drop Reason: {} " .format(cpu, ltime, reason))
            if reason != "NULL":
                # convert string to datetime
                dtime_obj = datetime.strptime(ltime, ' %a %b  %d %H:%M:%S %Y')
                # save entry on structure
                # | Datetime | Drop Reason | CPU ID
                data.append([dtime_obj, reason, cpu])
            # reset
            ltime = None
            reason = None

    # create master Data Frame
    df_master = pd.DataFrame(data, columns=['Time', 'Drop Reason', 'CPU ID'])
    

    # Take Drop Reason column and get drop reasons set
    drop_reasons_set = set(df_master['Drop Reason'])
    log.info("Detected drop reasons - {} "  .format(drop_reasons_set))


    # Extract one data frame per each drop reason - df_per_drop_reason['drop reason'] = data frame
    for v in drop_reasons_set:
        df_per_drop_reason[v] = df_master.loc[df_master['Drop Reason'] == v]

    # If debug is enabled, pring dataframes for each drop reason
    if args.loglevel == logging.DEBUG:
        pd.set_option('display.max_rows', len(df_master))
        log.debug(df_master)
        pd.reset_option('display.max_rows')
        for drop_r in drop_reasons_set:
            pd.set_option('display.max_rows', len(df_per_drop_reason[drop_r]))
            log.debug(df_per_drop_reason[drop_r])
            pd.reset_option('display.max_rows')


    # Create data frame for each drop reason accounting the number of events per second
    # regardless of which CPU dropped the packet
    for k, v in df_per_drop_reason.items():
        df_per_drop_reason_count_sec[k] = (v['Time']
                                           .dt.floor('S')
                                           .value_counts()
                                           .rename_axis('Time')
                                           .reset_index(name='Drop Count'))

    # Plot data frames - the data set will be the number of events per second
    # for a given drop reason
    fig, ax = plt.subplots()
    fig.suptitle("Data Source:" + filename, fontsize=8)

    for k, v in df_per_drop_reason_count_sec.items():
        log.debug("Table", k)
        log.debug(v)
        ax = v.plot(ax=ax, kind='line', x='Time', y='Drop Count', label=k)

    plt.legend(loc='best')
    plt.ylabel('Drop Count', fontsize=10)
    plt.show()


    ######
    # Plot the information Per-CPU, as it might be relevant
    # use the same logic as before
    # one sub-plot per drop reason

    # for each drop reason - extract cpuid set
    for drop_r in drop_reasons_set:
        cpu_id_set = set(df_per_drop_reason[drop_r]['CPU ID'])
        log.info("Drop reason {} - CPU ID Set {} " .format(drop_r, cpu_id_set))


        # Extract one data frame per CPU ID - df_cpuid_drop_reason['cpu id'] = data frame
        # for the current drop reason
        df_cpuid_drop_reason = {}
        for cpu in cpu_id_set:
            df_cpuid_drop_reason[cpu] = df_per_drop_reason[drop_r].loc[
                df_per_drop_reason[drop_r]['CPU ID'] == cpu]

        # Just printing - remove later
        if args.loglevel == logging.DEBUG:
            for k, v in df_cpuid_drop_reason.items():
                pd.set_option('display.max_rows', len(v))
                print(k)
                print(v)
                pd.reset_option('display.max_rows')

        # Create data frame for each drop reason accounting the number of events per second
        # per CPU
        df_cpuid_drop_reason_count_sec = {}
        for k, v in df_cpuid_drop_reason.items():
            df_cpuid_drop_reason_count_sec[k] = (v['Time']
                                                    .dt.floor('S')
                                                    .value_counts()
                                                    .rename_axis('Time')
                                                    .reset_index(name='Drop Count'))

        # Just printing - remove later
        if args.loglevel == logging.DEBUG:
            for k, v in df_cpuid_drop_reason_count_sec.items():
                print("\n")
                pd.set_option('display.max_rows', len(v))
                print(k)
                print(v)
                pd.reset_option('display.max_rows')

        # Plot data frames of Per CPU drop data - the data set will be the number of events per second
        # on a given CPU
        # a subplot per CPU, otherwise curves will overlap, making the graph difficult to read
        fig2, ax2 = plt.subplots(len(cpu_id_set), sharex=True, sharey=True)
        fig2.suptitle("Data Source:" + filename + "\n" + drop_r, fontsize=8)

        i = 0
        for k, v in df_cpuid_drop_reason_count_sec.items():
            log.debug("Drops on CPU {} " .format(k))
            log.debug(v)
            ax2[i] = v.plot(ax=ax2[i], kind='line', x='Time',
                            y='Drop Count', label=k, legend=False)
            ax2[i].set_ylabel(k, size=8)
            ax2[i].yaxis.set_label_position("right")
            i += 1

        # plt.legend(loc='best')
        plt.show()
pass

if __name__ == "__main__":
    main()

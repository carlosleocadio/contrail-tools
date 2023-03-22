#!/usr/bin/env python

import json
from dateutil import parser
from pprint import pprint
from collections import defaultdict, OrderedDict
import prettytable

__author__ = "Carlos Leocadio"
__copyright__ = "Copyright (c) 2022 Carlos Leocadio"
__license__ = "MIT"
__version__ = "1.0.0"

# EVENT TYPES
# Entering MASTER STATE - GREEN
# Transition to MASTER STATE - YELLOW
# Transition to BACKUP STATE - ORANGE
# Entering BACKUP STATE - RED

# Example Input Files:
# A: hno-msw-lb-03-l01-001-a.keepalived_full.20200915.log
# B: hno-msw-lb-03-l01-001-b.keepalived_full.20200915.log


# Return event structure ID | START | DURATION | TYPE
def get_event_structure(keepalived_logfile, node_name):
    events = []
    event_structure = {}
    index = 0
    with open(keepalived_logfile, 'r') as logfile:
        # first collect a list of all relevant events
        for line in logfile:
            json_entry = json.loads(line)
            if 'Entering' in json_entry['msg'] or 'Transition' in json_entry['msg']:
                events.append(json_entry)
                #print(data)
    
    # Create event structure ID | START | DURATION | TYPE
    # use datetime objects
    for a in events:
        index = index + 1
        if index <= len(events) - 1:
            b = events[index]
            x = parser.parse(b['ts']) - parser.parse(a['ts'])
            #print('%d ' % index, x)
            
        # determine TYPE
        if 'Entering MASTER STATE' in a['msg']:
            t = 'M'
        elif 'Entering BACKUP STATE' in a['msg']:
            t = 'B'
        elif 'Transition to MASTER STATE' in a['msg']:
            t = 'm'
        elif 'Transition to BACKUP STATE' in a['msg']:
            t = 'b'

        event_structure[index] = [node_name, parser.parse(a['ts']), x, t]

    return event_structure


def main():

    all_events = defaultdict(list)

    results_table = prettytable.PrettyTable(hrules=prettytable.ALL)
    results_table.field_names = ["Time", "Instance A", "Instance B"]

    legend_table = prettytable.PrettyTable()
    legend_table.field_names = ["Event Type", "Symbol"]
    legend_table.add_row(["Entering MASTER STATE ", "M"])
    legend_table.add_row(["Transition to MASTER STATE", "m"])
    #legend_table.add_row(["Transition to BACKUP STATE", "b"])
    legend_table.add_row(["Entering BACKUP STATE", "B"])

    a = get_event_structure('example_files/hno-msw-lb-03-l01-001-a.keepalived_full.20200915.log', 'A')

    b = get_event_structure('example_files/hno-msw-lb-03-l01-001-b.keepalived_full.20200915.log', 'B')

    # aggregate all events in a common structure
    # the key is now the timestamp datetime object
    # array format [Event ID, NODE, Event TYPE ]
    for k,v in a.items():
        event_list = [k, v[0], v[3]]
        all_events[v[1]].append(event_list)

    for k,v in b.items():
        event_list = [k, v[0], v[3]]
        all_events[v[1]].append(event_list)

    all_events_ordered = OrderedDict(sorted(all_events.items()))

    # print keys
    # create a table
    # Timestamp | A | B
    for k, v in all_events_ordered.items():
        #print("{} \n {} " .format(k , v))
        # get values related to A and B
        events_a = []
        events_b = []
        for i in v:
            if i[1] == 'A':
                events_a.append(i[2])
            elif i[1] == 'B':
                events_b.append(i[2])
        str_a = "\n".join(events_a)
        str_b = "\n".join(events_b)
        #print(str_a)
        results_table.add_row([k, str_a, str_b])
    
    print(results_table)

    print(legend_table)

    with open('example_files/keepalived_report.txt', 'w') as report:
        report.write(str(results_table))
        report.write("\n\n")
        report.write(str(legend_table))



if __name__ == "__main__":
    main()
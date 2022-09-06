from operator import length_hint
from typing import Tuple, List, Optional, Callable, TypeVar
import seaborn as sns
import pandas as pd
import matplotlib.pyplot as plt
from collections import Counter
from time import perf_counter
import argparse as ap

from scapy.config import conf
from scapy.layers.inet import IP, ICMP, UDP, TCP
from scapy.sendrecv import sr1
from scapy.all import *
import json
import plotly.graph_objects as go
import numpy as np




maxHops = 255
_DEFAULT_TIMEOUT = 5
_DEFAULT_VERBOSITY = False
num_runs = 3
_DEFAULT_RESOLVE_HOSTNAMES = True
time = []




#def _new_trace_packet(destination_ip: str, hop_n: int) -> ICMP:
#    return IP(dst=destination_ip, ttl=hop_n) / ICMP()

# Credit: https://stackoverflow.com/a/60845191/3000206
#def get_gateway_of(ip: str) -> str:
#    return conf.route.route(ip)[2]

def _find_proper_route(replies: List[ICMP]) -> Optional[Tuple[str, bool]]:
    if not replies:
        return None
    ip_isfin_pairs = [(resp[IP].src, resp[ICMP].type == 0) for resp in replies]
    found_destination = next((ip for ip, isfin in ip_isfin_pairs if isfin), None)
    selected_ip = found_destination or Counter(ip for ip, _ in ip_isfin_pairs).most_common(1)[0][0]
    return selected_ip, bool(found_destination)



def printFunc(x: str) -> None:
    print(x.ljust(10), end="", flush=True)


def _tracert_hop_row(destination_ip: str, #uga.edu
                     numbertests: int,   #3 is default
                     hop_n: int,     #4
                     #resolve_hostname: bool, 
                     best_route = [1],
                     **sr_kwargs, ) -> bool:

    packet = IP(dst=destination_ip, ttl=hop_n) / ICMP()

    replies = []
    for x in range(numbertests):
        reply = sr1(packet, **sr_kwargs)
        if reply is None:
            print('no reply')
        else:
            time.append((reply.time - packet.sent_time) * 1000)
            replies.append(reply)

    ipHopped, found_destination = _find_proper_route(replies)
    best_route.append(ipHopped)

    lister = []
    
    y = 1
    z = 0
    if found_destination:
        for i in range(len(best_route) -1):
            addingTime = 0
            minTime = time[z]                                                                  
            maxTime = time[z]

            for j in range(numbertests):
                addingTime = addingTime + time[z]
                if minTime > time[z]:
                    minTime = time[z]
                elif maxTime < time[z]:
                    maxTime = time[z]
                z = z + 1
            average = addingTime / numbertests;
            lister.append({ "avg" : average, "hop" : y, 'hosts' : best_route[y], "max" : maxTime,  "min" : minTime}) 
            y = y + 1
    
    json_data = json.dumps(lister, indent=5)
    jsonFile = open("data.json", "w")
    jsonFile.write(json_data)
    jsonFile.close()

    return found_destination



def tracert_internal(ip: str, max_hops: int = maxHops
                     , number_runs : int = num_runs) :

    for curHop in range(1, max_hops + 1):
        #printFunc(str(curHop))
        found_destination = _tracert_hop_row(ip, number_runs, curHop)
        print()
        if found_destination:
            break

    # creating boxplot
    fig = go.Figure()
    dividePlots  = 0
    print(int(len(time)/number_runs))
    for i in range(int(len(time)/number_runs)):
        plots = [];
        for j in range(number_runs):
            plots.append(time[dividePlots])
            dividePlots = dividePlots + 1
        fig.add_trace(go.Box(y= plots))

    fig.show()

def main():
    input = ap.ArgumentParser()

    input.add_argument("-t", type=str, default= 'uga.edu',
                        help="Target IP address or domain name")

    input.add_argument("-m", type=int, default= maxHops,
                        help="Maximum number of hops to search for target.")

    input.add_argument("-n", type=int, default= num_runs,
                        help="Number of times traceroute will run")
                    
    args = input.parse_args()
   #-d RUN_DELAY     Number of seconds to wait between two consecutive runs

    tracert_internal(args.t, args.m, args.n)

if __name__ == '__main__':
    main()
    

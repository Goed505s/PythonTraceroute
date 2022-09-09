from collections import Counter
import argparse as ap
from typing import Tuple, List, Optional
from scapy.layers.inet import IP, ICMP
from scapy.sendrecv import sr1
from scapy.all import *
import json
import plotly.graph_objects as go
import plotly.io as pio
import statistics
import time





maxHops = 255
run_delay = 0
num_runs = 3
output = 'data.json'
graph = 'graph.pdf'
time = []


def _find_proper_route(replies: List[ICMP]) -> Optional[Tuple[str, bool]]:
    if not replies:
        return None
    # Credit: https://stackoverflow.com/a/60845191/3000206
    ip_pairs = [(resp[IP].src, resp[ICMP].type == 0) for resp in replies]
    found_destination = next((ip for ip, isfin in ip_pairs if isfin), None)
    selected_ip = found_destination or Counter(ip for ip, _ in ip_pairs).most_common(1)[0][0]

    return selected_ip, bool(found_destination)

def _tracert_hop_row(destination_ip: str, #uga.edu
                     numbertests: int,   #3 is default
                     hop_n: int,     #4
                     #resolve_hostname: bool, 
                     output_file : str, run_delaying : int,
                     best_route = [1],
                     **sr_kwargs ) -> bool:

    packet = IP(dst=destination_ip, ttl=hop_n) / ICMP()

    replies = []
    for x in range(numbertests):
        reply = sr1(packet, **sr_kwargs)
        if reply is None:
            print('no reply')
        else:
            time.append((reply.time - packet.sent_time) * 1000)
            replies.append(reply)
        
        if run_delaying > 0:
            time.sleep(run_delaying)

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
            medianTime = time[z]
            medianArr = []
            for j in range(numbertests):
                addingTime = addingTime + time[z]
                if minTime > time[z]:
                    minTime = time[z]
                elif maxTime < time[z]:
                    maxTime = time[z]
                medianArr.append(time[z])
                z = z + 1

            medianTime =  statistics.median(medianArr)
            average = addingTime / numbertests;
            lister.append({ "avg" : average, "hop" : y, 'hosts' : best_route[y], "max" : maxTime, "med" : medianTime, "min" : minTime}) 
            y = y + 1
    
    json_data = json.dumps(lister, indent=5)
    jsonFile = open(output_file, "w")
    jsonFile.write(json_data)
    jsonFile.close()

    return found_destination



def tracert_internal(ip: str, max_hops: int = maxHops
                     , number_runs : int = num_runs, output_file : string = output, output_graph : string = graph,
                     run_delaying : int = run_delay) :

    for curHop in range(1, max_hops + 1):
        found_destination = _tracert_hop_row(ip, number_runs, curHop, output_file, run_delaying)
        if found_destination:
            break

    # creating boxplot
    fig = go.Figure()
    dividePlots  = 0
    for i in range(int(len(time)/number_runs)):
        plots = [];
        for j in range(number_runs):
            plots.append(time[dividePlots])
            dividePlots = dividePlots + 1
        fig.add_trace(go.Box(y= plots))

    fig.write_image(output_graph)



def main():
    input = ap.ArgumentParser()

    input.add_argument("-t", type=str, default= 'uga.edu',
                        help="Target IP address or domain name")

    input.add_argument("-m", type=int, default= maxHops,
                        help="Maximum number of hops to search for target.")

    input.add_argument("-n", type=int, default= num_runs,
                        help="Number of times traceroute will run")
    
    input.add_argument("-o", type=str, default= output,
                        help="Path and name of output JSON file containing the stats")

    input.add_argument("-g", type=str, default= graph,
                        help="Path and name of output PDF file containing stats graph")
       
    input.add_argument("-d", type=str, default= run_delay,
                        help="Number of seconds to wait between two consecutive runs")  
    args = input.parse_args()

    #   --test TEST_DIR  Directory containing num_runs text files, each of which

    tracert_internal(args.t, args.m, args.n, args.o, args.g)

if __name__ == '__main__':
    main()
    


from collections import Counter
import argparse as ap
from typing import Tuple, List, Optional
from scapy.layers.inet import IP, ICMP
from scapy.sendrecv import sr1
from scapy.all import *
import json
import plotly.graph_objects as go
import plotly.io as pio
import statistics




maxHops = 255
_DEFAULT_TIMEOUT = 5
_DEFAULT_VERBOSITY = False
num_runs = 3
_DEFAULT_RESOLVE_HOSTNAMES = True
output = 'data.json'
graph = 'graph.pdf'
time = []


def _find_proper_route(replies: List[ICMP]) -> Optional[Tuple[str, bool]]:
    if not replies:
        return None
    # Credit: https://stackoverflow.com/a/60845191/3000206
    ip_pairs = [(resp[IP].src, resp[ICMP].type == 0) for resp in replies]
    found_destination = next((ip for ip, isfin in ip_pairs if isfin), None)
    selected_ip = found_destination or Counter(ip for ip, _ in ip_pairs).most_common(1)[0][0]

    return selected_ip, bool(found_destination)

def _tracert_hop_row(destination_ip: str, #uga.edu
                     numbertests: int,   #3 is default
                     hop_n: int,     #4
                     #resolve_hostname: bool, 
                     output_file : str,
                     best_route = [1],
                     **sr_kwargs ) -> bool:

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
            medianTime = time[z]
            medianArr = []
            for j in range(numbertests):
                addingTime = addingTime + time[z]
                if minTime > time[z]:
                    minTime = time[z]
                elif maxTime < time[z]:
                    maxTime = time[z]
                medianArr.append(time[z])
                z = z + 1

            medianTime =  statistics.median(medianArr)
            average = addingTime / numbertests;
            lister.append({ "avg" : average, "hop" : y, 'hosts' : best_route[y], "max" : maxTime, "med" : medianTime, "min" : minTime}) 
            y = y + 1
    
    json_data = json.dumps(lister, indent=5)
    jsonFile = open(output_file, "w")
    jsonFile.write(json_data)
    jsonFile.close()

    return found_destination



def tracert_internal(ip: str, max_hops: int = maxHops
                     , number_runs : int = num_runs, output_file : string = output, output_graph : string = graph) :

    for curHop in range(1, max_hops + 1):
        found_destination = _tracert_hop_row(ip, number_runs, curHop, output_file)
        if found_destination:
            break

    # creating boxplot
    fig = go.Figure()
    dividePlots  = 0
    for i in range(int(len(time)/number_runs)):
        plots = [];
        for j in range(number_runs):
            plots.append(time[dividePlots])
            dividePlots = dividePlots + 1
        fig.add_trace(go.Box(y= plots))

    fig.write_image(output_graph)



def main():
    input = ap.ArgumentParser()

    input.add_argument("-t", type=str, default= 'uga.edu',
                        help="Target IP address or domain name")

    input.add_argument("-m", type=int, default= maxHops,
                        help="Maximum number of hops to search for target.")

    input.add_argument("-n", type=int, default= num_runs,
                        help="Number of times traceroute will run")
    
    input.add_argument("-o", type=str, default= output,
                        help="Path and name of output JSON file containing the stats")

    input.add_argument("-g", type=str, default= graph,
                        help="Path and name of output PDF file containing stats graph")
     
    args = input.parse_args()
    #-d RUN_DELAY     Number of seconds to wait between two consecutive runs
    #   --test TEST_DIR  Directory containing num_runs text files, each of which

    tracert_internal(args.t, args.m, args.n, args.o, args.g)

if __name__ == '__main__':
    main()
    

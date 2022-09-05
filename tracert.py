from operator import length_hint
from typing import Tuple, List, Optional, Callable, TypeVar
from collections import Counter
from time import perf_counter
import argparse as ap

from scapy.config import conf
from scapy.layers.inet import IP, ICMP, UDP, TCP
from scapy.sendrecv import sr1
from scapy.all import *
import json




maxHops = 255
_DEFAULT_TIMEOUT = 5
_DEFAULT_VERBOSITY = False
_DEFAULT_TESTS_PER = 3
_DEFAULT_RESOLVE_HOSTNAMES = True
#_TABLE_SPACING = 10

NO_INFO_SYM = "*"

T = TypeVar("T")



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
                     resolve_hostname: bool, 
                     best_route = [1], time = [1],
                     **sr_kwargs, ) -> bool:
   

    #target = ["172.217.17.46"]
   # host = destination_ip
    print ('Tracroute ')
    #flag = True
   # ttl=1
   # hops = []
   # while flag:
   #     ans, unans = sr(IP(dst=host,ttl=ttl)/ICMP())
   #     print(ans.sent_time)
   #     if ans.res[0][1].type == 0: # checking for  ICMP echo-reply
    #        flag = False
     #   else:
    #        hops.append(ans.res[0][1].src) # storing the src ip from ICMP error message
    #        ttl +=1
    #i = 1
    #for hop in hops:
    #    print (i, ' ', hop, '')
    #    i+=1

    #result, unans = sr(IP(dst=destination_ip, ttl=(1, 10)) / TCP(dport=53, flags="S"))
    #for snd, rcv in result:
    #    print(snd.ttl, rcv.src, snd.sent_time, rcv.time)

    #sr_kwargs.setdefault("timeout", _DEFAULT_TIMEOUT)
    #sr_kwargs.setdefault("verbose", _DEFAULT_VERBOSITY)

    packet = IP(dst=destination_ip, ttl=hop_n) / ICMP()

    #packet = _new_trace_packet(destination_ip, hop_n)
    replies = []
    for x in range(numbertests):
        reply = sr1(packet, **sr_kwargs)
        if reply is None:
            #printFunc(NO_INFO_SYM)
            print('no reply')
        else:
            #printFunc(f"{int((reply.time - packet.sent_time) * 1000)} ms")
           # print('Reply Time ', reply.time) 
           # `print('Sent Time ',packet.sent_time) 

            time.append((reply.time - packet.sent_time) * 1000)

            replies.append(reply)

    #for _ in range(n_tests):
     #   secs, reply = _time_exec(lambda: sr1(packet, **sr_kwargs))
     #   printFunc(NO_INFO_SYM if reply is None else f"{int(secs * 1000)} ms")
     #   if reply:
    #        replies.append(reply)
    #if not replies:
    #    printFunc(NO_INFO_SYM)
    #    return False
    ipHopped, found_destination = _find_proper_route(replies)
    best_route.append(ipHopped)
    #if resolve_hostname:
    ##    if isinstance(host, str):
     #       printFunc(f"{host} [{best_route}]")
     #   else:
     #       printFunc(best_route)
    #else:
    #routeHop[] = best_route;
    aList = [{"a":54, "b":87}]
    lister = []
    
    y = 1
    z = 1
    if found_destination:

        for i in range(len(best_route) -1):
            #print(y, ' ', best_route[y])
            addingTime = 0
            minTime = time[z]                                                                  
            maxTime = time[z]

            for j in range(numbertests):
               # print(time[z])
                addingTime = addingTime + time[z]
                if minTime > time[z]:
                    minTime = time[z]
                elif maxTime < time[z]:
                    maxTime = time[z]
                z = z + 1
            #print('Minimum ', minTime)
            #print('Maximum ', maxTime)
            average = addingTime / numbertests;
            #print('Average ', average)
            lister.append({ "avg" : average, "hop" : y, 'hosts' : best_route[y], "max" : maxTime,  "min" : minTime}) 
            y = y + 1
    
    json_data = json.dumps(lister, indent=5)
    jsonFile = open("data.json", "w")
    jsonFile.write(json_data)
    jsonFile.close()

    print (json_data)

    return found_destination



def tracert_internal(ip: str,
                    # n_tests_per_hop: int = _DEFAULT_TESTS_PER,
                    #resolve_hostnames: bool = _DEFAULT_RESOLVE_HOSTNAMES,
                     max_hops: int = maxHops # ,**sr_kwargs
                     ) :

    for curHop in range(1, max_hops + 1):
        #printFunc(str(curHop))
        found_destination = _tracert_hop_row(ip, 3, curHop, _DEFAULT_RESOLVE_HOSTNAMES)
        print()
        if found_destination:
            break


def main():
    input = ap.ArgumentParser()
       #input.add_argument("-d", type=float, default=_DEFAULT_TIMEOUT,
    #                    help="Wait timeout milliseconds for each reply.")

    #input.add_argument("-t", type=int, default=_DEFAULT_TESTS_PER,
    #                    help="How many per packets to send per hop.")
    
  #-t TARGET        A target domain name or IP address (required if --test 
  #                 is absent)
    #input.add_argument("-w", action="store_false", default=True,
    #                    help="Do not resolve addresses to hostnames.")

   # input.add_argument("ip")

    input.add_argument("-t", type=str, default= 'uga.edu',
                        help="Target IP address or domain name")

    input.add_argument("-m", type=int, default= maxHops,
                        help="Maximum number of hops to search for target.")

    args = input.parse_args()

   #-n nUM_RUNS      Number of times traceroute will run
   #-d RUN_DELAY     Number of seconds to wait between two consecutive runs



    #try:
    tracert_internal(args.t, args.m)
    #except KeyboardInterrupt:
    #    pass


if __name__ == '__main__':
    main()
    

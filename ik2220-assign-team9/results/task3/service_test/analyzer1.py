import os
print 'ANALYZER 1'

file = open("/var/log/resultservice.log","a")
file.write("\nIDS test for allowed packets\n")
try:
    if os.stat("62.pcap").st_size>24 and os.stat("s6-eth3.log").st_size<25:
       file.write("ARP PING test	        : PASS")
    else:
       file.write("ARP PING test        	: FAIL")
except OSError:
    file.write("Some error happened")

file.close()


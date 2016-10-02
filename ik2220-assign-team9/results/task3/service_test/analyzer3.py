import os
#print 'ANALYZER 3'

file = open("/var/log/resultservice.log","a")

try:
    if os.stat("62.pcap").st_size>24 and os.stat("63.pcap").st_size<25:
       file.write("\nHTTP PUT (allowed packet) test : PASS")
    else:
       file.write("\nHTTP PUT (allowed packet) test : FAIL")
except OSError:
    file.write("Some error happened")

file.close()


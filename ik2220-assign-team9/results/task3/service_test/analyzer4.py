import os
#print 'ANALYZER 4'

file = open("/var/log/resultservice.log","a")
file.write("\nidstest blocked packets")
try:
    if os.stat("63.pcap").st_size>24:
       file.write("\nHTTP PUT (blocked packet) test : PASS")
    else:
       file.write("\nHTTP PUT (blocked packet) test : FAIL")
except OSError:
    file.write("Some error happened")

file.close()


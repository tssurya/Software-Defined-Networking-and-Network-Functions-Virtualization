#Read pcap file and take out only HTTP packets

from StringIO import StringIO
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import scapy.all as scapy
import sys
import string

#pcap file name
file = "72.pcap"

#Print pcap to screen and capture
#Source : http://stackoverflow.com/questions/29288848/get-info-string-from-scapy-packet
try:
	capture = StringIO()
	save_stdout = sys.stdout
	sys.stdout = capture
	scapy.rdpcap(file).show()
	sys.stdout = save_stdout
except:
	print ("Error reading pcap file")

#Convert capture to string
rawoutput = capture.getvalue()
f1=open("out1.txt","w")
f1.write(rawoutput)
f1.close()

#Remove other packets
f1=open("out1.txt","r")
f2=open("out2.txt","w")
source="100.0.0.45";
type="PA" #P for POST

for line in f1 :
	index1 = line.find(source)
	index2 = line.find(type)
	if ('http' in line) and (index1 == 22) and (index2 == 57):
		f2.write(line);
f1.close()
f2.close()

#Check the sequence 40-41-42
f2=open("out2.txt","r")
result = 'PASS';
firstline = f2.readline()
previous=int(firstline[49:51]);
for line in f2:
	current=int(line[49:51]);
	if current == 40:
		if previous == 42 or previous == 40:
			previous = current;
			continue
		else:
			result='FAIL';
			break
	elif current == 41:
                if previous == 40 or previous == 41:
			previous = current;
                        continue
                else:
			result='FAIL';
               	        break
        elif current == 42:
       	        if previous == 41 or previous == 42:
			previous = current;
               	        continue
                else:
			result='FAIL';
               	        break
	else:		
		print "Error here";

f2.close()

#Print result. Return "True" if round robin works properly
file = open("/var/log/resultservice.log","a")
file.write("\n\nWWW LB round robin test : "+result)
file.close()


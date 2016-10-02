import sys
import string

file = open("/var/log/resultservice.log","w")

if 'ANSWER' in open('/var/log/servicedns.log').read():
	file.write("\n\nDNS server DIG test : PASS")
else:
	file.write("\nDNS server DIG test : FAIL")

file.close()

import sys
import string

file = open("/var/log/resultservice.log","a")

if '<html>' in open('/var/log/servicewww.log').read():
	file.write("\n\nWWW server DIG test : PASS")
else:
	file.write("\nWWW server DIG test : FAIL")

file.close()

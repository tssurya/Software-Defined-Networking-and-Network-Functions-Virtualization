#!/usr/bin/env python

import re
flag = 0
if __name__ == "__main__":
	test = open("ping.log", "r")
	for line in test:
		#print line
    		if re.match("(.*)ping(.*)",line):
			print "========================="
			print line,
		if re.match("(.*)ws1(.*)",line) or re.match("(.*)ds1(.*)",line):
#			print "hey hey"
			if re.match("(.*)h1(.*)",line) or re.match("(.*)h2(.*)",line):
				global flag
				flag = 1
#				print "hey"
			else:
				global flag
				flag = 2

		if re.match(".*()connect(.*)",line):
			print line,	
    		if re.match("(.*)packet(.*)", line):
			global flag
			work = line
			number = work.split()
			print "transmitted = ",number[0]
			print "received = ", number[3]
			if flag == 1:	
				global flag
				flag = 0
				print "packet loss percent = ", number[7]
				if number[7] == "100%":
					print "PASS"
				else:
					print "FAIL"
			elif flag == 2:
				global flag
				flag = 0
				print "packet loss percent = ", number[5]
                                if number[5] == "100%":
                                        print "PASS"
                                else:
                                        print "FAIL"

			else:
				print "packet loss percent = ", number[5]
				if number[5] == "100%":
					print "FAIL"
				else:
					print "PASS"

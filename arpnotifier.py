#!/bin/python3

import sys
import re
from datetime import datetime
from scapy.all import *
import ipaddress

print("                       _   _  __ _           	    __
                             | | (_)/ _(_)             w  c(..)o   (      
  __ _ _ __ _ __  _ __   ___ | |_ _| |_ _  ___ _ __     \__(-)    __)
 / _` | '__| '_ \| '_ \ / _ \| __| |  _| |/ _ \ '__|        /\   (
| (_| | |  | |_) | | | | (_) | |_| | | | |  __/ |   	   /(_)___)   
 \__,_|_|  | .__/|_| |_|\___/ \__|_|_| |_|\___|_|    	  w /|
           | |                                              | \
           |_|                                              m  m 	*apenotifier.py
      
      @Nicola Bottura 
      @Giuseppe D'Agostino 
      @Giorgia Lombardi
")

file="daemon.log"
syslog_list=["new activity", "new station", "flip flop", "reused old ethernet address", "bogon", "ethernet mismatch", "changed ethernet address"]
hours=[]
      
#Iterate forever on the syslog file
def cicle():
	starting_time=starting()

	while(True):
		get_syslog(starting_time)

#Search in the syslog strings that refers to a possible intruder
def get_syslog(starting_time):
	with open(file) as f_log:
		for line in f_log:
			for flag in syslog_list:
				if flag in line:				
					time=line.split(" ")[2]
					for times in hours:
						if time in times:
							closing(hours)	

					hours.append(time)

					if line_len(line) == 10:
						addr=line.split(" ")[7]
						MAC=line.split(" ")[8]
						next_frame(flag, time, addr, MAC, starting_time)
					elif line_len(line) == 9:
						addr=line.split(" ")[6]
						MAC=line.split(" ")[7]	
						next_frame(flag, time, addr, MAC, starting_time)
					elif line_len(line) == 11:
						addr=line.split(" ")[8]
						MAC=line.split(" ")[9]
						next_frame(flag, time, addr, MAC, starting_time)
					elif line_len(line) == 12:
						addr=line.split(" ")[9]
						MAC=line.split(" ")[10]
						next_frame(flag, time, addr, MAC, starting_time)

#Compute the next MAC address that I want to process
def next_frame(flag, time, addr, MAC, starting_time):
	if time > starting_time:
		starting_time=time
		send_frame(addr, MAC, flag)
	
#Send the modified ethernet frame
def send_frame(addr, MAC, flag):
	ether = Ether()
	ether.type= 0x0101
	ether.load= "Error: " + flag + " found"
	ip = IP()
	#ip.src = "100.101.0.2"
	ip.dst = addr
	icmp= ICMP()
	icmp.type = 8
	pkt= ether/ip/icmp
	send(pkt)

# Get the length of the line
def line_len(line):
	return len(line.split(" "))

# Open the file where we store the last time processed(hh:mm:ss)
def starting():
	hour_f=open("current_hour.txt", "r")
	return hour_f.read()
	
	
#Write into a file the last hour seen by the program and exit
def closing(hours):
	hour_f=open("current_hour.txt", "w")
	hour_f.write(hours[-1])
	hour_f.close()
	print("\n")
	print("Nothing new..closing")
	sys.exit()

def switch(flag):
	switcher = {
		"new activity": "Detected new activity", 
		"new station": "Detected new station",
		"flip flop": "Detected flip flop",
		"changed ethernet address": "detected changeging in ethernet address",
		"bogon": "detected bogon",
		"ethernet mismatch": "detected ethernet mismatch",
		"reused old ethernet address": "detected reusing of an old ethernet address"
	}
	return switcher.get(flag)

try:
	cicle()

except KeyboardInterrupt:
	print("\nExiting program.")
	sys.exit()

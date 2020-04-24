#!/bin/python3

import sys
import re
from datetime import datetime
from scapy.all import *
import ipaddress

welcome = """
                              _   _  __ _           	    __
                             | | (_)/ _(_)             w  c(..)o   (    
  __ _ _ __ _ __  _ __   ___ | |_ _| |_ _  ___ _ __     \__(-)    __)
 / _` | '__| '_ \| '_ \ / _ \| __| |  _| |/ _ \ '__|        /\   (
| (_| | |  | |_) | | | | (_) | |_| | | | |  __/ |   	   /(_)___)
 \__,_|_|  | .__/|_| |_|\___/ \__|_|_| |_|\___|_|    	  w /|  
           | |                                              | \  
           |_|                                              m  m    

                    *apenotifier.py

@Nicola Bottura,
@Giuseppe D'Agostino,
@Giorgia Lombardi.

"""

print(welcome)

file = "/var/log/syslog"
temp_file =  "/root/arpnotifier/current_hour.txt"
syslog_list = ["new activity", "new station", "flip flop", "reused old ethernet address",
                "ethernet mismatch", "changed ethernet address"]

# Iterate forever on the syslog file
def cicle():
    starting_time = starting()

    while(True):
        get_syslog(starting_time)

# Search in the sysslog strings that refers to a possible intruder
def get_syslog(starting_time):
    with open(file) as f_log:
        for line in f_log:
            starting_time = starting()
            for flag in syslog_list:
                if flag in line:
                    time = line.split(" ")[2]

                    if flag == "flip flop" and line_len(line) == 11:
                        MAC=line.split(" ")[8]
                        next_frame(flag, time, MAC, starting_time)
                    elif (flag == "new station" or flag == "new activity") and line_len(line) == 10:
                        MAC = line.split(" ")[8]
                        next_frame(flag, time, MAC, starting_time)
                    elif flag == "ethernet mismatch" and line_len(line) == 11:
                        MAC = line.split(" ")[8]
                        next_frame(flag, time, MAC, starting_time)
                    elif flag == "changed ethernet address" and line_len(line) == 12:
                        MAC = line.split(" ")[9]
                        next_frame(flag, time, MAC, starting_time)
                    elif flag == "reused old ethernet address" and line_len(line) == 13:
                        MAC = line.split(" ")[10]
                        next_frame(flag, time, MAC, starting_time)

# Compute the next MAC address that I want to process
def next_frame(flag, time, MAC, starting_time):
    if time > starting_time:
        starting_time = time
        send_frame(MAC, flag, time)

# Modify the ethernet frame and send it
def send_frame(MAC, flag, time):
    ether = Ether()
    ether.type = 0x0101
    ether.dst = MAC
    print(MAC)
    pkt = ether/Raw(load = "Warning: " + flag + " found with MAC: " + MAC)

    print("Sending a warning frame to: " + MAC + " - FLAG: " + flag + "\n")
    sendp(pkt, verbose=0)

    update_current_hour(time)

# Get the length of the line
def line_len(line):
    return len(line.split(" "))

# Open the file where we store the last time processed(hh:mm:ss)
def starting():
    hour_f = open(temp_file, "r")
    return hour_f.read()

# Write into a file the last hour seen by the program and exit
def update_current_hour(time):
    hour_f = open(temp_file, "w")
    hour_f.write(time)
    hour_f.close()
    print("Cursor updated")

try:
    cicle()

except KeyboardInterrupt:
    print("\nExiting program.")
    sys.exit()

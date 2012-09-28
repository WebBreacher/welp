#!/usr/bin/python
#-------------------------------------------------------------------------------
# Name:        WELP - Web Error Log Processor
# Purpose:     Scan error and access logs for known traces of scanners and then grab stats
#
# Author:      micah
#
# Created:     2012/09/23
#-------------------------------------------------------------------------------

# TODO
#
# 1 - Come up with HELP/USAGE -> import cli.app
# 2 - Implement options
#   --types (-t)
#       a - default = search for everything
#       i - IRC commands
#       m - HTTP Methods
#       s - SQLi
#       u - UserAgent Strings
#       x - XSS
# 3 - When a match is found
#   a - Create a record of the event by IP. Track all the things that IP did in that entry
#       Including: first and last times/dates seen, all attacks performed, etc.


import os,sys,re


# Constants & Variables #

# UserAgents show (in general) in Apache access.log not error.log
USER_AGENT_STRINGS = ["dirbuster", "nikto", "netsparker", "acunetix", "w3af",\
                        "burp"]

# HTTP Methods that aren't used much
HTTP_METHOD_LIST = ["head", "options", "track", "trace"]

# TODO - Search after the ? in non-RESTful URLs
SQL_COMMAND_LIST = ["select", "union", "group", "benchmark", "null", "'--",\
                    "or 1=1"]

XSS_COMMAND_LIST = ["alert", "xss", "ha.ckers.org"]

IRC_COMMAND_LIST = ["Joined channel", "Port", "BOT", "Login", "flood",\
                    "ddos", "NICK", "ECHO", "PRIVMSG", "ADMIN", "AWAY",\
                    "CONNECT", "KICK", "LIST", "MODE", "MOTD", "PING",\
                    "POMG", "QUIT", "SERVLIST", "SERVICE", "NAMES", "JOIN",\
                    "INVITE", "INFO", "TRACE", "USERHOST", "WHO", "WHOIS",\
                    "VERSION"]

# Create a SET for the attacks that we see
matches = set([])         # This will get phased out as the more-robust attacker profile is implemented
# This will be a dictionary for the attacker: ip, useragents, dates, times (first/most recent), # attacks
attacker = {'ip': '', 'event_date_first': '', 'event_date_most_recent': '', 'user_agents': '', 'num_of_attacks': ''}
line_counter = 1          # Counts the lines in the file


# Functions #

def findIt(line, line_counter, search_cat, search_strings):
    # Need to remove the "global" below and get it to work another way
    global matches, attacker

    # Break down the log_file line into components
    # TODO - Need to examine other web server logs (IIS, ColdFusion, Tomcat, ...)
    # Apache 2.x access log regex
    # 1=IP, 2=Date/Time of the activity, 3=HTTP Method, 4=URL Requested, 5=User Agent
    line_regex_split = re.search('^(\d+\.\d+\.\d+\.\d+) .*\[(\d+.*) \-\d+\] "([A-Z]{1,11}) (\/.*) HTTP.*" \d{3} \d+ ".*" "([A-Za-z].+)"', line)

    # Assign easy to understand variables
    remote_ip     = line_regex_split.group(1)
    event_date    = line_regex_split.group(2)
    http_method   = line_regex_split.group(3)
    url_requested = line_regex_split.group(4)
    user_agent    = line_regex_split.group(5)

    if search_cat == 'HTTP Method':
        # Regex for HTTP Method is the first group
        line = http_method
    elif search_cat == 'User Agent':
        # Regex for the User Agent is second group
        line = user_agent

    # Look for search_strings
    for search_string in search_strings:
        if re.search(search_string, line, re.I):
            log_entry = (search_cat, search_string)
            matches.add(log_entry)
            #print "[+] Line %s contains the %s string: %s" % (line_counter, search_cat, search_string) #DEBUG

            # Add content to the attacker array
            # If we don't have an existing entry for this IP, create one
            if remote_ip not in attacker['ip']:
                attacker['ip'] = remote_ip

            # Figure out when the events for this IP were first seen within the log
            if event_date < attacker['event_date_first']:
                attacker['event_date_first'] = event_date

            # When was the most recent event from this IP?
            if event_date > attacker['event_date_most_recent']:
                attacker['event_date_most_recent'] = event_date

            # TODO - Here we need to create a list inside the dictionary key 'user_agents'
            #if user_agent not in attacker['user_agents']:
                #attacker['user_agents'][]=user_agent


# Main Code #

# Check how many command line args were passed and provide HELP msg if not right
if len(sys.argv) == 2:
    user_log_file=sys.argv[1]
else:
    sys.exit('\n[!!] Fatal Error. You need to enter in the logfile name such as: %s logfilename\n' % sys.argv[0])


# TODO - Read in args for -t or --type and add those lists to the tests{}
# For now, make a dictionary and lets do all tests
tests = { 'User Agent': USER_AGENT_STRINGS,
          'HTTP Method': HTTP_METHOD_LIST,
          'SQLi': SQL_COMMAND_LIST,
          'XSS': XSS_COMMAND_LIST,
          'IRC': IRC_COMMAND_LIST   }

# Open the log_file (or try to)
try:
    log_file = open(user_log_file,'r').readlines()
except (IOError) :
    print "\n\n[!!]Can't read file ... Exiting."
    sys.exit(0)

# Actually start to look for stuff
print "\n[-] Analyzing the file: ", user_log_file

# Pull each line of the file then perform all analysis
for line in log_file:

    # If the log traffic is from 127.0.0.1|localhost, ignore it
    if re.search('^((127.0.0.1)|localhost)', line):
        continue

    # Cycle through each of the tests the user specified
    for key in tests:
        findIt(line, line_counter, key, tests[key])
        line_counter += 1

# Show the Results
if len(matches) == 0:
    print "[-] No strings found."

elif len(matches) > 0:
    print "[+] Found the following Categories and Strings"
    for k,v in sorted(matches):
        print "    [+] %s: %s" % (k, v)
    print "[+] Found the following IPs (and associated activity)"
    for k,v in attacker.iteritems():
        print "    [+] %s: %s" % (k, v)

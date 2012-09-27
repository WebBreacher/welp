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
# Create a SET for the information about the attacker <-- not sure this is right...just an array instead?
attacker = set([])        # This will be an array for the attacker: ip, useragents, dates, times (first/most recent), # attacks
line_counter = 1          # Counts the lines in the file


# Functions #

def findIt(line, line_counter, search_cat, search_strings):
    # Need to remove the "global" below and get it to work another way
    global matches

    # Break down the log_file line into components
    # 1=IP, 2=Date/Time of the activity, 3=HTTP Method, 4 = User Agent
    line_regex_match = re.search('^(\d+\.\d+\.\d+\.\d+) .*\[(\d+"([A-Z]{3,8}) \/.* HTTP.*" \d{3} \d+ ".*" "([A-Za-z].+)"', line)

    if search_cat == 'HTTP Method':
        # Regex for HTTP Method is the first group
        line = line_regex_match.group(1)
    elif search_cat == 'User Agent':
        # Regex for the User Agent is second group
        line = line_regex_match.group(2)

    # Look for search_strings
    for search_string in search_strings:
        if re.search(search_string, line, re.I):
            log_entry = (search_cat, search_string)
            matches.add(log_entry)

            #print "[+] Line %s contains the %s string: %s" % (line_counter, search_cat, search_string) #DEBUG


# Main Code #

# Check how many command line args were passed and provide HELP msg if not right
if len(sys.argv) == 2:
    user_log_file=sys.argv[1]
else:
    sys.exit('\n[!!] Fatal Error. You need to enter in the logfile name such as: %s logfilename\n' % sys.argv[0])


# Parse the command arguments to see if the user passed in which tests they wanted done
# TODO - read in args for -t or --type and add those lists to the tests{}
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

# Start pulling each line of the file then performs all analysis
for line in log_file:

    # If the line is from 127.0.0.1|localhost, ignore it
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

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
# 1 - Come up with HELP/USAGE
# 2 - Implement options
#   --types (-t)
#       a - default = search for everything
#       i - IRC commands
#       m - HTTP Methods
#       s - SQLi
#       u - UserAgent Strings
#       x - XSS


import os,sys,re

def findIt(HAYSTACK, COUNTER, NEEDLE_TYPE, NEEDLES):
    global performed

    # Read in line of the log file and look for all needles
    for NEEDLE in NEEDLES:
        # TODO - Use specific REGEX for the specific NEEDLE_TYPE
        if re.search(NEEDLE, HAYSTACK, re.I):
            log_entry = (NEEDLE_TYPE, NEEDLE)
            performed.add(log_entry)

            print "[+] Line %s contains the %s string: %s" % (COUNTER, NEEDLE_TYPE, NEEDLE) #DEBUG

# Check how many command line args were passed and provide HELP msg if not right
userlogfile=sys.argv[1]

# Search the correct areas of the logs for each of these (REGEXs)
# UserAgents show (in general) in Apache access.log not error.log
USER_AGENT_STRINGS = ["dirbuster", "nikto", "netsparker", "acunetix", "w3af",\
                        "burp"]

# TODO - Methods if not from 127.0.0.1 - Apache access.log
# Maybe search for stuff other than the normal get,post,put,...etc?
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


# Parse the command arguments to see if the user passed in which tests they wanted done
tests = {}
# TODO - read in args for -t or --type and add those lists to the tests{}
# For now, make a dictionary and lets do all tests
tests = { 'useragent': USER_AGENT_STRINGS,
          'httpmethods': HTTP_METHOD_LIST,
          'sqlcommands': SQL_COMMAND_LIST,
          'xsscommands': XSS_COMMAND_LIST,
          'irccommands': IRC_COMMAND_LIST   }

try:
    # Try to open the file specified
    log_file = open(userlogfile,'r').readlines()
    print "\n[!] Analyzing the file: ",userlogfile

    # Create a SET for the attacks that we see
    performed = set([])       # This will get phased out as the more-robust attacker profile is implemented
    # Create a SET for the information about the attacker <-- not sure this is right...just an array instead?
    attacker = set([])        # This will be an array for the attacker: ip, useragents, dates, times (first/most recent), # attacks
    line_counter = 0          # Counts the lines in the file


    # Start pulling each line of the file then performs all analysis
    for line in log_file:

        if 'httpmethods' in tests.keys():    # Test for HTTPMethods
            findIt(line, line_counter, "HTTP Method", tests["httpmethods"])

        if 'useragent' in tests.keys():      # Test for UserAgents
            findIt(line, line_counter, "User Agent", tests["useragent"])

        if 'sqlcommands' in tests.keys():      # Test for SQL Injection attacks
            findIt(line, line_counter, "SQLi", tests["sqlcommands"])

        if 'xsscommands' in tests.keys():      # Test for Cross Site Scripting attacks
            findIt(line, line_counter, "XSS", tests["xsscommands"])

        if 'irccommands' in tests.keys():      # Test for IRC commands
            findIt(line, line_counter, "IRC", tests["irccommands"])

	    line_counter += 1

    # Show the Results
    if len(performed) == 0:
        print "[-] No strings found."
    elif len(performed) > 0:
        print "[+] Found the following Categories and Strings"
        for k,v in sorted(performed):
	    print "    [+] %s: %s" % (k, v)

except (IOError) :
    print "\n\nCan't read file ... Exiting."
    sys.exit(0)


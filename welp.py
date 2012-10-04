#!/usr/bin/python
'''
-------------------------------------------------------------------------------
Name:        WELP - Web Error Log Processor
Purpose:     Scan error and access logs for known traces of scanners and then grab stats
Authore:     Micah Hoffman
-------------------------------------------------------------------------------
 TODO

 1 - Come up with HELP/USAGE -> import cli.app
 2 - Implement options
   --types (-t)
       a - default = search for everything
       i - IRC commands
       m - HTTP Methods
       s - SQLi
       u - UserAgent Strings
       x - XSS
 3 - Count up the number of events per IP and give stats
'''

import os, sys, re, itertools, operator


#=================================================
# Constants and Variables
#=================================================

# UserAgents show (in general) in Apache access.log not error.log - Pulled from ModSecurity modsecurity_35_scanners.data
USER_AGENT_STRINGS = [".nasl","absinthe","acunetix", "arachni","bilbo","black widow","blackwidow","brutus","bsqlbf","burp","cgichk","dirbuster","grabber","grendel-scan","havij","hydra","jaascois","metis","mozilla/4.0 (compatible)","mozilla/4.0 (compatible; msie 6.0; win32)","mozilla/5.0 sf//","n-stealth","nessus","netsparker","nikto","nmap nse","nsauditor","pangolin","paros","pmafind","python-httplib2","sql power injector","sqlmap","sqlninja","w3af","webinspect","webtrends security analyzer"]

# HTTP Methods that aren't used much
HTTP_METHOD_LIST = ["head", "options", "track", "trace"]

# TODO - Search after the ? in non-RESTful URLs
SQL_COMMAND_LIST = ["select", "union", "group", "benchmark", "null", "'--", "or 1=1"]

XSS_COMMAND_LIST = ["alert", "xss", "ha.ckers.org"]

IRC_COMMAND_LIST = ["Joined channel", "Port", "BOT", "Login", "flood", "ddos", "NICK", "ECHO", "PRIVMSG", "ADMIN", "AWAY",\
                    "CONNECT", "KICK", "LIST", "MODE", "MOTD", "PING", "POMG", "QUIT", "SERVLIST", "SERVICE", "NAMES", "JOIN",\
                    "INVITE", "INFO", "TRACE", "USERHOST", "WHO", "WHOIS", "VERSION"]

# TODO - May wish to use http://docs.python.org/library/collections.html - elements(), most_common() and others
# Create a list of dictionaries per http://www.developer.nokia.com/Community/Wiki/List_of_Dictionaries_in_Python
attacker = []

#=================================================
# Functions
#=================================================

def findIt(line, line_counter, search_cat, search_strings):

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

    # Set the spot in the log entry that we want to examine
    if search_cat == 'HTTP Method':
        line = http_method          # Regex for HTTP Method is the first group
    elif search_cat == 'User Agent':
        line = user_agent           # Regex for the User Agent is second group
    elif search_cat == 'IRC' or search_cat == 'XSS' or search_cat == 'SQLi':
        line = url_requested        # Regex should look at the URL requested

    # Look for search_strings
    for search_string in search_strings:
        if re.search(search_string, line, re.I):
            # Add content to the attacker list of dictionaries
            attacker.append({'ip': remote_ip,'user_agent': user_agent, 'event_date': event_date, 'cat': search_cat, 'string':search_string, 'line': line, 'line_number': line_counter})


def main():

    line_counter = 1          # Counts the lines in the file

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
    if len(attacker) == 0:
        print "[-] No strings found."

    elif len(attacker) > 0:
        print "[+] Found the following IPs (and associated activity)"

        attacker.sort(key=operator.itemgetter('string'))
        for event in attacker:
            print '    [+] "%s" found in IP: %s in line# %d -> %s' % (event['string'], event['ip'], event['line_number'], event['line']        )


#=================================================
# START
#=================================================

if __name__ == "__main__": main()
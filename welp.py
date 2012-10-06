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
 3 - Count up the number of events per IP and give stats
 4 - Need to parse Apache error.log
 5 - Count lines in log file then give status every 1% completed - use http://pypi.python.org/pypi/progressbar
'''

import os, sys, re, itertools, operator
from xml.dom import minidom


#=================================================
# Constants and Variables
#=================================================

# UserAgents show (in general) in Apache access.log not error.log - Pulled from ModSecurity modsecurity_35_scanners.data
USER_AGENT_STRINGS = [".nasl","absinthe","acunetix", "arachni","bilbo","black widow","blackwidow","brutus","bsqlbf","burp","cgichk","dirbuster","grabber","grendel-scan","havij","hydra","jaascois","metis","mozilla/4.0 (compatible)","mozilla/4.0 (compatible; msie 6.0; win32)","mozilla/5.0 sf//","n-stealth","nessus","netsparker","nikto","nmap nse","nsauditor","pangolin","paros","pmafind","python-httplib2","sql power injector","sqlmap","sqlninja","w3af","webinspect","webtrends security analyzer"]

# HTTP Methods that aren't used much
HTTP_METHOD_LIST = ["head", "options", "track", "trace"]

# IRC Commands - Getting many false positives with this
#IRC_COMMAND_LIST = ["Joined channel", "Port", "BOT", "Login", "flood", "ddos", "NICK", "ECHO", "PRIVMSG", "ADMIN", "AWAY",\
#                    "CONNECT", "KICK", "LIST", "MODE", "MOTD", "PING", "POMG", "QUIT", "SERVLIST", "SERVICE", "NAMES", "JOIN",\
#                    "INVITE", "INFO", "TRACE", "USERHOST", "WHO", "WHOIS", "VERSION"]

# TODO - May wish to use http://docs.python.org/library/collections.html - elements(), most_common() and others
# Create a list of dictionaries per http://www.developer.nokia.com/Community/Wiki/List_of_Dictionaries_in_Python
attacker = []
php_ids_rules = {}

#=================================================
# Functions
#=================================================

def findIt(line, line_counter, search_cat, search_strings):

    # TODO - Determine what type of log it is from regex
    log_type=2 #Hard-coded DEBUG

    # Break down the log_file line into components
    # TODO - Need to examine other web server logs (IIS, ColdFusion, Tomcat, ...)
    if log_type == 2:
        # TODO - Make this strip off/ignore the referrer if it is there
        # Apache 2.x error log is separated by []
        line_regex_split = re.search('^\[([SMTWF].*)\] \[error\] \[client (\d.*)\] (.*)(, referer.*)', line)

        # Some lines in the log we don't care about (notice, info...). Discard those lines
        if line_regex_split == None: return

        # Assign easy to understand variables
        remote_ip     = line_regex_split.group(2)
        event_date    = line_regex_split.group(1)
        error_thrown  = line_regex_split.group(3)
        user_agent    = 'Error Log. No U/A'

        # Set the spot in the log entry that we want to examine
        line = error_thrown

    else:
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

        # Look for search_strings
        for search_string in search_strings:
            if re.search(search_string, line, re.I):
                # Add content to the attacker list of dictionaries
                attacker.append({'ip': remote_ip,'user_agent': user_agent, 'event_date': event_date, 'cat': search_cat,
                'string':search_string, 'line': line, 'line_number': line_counter})

    # Look for PHP-IDS matches
    for id in php_ids_rules.keys():
        try:
            regex = re.compile(php_ids_rules[id])
        except:
            print "[!] Error compiling PHP-IDS rule %s. Skipping" % id
            continue

        if regex.search(line):
            # Add content to the attacker list of dictionaries
            attacker.append({'ip': remote_ip,'user_agent': user_agent, 'event_date': event_date, 'cat': 'PHP-IDS Rule',
            'string': id, 'line': line, 'line_number': line_counter})

def main():

    line_counter = 1          # Counts the lines in the file

    # Check how many command line args were passed and provide HELP msg if not right
    if len(sys.argv) == 2:
        user_log_file=sys.argv[1]
    else:
        sys.exit('\n[!!] Fatal Error. You need to enter in the full\
                  \n     logfile path and name such as: %s [logfilename]\n' % sys.argv[0])


    # TODO - Read in args for -t or --type and add those lists to the tests{}
    # For now, make a dictionary and lets do all tests
    tests = { 'User Agent': USER_AGENT_STRINGS, 'HTTP Method': HTTP_METHOD_LIST }

    # Open the log_file (or try to)
    try:
        log_file = open(user_log_file,'r').readlines()

    except (IOError) :
        sys.exit("\n[!!] Can't read file the logfile you entered.\
                  \n[!!] Exiting.\n")

    # Open the PHP-IDS filter file - grab most recent from https://phpids.org/
    try:
        xmldoc = minidom.parse("default_filter.xml")
    except (IOError) :
        sys.exit("\n[!!] Can't read file the PHP-IDS default_filter.xml.\
                  \n     Please get the latest file from https://phpids.org/\
                  \n     and place the XML file in the same directory as this script.\
                  \n[!!] Exiting.\n")

    # Cycle through all the PHP-IDS regexs and make a dictionary
    print "\n[-] Opened the PHP-IDS filter file and parsing the rules. "
    for filt in xmldoc.getElementsByTagName('filter'):
        id_xml = filt.getElementsByTagName('id')[0].toxml()
        id_content = id_xml.replace('<id>','').replace('</id>','')
        rule_xml = filt.getElementsByTagName('rule')[0].toxml()
        rule_content = rule_xml.replace('<rule>','').replace('</rule>','')
        rule_content = rule_content.replace("<![CDATA[", "")
        rule_content = rule_content.replace("]]>", "")
        #TODO - Grab the rule name or what it does and output that for the "string" in the ouput

        try:
            regex = re.compile(rule_content)
        except:
            print "[!] Error compiling PHP-IDS rule %s. Skipping" % id_content
            continue

        php_ids_rules[id_content] = rule_content


    # Actually start to look for stuff
    print "\n[-] Analyzing the file: ", user_log_file
    print "[-] Processing line ",

    # Pull each line of the file then perform all analysis
    for line in log_file:
        # Shows that we are actually working
        print (line_counter),

        # If the log traffic is from 127.0.0.1|localhost, ignore it
        if re.search('^((127.0.0.1)|localhost)', line):
            continue

        # Cycle through each of the tests the user specified
        for key in tests:

            findIt(line, line_counter, key, tests[key])
            line_counter += 1

            # TODO - Tell user how far into the file we are using http://pypi.python.org/pypi/progressbar


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
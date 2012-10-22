#!/usr/bin/python
'''
-------------------------------------------------------------------------------
Name:        WELP - Web Error Log Processor
Purpose:     Scan error and access logs for known traces of scanners and then grab stats
Author:      Micah Hoffman (@WebBreacher)
-------------------------------------------------------------------------------
 TODO (Overall)

 1 -
 2 -
 3 - Count up the number of events per IP and give stats
 4 -
 5 - Make output nicer looking and grouped by IP
 6 - Revise the User Agent searching - Record a set of all User Agents and post process for apps/tools
 7 -
 8 - Look for other anomalies such as known bad (RAT) strings (/w00t-w00t...)
 9 - Do analysis on the IPs found - lookup? Country?
 10- Look at the HTTP response code for success or failure and only report 2xx
 11- Look at the HTTP response code and count # of each code each IP got (34 500s....)
 12- Mod the IP field to also allow for domain names
 13- Do reverse lookup of the domain names to get IPs and stats

'''

import os, sys, re, itertools, operator
from datetime import datetime
from xml.dom import minidom
from welpcore import *


#=================================================
# Constants and Variables
#=================================================

# Pulled from ModSecurity modsecurity_35_scanners.data
USER_AGENT_STRINGS = [".nasl","absinthe","acunetix", "arachni","bilbo","black widow","blackwidow","brutus","bsqlbf","burp","cgichk","dirbuster","grabber","grendel-scan","havij","hydra","jaascois","metis","mozilla/4.0 (compatible)","mozilla/4.0 (compatible; msie 6.0; win32)","mozilla/5.0 sf//","n-stealth","nessus","netsparker","nikto","nmap nse","nsauditor","pangolin","paros","pmafind","python-httplib2","sql power injector","sqlmap","sqlninja","w3af","webinspect","webtrends security analyzer"]

HTTP_METHOD_LIST = ["head", "options", "track", "trace"]

# TODO - May wish to use http://docs.python.org/library/collections.html - elements(), most_common() and others
# Create a list of dictionaries per http://www.developer.nokia.com/Community/Wiki/List_of_Dictionaries_in_Python
attacker = [] # TODO - Change this to dictionary and make the evaluations about the attacker
php_ids_rules = {}
log = {}

#=================================================
# Functions & Classes
#=================================================

class Attacker:
    attacker_counter = 0

    def __init__(self, ip):
        self.ip = ip
        self.user_agent = set([])
        self.date_earliest_event = datetime.now()
        self.date_recent_event = datetime.now()
        Attacker.attacker_counter += 1

    def date_work(self, event_date):
        tt = datetime.strptime(event_date, "%d/%b/%Y:%H:%M:%S")
        if self.date_earliest_event > tt : self.date_earliest_event = tt
        if self.date_recent_event < tt : self.date_recent_event = tt


def rematch(line):      # Determine log type and set name/regex
    # Apache 2.x Error Log
    match = re.match("^\[[A-Z][a-z]{2} ", line)
    if match:
        log['type']="Apache2 Error"
        # TODO - Make this strip off/ignore the referrer if it is there - regex not working
        # REGEX - 1=Date/Time of the activity, 2=IP, 3=URL Requested
        log['regex']="^\[([SMTWF].*)\] \[error\] \[client (\d.*)\] (.*), referer.*"
        return log

    # Apache 2.x Access Log
    match = re.match("^\d{1,3}\.\d{1,3}\.", line)
    if match:
        log['type']="Apache2 Access"
        # REGEX - 1=IP, 2=Date/Time of the activity, 3=HTTP Method, 4=URL Requested, 5=User Agent
        log['regex']='^(\d+\.\d+\.\d+\.\d+) .*\[(\d+.*) \-\d+\] "([A-Z]{1,11}) (\/.*) HTTP.*" \d{3} \d+ ".*" "([A-Za-z].+)"'
        return

    # If we have not returned already, there is no match. Exit
    print bcolors.RED + "\n[Error] " + bcolors.ENDC + "No idea what kinda log you just submitted. Right now we only work on Apache 2.x access and error logs."
    sys.exit()


def findIt(line, line_counter, search_cat, search_strings):

    line_regex_split = re.search(log['regex'], line)

    # Some lines in the log we don't care about (notice, info...). So if we have no regex match discard those lines
    if line_regex_split == None: return

    # Break down the log_file line into components
    if log['type'] == "Apache2 Error":

        # Assign easy to understand variables
        remote_ip     = line_regex_split.group(2)
        event_date    = line_regex_split.group(1)
        error_thrown  = line_regex_split.group(3)
        user_agent    = 'Error Log. No U/A'

        # Set the spot in the log entry that we want to examine
        line = error_thrown

    elif log['type'] == "Apache2 Access":

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
            print bcolors.RED + "[Error] " + bcolors.ENDC + "Compiling PHP-IDS rule %s failed. Skipping it." % id
            continue

        if regex.search(line):
            # Add content to the attacker list of dictionaries
            attacker.append({'ip': remote_ip,'user_agent': user_agent, 'event_date': event_date, 'cat': 'PHP-IDS Rule',
            'string': id, 'line': line, 'line_number': line_counter})

def main():

    line_counter = 1          # Counts the lines in the file

    print bcolors.GREEN + "\n[Start] " + bcolors.CYAN + "Starting the WELP script. Hang on."

    # Check how many command line args were passed and provide HELP msg if not right
    if len(sys.argv) == 2:
        user_log_file=sys.argv[1]
    else:
        print bcolors.RED + "\n[Error] " + bcolors.ENDC + "You need to enter in the full logfile path and name such as: %s [logfilename]\n" % sys.argv[0]
        sys.exit()


    # TODO - Read in args for -t or --type and add those lists to the tests{}
    # For now, make a dictionary and lets do all tests
    tests = { 'User Agent': USER_AGENT_STRINGS, 'HTTP Method': HTTP_METHOD_LIST }

    # Open the log_file (or try to)
    try:
        log_file = open(user_log_file,'r').readlines()

    except (IOError) :
        print bcolors.RED + "\n[Error] " + bcolors.ENDC + "Can't read file the logfile you entered."
        sys.exit()

    # Open the PHP-IDS filter file - grab most recent from https://phpids.org/
    try:
        xmldoc = minidom.parse("default_filter.xml")
    except (IOError) :
        print bcolors.RED + "\n[Error] " + bcolors.ENDC + "Can't read file the PHP-IDS default_filter.xml. Please get the latest file from https://phpids.org/ and place the XML file in the same directory as this script.\n"
        sys.exit()

    # Cycle through all the PHP-IDS regexs and make a dictionary
    print bcolors.BLUE + "[info] " + bcolors.ENDC + "Opened the PHP-IDS filter file and parsing the rules. "
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
            print bcolors.RED + "[Error] " + bcolors.ENDC + "Compiling PHP-IDS rule %s failed. Skipping it." % id_content
            continue

        php_ids_rules[id_content] = rule_content

    # Using line 1 - see what kind of log this is
    if line_counter == 1:
        print bcolors.BLUE + "[info] " + bcolors.ENDC + "Examining the log format"
        rematch(log_file[0])
        print bcolors.GREEN + "[info] " + bcolors.ENDC + "Log format found to be %s" % log['type']

    # Actually start to look for stuff
    print bcolors.GREEN + "[info] " + bcolors.ENDC + "Analyzing the file:", user_log_file
    print bcolors.GREEN + "[info] " + bcolors.ENDC+ "There are %d lines in this log file." % len(log_file)

    # Pull each line of the file then perform all analysis
    for line in log_file:
        sys.stdout.write(bcolors.BLUE + "\r[info] " + bcolors.YELLOW + "Processing line # %d" %line_counter)
        sys.stdout.flush()

        # If the log traffic is from 127.0.0.1|localhost, ignore it
        if re.search('^((127.0.0.1)|localhost)', line): continue

        # Cycle through each of the tests the user specified
        for key in tests:
            findIt(line, line_counter, key, tests[key])

        line_counter += 1

    # Show the Results
    if len(attacker) == 0:
        print bcolors.PURPLE + "[info] " + bcolors.ENDC + "No strings found."

    elif len(attacker) > 0:
        print bcolors.YELLOW + "[FOUND] " + bcolors.ENDC + "Found the following IPs (and associated activity)"

        attacker.sort(key=operator.itemgetter('string'))
        for event in attacker:
            print bcolors.YELLOW + '    [FOUND] ' + bcolors.ENDC + '"%s" found in IP: %s in line# %d -> %s' % (event['string'], event['ip'], event['line_number'], event['line']        )


#=================================================
# START
#=================================================

if __name__ == "__main__": main()

print bcolors.GREEN + "\n[Finished] " + bcolors.CYAN + "WELP script completed. Thanks for using it.\n"
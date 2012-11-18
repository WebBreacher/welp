#!/usr/bin/python -tt
'''
-------------------------------------------------------------------------------
Name:        WELP - Web Event Log Processor
Purpose:     Scan access logs for known traces of scanners and then grab stats
Author:      Micah Hoffman (@WebBreacher)

Requirements: PHP-IDS default_filters.xml file, welpcore.py helper file.

Usage: $ python welp.py [apache_log_fileto_parse]
-------------------------------------------------------------------------------
 TODO (Overall)
 1 - Add output file flag content
 2 - Check if all IPs with events are being logged
 3 - Sort the IPs/host names of the events/attackers for output
 7 - Make output to a file
 8 - Look for other anomalies such as known bad (RAT) strings (/w00t-w00t...)
 9 - Do analysis on the IPs found - lookup? Country? maybe use other tool to do this?
 10- Look at the HTTP response code for success or failure and ignore 300s and 400s
 11- Look at the HTTP response code and count # of each code each IP got (34 500s....)
'''

import os, sys, re, itertools, operator, signal, threading, argparse
from datetime import datetime
from xml.dom import minidom
from welpcore import *


#=================================================
# Constants and Variables
#=================================================

# Pulled from ModSecurity modsecurity_35_scanners.data
USER_AGENT_STRINGS = [".nasl","absinthe","acunetix", "arachni","bilbo","black widow","blackwidow","brutus","bsqlbf","burp","cgichk","dirbuster","grabber","grendel-scan","havij","hydra","jaascois","metis","mozilla/4.0 (compatible)","mozilla/4.0 (compatible; msie 6.0; win32)","mozilla/5.0 sf//","n-stealth","nessus","netsparker","nikto","nmap nse","nsauditor","pangolin","paros","pmafind","python-httplib2","sql power injector","sqlmap","sqlninja","w3af","webinspect","webtrends security analyzer"]

HTTP_METHOD_LIST = ["options", "track", "trace"]


attacker = [] #ip,ua,date_earliest,date_recent,date_all,cats,attacks,lines
php_ids_rules = {}
log = {}
threads = []

#=================================================
# Functions & Classes
#=================================================
def word_wrap(string, width=80, ind1=0, ind2=0, prefix=''):
    """ word wrapping function from http://www.saltycrane.com/blog/2007/09/python-word-wrap-function/
        string: the string to wrap
        width: the column number to wrap at
        prefix: prefix each line with this string (goes before any indentation)
        ind1: number of characters to indent the first line
        ind2: number of characters to indent the rest of the lines
    """
    string = prefix + ind1 * " " + string
    newstring = ""
    while len(string) > width:
        # find position of nearest whitespace char to the left of "width"
        marker = width - 1
        while not string[marker].isspace():
            marker = marker - 1

        # remove line from original string and add it to the new string
        newline = string[0:marker] + "\n"
        newstring = newstring + newline
        string = prefix + ind2 * " " + string[marker + 1:]

    return newstring + string

def signal_handler(signal, frame):
    # TODO - This exits the loop line but not the application
    print bcolors.RED + '\nYou pressed Ctrl+C. Exiting.' + bcolors.ENDC
    sys.exit(1)

def rematch(line):      # Determine log type and set name/regex
    # Apache 2.x Access Log
    match = re.match("^.+\..+\..+ ", line)
    if match:
        log['type']="Apache2 Access"
        # REGEX - 1=IP/domain, 2=Date/Time of the activity, 3=HTTP Method, 4=URL Requested, 5=HTTP Response Code, 6=User Agent
        # Find specific format of Apache Log
        m = re.match('^.+\..+ .+ \[\d+.+ \-\d+\] "[A-Z]{1,11} .* HTTP.+" \d{3} \d+ ".*" ".*"', line)
        if m:
            log['regex'] = '^(.+\.[^\s]+) .+ \[(\d+.+) \-\d+\] "([A-Z]{1,11}) (\/.*) HTTP.+" (\d{3}) \d+ ".*" "(.*)"'
            return

        m = re.match('^.+\..+ .+ \[\d+.+ \-\d+\] "[A-Z]{1,11} \/.* HTTP.+" \d{3} .+ .+ ".+" ".+" ".+"', line)
        if m:
            log['regex'] = '^(.+\.[^\s]+) .+ \[(\d+.+) \-\d+\] "([A-Z]{1,11}) (\/.*) HTTP.+" (\d{3}) .+ .+ ".*" "(.+)" ".*"'
            return

    # If we have not returned already, there is no match. Exit
    print bcolors.RED + "\n[Error] " + bcolors.ENDC + "No idea what kinda log you just submitted. Right now we only work on Apache 2.x access and error logs."
    sys.exit()

def seen_ip_before(event):
    # Apache Access = 0=remote_ip,1=user_agent,2=event_date,3=search_cat+attack,4=line,5=line#,6=http response

    # Grab just the needed parts of Nikto UA
    is_ua_nikto = re.search("\((Nikto/[0-9]\.[0-9]\.[0-9])\)", event[1])
    if is_ua_nikto: event[1] = is_ua_nikto.group(1)

    for actor in attacker:
        if event[0] in actor['ip']:
            if not args.q: print bcolors.YELLOW + "[Found] Additional activity for " + bcolors.ENDC + "%s; Line# %d." % (event[0],event[5])
            actor['ua'].add(event[1])
            tt = datetime.strptime(event[2], "%d/%b/%Y:%H:%M:%S")
            actor['date_all'].add(tt)
            actor['attacks'].add(event[3])
            if actor['date_earliest'] > tt : actor['date_earliest'] = tt
            if actor['date_recent'] < tt : actor['date_recent'] = tt
            actor['lines'].add(event[5])
            if args.v:
                print bcolors.DARKCYAN + "  [verbose] Date: " + bcolors.ENDC + "%s" % event[2]
                print bcolors.DARKCYAN + "  [verbose] Attack: " + bcolors.ENDC + "%s" % event[3]
                print bcolors.DARKCYAN + "  [verbose] Match: " + bcolors.ENDC + "%s" % event[4]
                print bcolors.DARKCYAN + "  [verbose] Server HTTP Response: " + bcolors.ENDC + "%s" % event[6]
            return

    # Add new if we haven't had a match
    print bcolors.PURPLE + "[Found] Making new record for " + bcolors.ENDC + "%s; Line# %d." % (event[0],event[5])
    attacker.append({'ip': event[0],\
                     'ua': set([event[1]]),\
                     'date_earliest':datetime.strptime(event[2], "%d/%b/%Y:%H:%M:%S"),\
                     'date_recent':datetime.strptime(event[2], "%d/%b/%Y:%H:%M:%S"),\
                     'date_all':set([datetime.strptime(event[2], "%d/%b/%Y:%H:%M:%S")]),\
                     'attacks':set([event[3]]),\
                     'lines':set([event[5]])\
                     })

    if args.v:
        print bcolors.DARKCYAN + "  [verbose] Date: " + bcolors.ENDC + "%s" % event[2]
        print bcolors.DARKCYAN + "  [verbose] Attack: " + bcolors.ENDC + "%s" % event[3]
        print bcolors.DARKCYAN + "  [verbose] Match: " + bcolors.ENDC + "%s" % event[4]
        print bcolors.DARKCYAN + "  [verbose] Server HTTP Response: " + bcolors.ENDC + "%s" % event[6]

def findIt(line, line_counter, search_cat, search_strings):

    line_regex_split = re.search(log['regex'], line)

    # Some lines in the log we don't care about (notice, info...). So if we have no regex match discard those lines
    if line_regex_split == None:
        print bcolors.RED + "[Error] " + bcolors.ENDC + "Line# %d didn't match log REGEX. Skipping it." % line_counter
        return

    if log['type'] == "Apache2 Access":

        # Assign easy to understand variables
        remote_ip     = line_regex_split.group(1)
        event_date    = line_regex_split.group(2)
        http_method   = line_regex_split.group(3)
        url_requested = line_regex_split.group(4)
        http_response = line_regex_split.group(5)
        user_agent    = line_regex_split.group(6)


        # Set the spot in the log entry that we want to examine
        if search_cat == 'HTTP Method':
            line = http_method          # Regex for HTTP Method is the first group
        elif search_cat == 'User Agent':
            line = user_agent           # Regex for the User Agent is second group

        # Look for search_strings
        for search_string in search_strings:
            if re.search(search_string, line, re.I):
                # Add content to the attacker
                event = [remote_ip,user_agent,event_date,search_cat + '-' + search_string,line,line_counter,http_response]
                seen_ip_before(event)

    # Look for PHP-IDS matches
    for id in php_ids_rules.keys():
        try:
            regex = re.compile(php_ids_rules[id])
        except:
            if not args.q: print bcolors.RED + "[Error] " + bcolors.ENDC + "Compiling PHP-IDS rule %s failed. Skipping it." % id
            continue

        if regex.search(line):
            # Add content to the attacker list of dictionaries
            event = [remote_ip,user_agent,event_date,'PHP-IDS Rule -' + id, line, line_counter]
            seen_ip_before(event)

def main():

    line_counter = 1          # Counts the lines in the parsed log file
    tests = { 'User Agent': USER_AGENT_STRINGS, 'HTTP Method': HTTP_METHOD_LIST }

    # Open the log_file (or try to)
    user_log_file = args.log_file_to_parse.name
    try:
        log_file = open(user_log_file,'r').readlines()

    except (IOError) :
        print bcolors.RED + "\n[Error] " + bcolors.ENDC + "Can't read file the logfile you entered."
        sys.exit()

    # Open the PHP-IDS filter file - grab most recent from https://phpids.org/
    try:
        xmldoc = minidom.parse("default_filter.xml")
    except (IOError) :
        print bcolors.RED + "\n[Error] " + bcolors.ENDC + "Can't read file the PHP-IDS default_filter.xml.\
                                                           Please get the latest file from https://phpids.org/\
                                                           and place the XML file in the same directory as this script.\n"
        sys.exit()

    # Cycle through all the PHP-IDS regexs and make a dictionary
    if not args.q: print bcolors.BLUE + "[info] " + bcolors.ENDC + "Opened the PHP-IDS filter file and parsing the rules. "
    for filt in xmldoc.getElementsByTagName('filter'):
        descr_xml = filt.getElementsByTagName('description')[0].toxml()
        descr_content = descr_xml.replace('<description>','').replace('</description>','')
        rule_xml = filt.getElementsByTagName('rule')[0].toxml()
        rule_content = rule_xml.replace('<rule>','').replace('</rule>','')
        rule_content = rule_content.replace("<![CDATA[", "")
        rule_content = rule_content.replace("]]>", "")

        try:
            regex = re.compile(rule_content)
        except:
            if not args.q: print bcolors.RED + "[Error] " + bcolors.ENDC + "Compiling PHP-IDS rule %s failed. Skipping it." % descr_content
            continue

        php_ids_rules[descr_content] = rule_content

    # Using line 1 - see what kind of log this is
    if not args.q: print bcolors.BLUE + "[info] " + bcolors.ENDC + "Examining the log format"
    rematch(log_file[0])
    if not args.q: print bcolors.BLUE + "[info] " + bcolors.ENDC + "Log format found to be %s" % log['type']

    # Actually start to look for stuff
    if not args.q: print bcolors.BLUE + "[info] " + bcolors.ENDC + "Analyzing the file:", user_log_file

    # Pull each line of the file then perform all analysis
    for line in log_file:
        signal.signal(signal.SIGINT, signal_handler)    # Trap Ctrl-C

        # If the log traffic is from 127.0.0.1|localhost, ignore it
        if re.search('^((127.0.0.1)|localhost)', line): continue

        # Cycle through each of the tests the user specified
        # Each line from the logfile spawns a new thread
        for key in tests:
            t = threading.Thread(target=findIt, args=(line.strip(), line_counter, key, tests[key]))
            try:
                t.start()
            except:
                pass

        t.join()
        line_counter += 1

    # Show the Results
    if len(attacker) == 0:
        print bcolors.GREEN + "[info] " + bcolors.ENDC + "No security events found."

    elif len(attacker) > 0:
        print bcolors.GREEN + "\n-+-+- Found the following hosts (and associated activity) -+-+-\n" + bcolors.ENDC

        #TODO - attacker.sort(key=operator.itemgetter('string'))
        for event in attacker:
            print bcolors.RED    +    "%s :" % event['ip']
            print bcolors.YELLOW +    "   Earliest Date Seen:   %s" % event['date_earliest']
            print                     "   Earliest Recent Seen: %s" % event['date_recent']
            #TODO print                   "\tAll Dates Seen:       %s" % ", ".join(event['date_all'])
            if len(event['ua']) != 0:
                print bcolors.GREEN + "   User-Agents:\n\t- %s" % "\n\t- ".join(sorted(event['ua']))
            print bcolors.BLUE +      "   All Attacks Seen:\n\t- %s" % "\n\t- ".join(sorted(event['attacks']))
            print bcolors.PURPLE +    "   Line Numbers Where Attacks were Seen:\n\t- %s" % word_wrap(", ".join(str(x) for x in event['lines']), 79, 0, 10, "")
            print bcolors.ENDC + "---------------------------------------------------------------"


#=================================================
# START
#=================================================
print bcolors.GREEN + "\n[Start] " + bcolors.CYAN + "Starting the WELP script. Hang on." + bcolors.ENDC

# Command Line Arguments
parser = argparse.ArgumentParser(description='Scan error and access logs for known traces of scanners and then grab stats')
parser.add_argument('log_file_to_parse', type=file, help='the log file that you want parsed')
parser.add_argument('-v', action='store_true', default=False, help='Verbose output')
parser.add_argument('-q', action='store_true', default=False, help='Minimal (Quiet) output')
#TODO - parser.add_argument('-o', dest='outfile', help='Output file name [DEFAULT: stdout]')
#TODO - parser.add_argument('-f', dest='out_format', choices='htx', default='t', help='The format you want the output to be in Html, Text, Xml. [DEFAULT: T=human readable color text]')
args = parser.parse_args()

if args.q: print bcolors.BLUE + "[info] " + bcolors.ENDC + "Entering 'Quiet Mode'....shhh! Only important messages and new IPs/Hosts displayed."
if args.v: print bcolors.BLUE + "[info] " + bcolors.ENDC + "Entering 'Verbose Mode'....brace yourself for additional information."

if __name__ == "__main__": main()

print bcolors.GREEN + "\n[Finished] " + bcolors.CYAN + "WELP script completed.\n"
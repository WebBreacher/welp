#!/usr/bin/python -tt
'''
-------------------------------------------------------------------------------
Name:        WELP - Web Event Log Processor
Purpose:     Scan access logs for known traces of scanners/attack
Author:      Micah Hoffman (@WebBreacher)

Requirements: PHP-IDS default_filters.xml file, welpcore.py helper file.

Usage: $ python welp.py [apache_log_fileto_parse]
-------------------------------------------------------------------------------
 TODO (Overall)
 1 - Uncolor output going to outfile
 2 - Get XML output working
 3 - Sort the IPs/host names of the events/attackers for output
 4 - Sort the line numbers by integer value not by string
 5 - Fix the MODSEC_SQLI_REGEXs
 6 - Redo output so that all strings for each cat are on a single line (File Exts - 1, 2, 3, 4, ...)
 9 - Do analysis on the IPs found - lookup? Country? use other tool to do this?
 10 - Create run time error log for lines that don't match regex #novahackers
 11 - Parse "exclude" file for strings to ignore - known good #novahackers
 12 - Could I do a time-based analysis of hits to say "tool" v "human"? #novahackers
'''

import os, sys, re, itertools, operator, signal, threading, argparse
from datetime import datetime
from xml.dom import minidom
from welpcore import *

#=================================================
# Constants and Variables
#=================================================

attacker = [] #ip, ua, date_earliest, date_recent, date_all, cats, attacks, lines
php_ids_rules = {}
log = {}
threads = []

#=================================================
# Functions & Classes
#=================================================

def output(content):
    # Send output to the correct place
    if args.outfile:
        #TODO - Need to strip all the coloring from the output before logging.
        out_file.write(content + "\n")
    else:
        print content

def rematch(line):      # Determine log type and set name/regex
    # Apache 2.x Access Log
    match = re.match("^.+\..+\..+ ", line)
    if match:
        log['type']="Apache2 Access"
        # REGEX - 1=IP/domain, 2=Date/Time of the activity, 3=HTTP Method, 4=URL Requested, 5=HTTP Response Code, 6=User Agent
        # Find specific format of Apache Log
        m = re.match('^.+\..+ .+ \[\d+.+ \-\d+\] "[A-Za-z]+ .* [A-Z].+" \d{3} .+ ".*" ".*"', line)
        if m:
            log['regex'] = '^(.+\.[^\s]+) .+ \[(\d+.+) \-\d+\] "(.+) (.+) [A-Z].+" (\d{3}) .+ ".*" "(.*)"'
            if not args.q: output(bcolors.BLUE + "[info] " + bcolors.ENDC + "Log format found to be %s" % log['type'])
            return

        m = re.match('^.+\..+ .+ \[\d+.+ \-\d+\] "[A-Z]{1,11} \/.* [A-Z].+" \d{3} .+ .+ ".+" ".+" ".+"', line)
        if m:
            log['regex'] = '^(.+\.[^\s]+) .+ \[(\d+.+) \-\d+\] "(.+) (.+) [A-Z].+" (\d{3}) .+ .+ ".*" "(.+)" ".*"'
            if not args.q: output(bcolors.BLUE + "[info] " + bcolors.ENDC + "Log format found to be %s" % log['type'])
            return

    match = re.match("^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d \d+\.\d+\.\d+\.\d+ [A-Z].+ \/.* .+ \d+ .+ \d+\.\d+\.\d+\.\d+ .+ \d+ \d+ \d+ \d+", line)
    if match:
        log['type']="IIS 7.5"
        # Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip cs(User-Agent) sc-status sc-substatus sc-win32-status time-taken
        # REGEX - 1=Date/Time of the activity, 2=HTTP Method, 3=URL Requested, 4=IP/domain, 5=User Agent, 6=HTTP Response Code
        # Find specific format of IIS Log
        log['regex'] = '^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) \d+\.\d+\.\d+\.\d+ ([A-Z].+) (\/.*) .+ \d+ .+ (\d+\.\d+\.\d+\.\d+) (.+) (\d+) \d+ \d+ \d+'
        if not args.q: output(bcolors.BLUE + "[info] " + bcolors.ENDC + "Log format found to be %s" % log['type'])
        return

    # If we have not returned already, there is no match. Exit
    output(bcolors.RED + "\n[Error] " + bcolors.ENDC + "No idea what kinda log you just submitted. Right now we only work on Apache 2.x access and IIS 7.5 logs.")
    sys.exit()


def seen_ip_before(event):
    # event[] mapping -> 0=remote_ip,1=user_agent,2=event_date,3=search_cat,4=attack,5=line,6=line#,7=http response
    attack = event[3] + " - " + str(event[4])

    # Grab just the needed parts of Nikto UA
    is_ua_nikto = re.search("\((Nikto/[0-9]\.[0-9]\.[0-9])\)", event[1])
    if is_ua_nikto: event[1] = is_ua_nikto.group(1)

    for actor in attacker:
        if event[0] in actor['ip']:
            if not args.q and args.v: output(bcolors.YELLOW + "[Found] Additional activity for " + bcolors.ENDC + "%s; Line# %d." % (event[0],event[6]))
            if len(event[1]) > 1: actor['ua'].add(event[1])
            # We need to transform the date
            if log['type'] == 'Apache2 Access':
                tt = datetime.strptime(event[2], "%d/%b/%Y:%H:%M:%S")
            elif log['type'] == 'IIS 7.5':
                tt = datetime.strptime(event[2], "%Y-%m-%d %H:%M:%S")
            actor['date_all'].add(tt)
            actor['attacks'].add(attack) # TODO figure out how to get the single attack cat with a set of events
            if actor['date_earliest'] > tt : actor['date_earliest'] = tt
            if actor['date_recent'] < tt : actor['date_recent'] = tt
            actor['lines'].add(event[6])
            if args.v:
                output(bcolors.DARKCYAN + "  [verbose] Date: " + bcolors.ENDC + "%s" % event[2])
                output(bcolors.DARKCYAN + "  [verbose] Attack Category: " + bcolors.ENDC + "%s" % event[3])
                output(bcolors.DARKCYAN + "  [verbose] String: " + bcolors.ENDC + "%s" % event[4])
                output(bcolors.DARKCYAN + "  [verbose] Match: " + bcolors.ENDC + "%s" % event[5])
                output(bcolors.DARKCYAN + "  [verbose] Server HTTP Response: " + bcolors.ENDC + "%s" % event[7])
            return

    # Add a new entry if we do not already have an entry
    output(bcolors.PURPLE + "[Found] Making new record for " + bcolors.ENDC + "%s; Line# %d." % (event[0],event[6]))
    # We need to transform the date
    if log['type'] == 'Apache2 Access':
        tt = datetime.strptime(event[2], "%d/%b/%Y:%H:%M:%S")
    elif log['type'] == 'IIS 7.5':
        tt = datetime.strptime(event[2], "%Y-%m-%d %H:%M:%S")

    if len(event[1]) > 1:
        # TODO make this event(3) a set([dictionary ]) so set([php: #1])
        attacker.append({'ip': event[0],\
                         'ua': set([event[1]]),\
                         'date_earliest':tt,\
                         'date_recent':tt,\
                         'date_all':set([tt]),\
                         'attacks':set([attack]),\
                         'lines':set([event[6]])\
                         })
    else:
        attacker.append({'ip': event[0],\
                         'ua': set([]),\
                         'date_earliest':tt,\
                         'date_recent':tt,\
                         'date_all':set([tt]),\
                         'attacks':set([attack]),\
                         'lines':set([event[6]])\
                         })

    if args.v:
        output(bcolors.DARKCYAN + "  [verbose] Date: " + bcolors.ENDC + "%s" % event[2])
        output(bcolors.DARKCYAN + "  [verbose] Attack Category: " + bcolors.ENDC + "%s" % event[3])
        output(bcolors.DARKCYAN + "  [verbose] String: " + bcolors.ENDC + "%s" % event[4])
        output(bcolors.DARKCYAN + "  [verbose] Match: " + bcolors.ENDC + "%s" % event[5])
        output(bcolors.DARKCYAN + "  [verbose] Server HTTP Response: " + bcolors.ENDC + "%s" % event[7])


def findIt(line, line_counter, search_cat, search_strings):

    line_regex_split = re.search(log['regex'], line)

    # Assign easy to understand variables
    if log['type'] == "Apache2 Access":
        remote_ip     = line_regex_split.group(1)
        event_date    = line_regex_split.group(2)
        http_method   = line_regex_split.group(3)
        url_requested = line_regex_split.group(4)
        http_response = line_regex_split.group(5)
        user_agent    = line_regex_split.group(6)
    elif log['type'] =="IIS 7.5":
        event_date     = line_regex_split.group(1)
        http_method    = line_regex_split.group(2)
        url_requested  = line_regex_split.group(3)
        remote_ip      = line_regex_split.group(4)
        user_agent     = line_regex_split.group(5)
        http_response  = line_regex_split.group(6)

    # If the log traffic is from 127.0.0.1|localhost|nonwordchar, ignore it
    if re.match('^(127\.0\.0\.1|localhost|\W)', remote_ip):
        # TODO - Output this "line" to an error file
        output(bcolors.RED + "[Error] " + bcolors.ENDC + "Line# %d was not a viable IP/domain (%s). Skipping it." % (line_counter, remote_ip))
        return

    # If the user only wants 2xx HTTP response codes, and this is higher, don't examine the line
    if args.s and int(http_response) > 299:
        return

    # Does the entered URL have parameters on it?
    has_params = False
    if re.search('\?', url_requested):
        has_params = True
        url_pieces = url_requested.split('?') #Split the url_requested into the dir/file [0] and the params [1]

    if search_cat == 'HTTP Methods':
        if http_method not in search_strings:
            event = [remote_ip,user_agent,event_date,search_cat,http_method,line,line_counter,http_response]
            seen_ip_before(event)
    else:
        if search_cat == 'User Agents': line = user_agent
        if search_cat == 'ModSecurity XSS Strings' or search_cat == 'ModSecurity SQLi Strings' or search_cat =='Misc Strings' or search_cat =='Misc Tools' :
            if has_params:
                line = url_pieces[1]
            else:
                return
        if search_cat == 'Restricted File Extensions':
            if has_params:
                line = url_pieces[0]
            else:
                return

        # Is there any string to search? Thinking empty UserAgent
        if len(line) > 3:
            # Look for search_strings
            # Lists
            if search_cat == 'ModSecurity XSS Strings' or search_cat == 'ModSecurity SQLi Strings' :
                for string in search_strings:
                    if re.search(string, line, re.I):
                        event = [remote_ip,user_agent,event_date,search_cat,string,line,line_counter,http_response]
                        seen_ip_before(event)

            # Dictionaries
            if search_cat == 'Misc Strings' or search_cat =='Misc Tools' :
                for key in search_strings:
                    if re.search(search_strings[key], line, re.I):
                        event = [remote_ip,user_agent,event_date,search_cat,key,line,line_counter,http_response]
                        seen_ip_before(event)

    if has_params:
        if args.p:
            # Look for PHP-IDS matches
            for id in php_ids_rules.keys():
                ''' FP rules:
                       #43 Detects classic SQL injection probings 2/2,
                       #23 Detects JavaScript location/document property access and window access obfuscation'''

                if (id == 'Detects classic SQL injection probings 2/2') or\
                   (id == 'Detects JavaScript location/document property access and window access obfuscation'):
                   continue #Skip False Positive REGEXES
                try:
                    regex = re.compile(php_ids_rules[id])
                except:
                    if not args.q: output(bcolors.RED + "[Error] " + bcolors.ENDC + "Compiling PHP-IDS rule: '%s' failed. Skipping it." % id)
                    continue

                if regex.search(url_pieces[1]):
                    # Add content to the attacker list of dictionaries
                    event = [remote_ip,user_agent,event_date,'PHP-IDS Rule',id, line, line_counter,http_response]
                    seen_ip_before(event)

        # Look for SYMANTEC_REGEX matches
        for id in strings_and_regexes.SYMANTEC_REGEX.keys():
            regex = re.search(strings_and_regexes.SYMANTEC_REGEX[id], url_pieces[1], re.I)
            if regex:
                event = [remote_ip,user_agent,event_date,'SYMANTEC REGEX Rule', id, url_pieces[1], line_counter,http_response]
                seen_ip_before(event)

        if args.m:
            # Look for MODSEC_REGEX matches
            for id in strings_and_regexes.MODSEC_XSS_REGEX.keys():
                regex = re.search(strings_and_regexes.MODSEC_XSS_REGEX[id], url_pieces[1], re.I)
                if regex:
                    event = [remote_ip,user_agent,event_date,'ModSecurity XSS Regex', id, url_pieces[1], line_counter,http_response]
                    seen_ip_before(event)

            # TODO - Fix the MODSEC_SQLI_REGEXs
            #count = 1
            #for id in strings_and_regexes.MODSEC_SQLI_REGEX.keys():
            #    regex = re.search(strings_and_regexes.MODSEC_SQLI_REGEX[id], url_pieces[1], re.I)
            #    if regex:
            #        event = [remote_ip,user_agent,event_date,'ModSecurity SQLI Regex', id, url_pieces[1], line_counter,http_response]
            #        seen_ip_before(event)'''

def main():

    line_counter = 1          # Counts the lines in the parsed log file
    log['type'] = ''

    # ENABLE things to search for here.
    tests = {   'User Agents': strings_and_regexes.USER_AGENT_STRINGS,
                'HTTP Methods': strings_and_regexes.HTTP_METHODS,
                'Misc Tools': strings_and_regexes.MISC_TOOLS,
                'Restricted File Extensions': strings_and_regexes.RESTRICTED_EXT,
                'Misc Strings': strings_and_regexes.MISC_STRINGS
            }

    if args.m:
        tests['ModSecurity XSS Strings'] = strings_and_regexes.MODSEC_XSS
        tests['ModSecurity SQLi Strings'] = strings_and_regexes.MODSEC_SQLI

    # Open the log_file (or try to)
    user_log_file = args.log_file_to_parse.name
    try:
        log_file = open(user_log_file,'r').readlines()

    except (IOError) :
        output(bcolors.RED + "\n[Error] " + bcolors.ENDC + "Can't read file the logfile you entered.")
        sys.exit()

    if args.p:
        # Open the PHP-IDS filter file - grab most recent from https://phpids.org/
        try:
            xmldoc = minidom.parse("default_filter.xml")

            # Cycle through all the PHP-IDS regexs and make a dictionary
            if not args.q: output(bcolors.BLUE + "[info] " + bcolors.ENDC + "Opened the PHP-IDS filter file and parsing the rules. ")
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
                    if not args.q: output(bcolors.RED + "[Error] " + bcolors.ENDC + "Compiling PHP-IDS rule %s failed. Skipping it." % descr_content)
                    continue

                php_ids_rules[descr_content] = rule_content

        except (IOError) :
            output(bcolors.RED + "[Error] Can't read file the PHP-IDS default_filter.xml. Skipping PHP-IDS searches." + bcolors.ENDC)
            args.p = False

    # Actually start to look for stuff
    if not args.q: output(bcolors.BLUE + "[info] " + bcolors.ENDC + "Analyzing the file: %s" % user_log_file)

    # Pull each line of the file then perform all analysis
    for line in log_file:
        signal.signal(signal.SIGINT, signal_handler)    # Trap Ctrl-C

        # Ignore lines starting with a #
        if re.match('^#', line):
            line_counter += 1
            continue

        # Figure out what type of log format this is
        if (log['type'] == ''): rematch(line)

        # Some lines in the log we don't care about (notice, info...). So if we have no regex match discard those lines
        line_regex_split = re.search(log['regex'], line)
        if line_regex_split == None:
            # TODO - Output this "line" to an error file
            output(bcolors.RED + "[Error] " + bcolors.ENDC + "Line# %d didn't match log REGEX. Skipping it." % line_counter)
            if args.v: output(bcolors.DARKCYAN + "  [verbose] Line: " + bcolors.ENDC + "%s" % line)
            t.join()
            sys.stdout.flush()
            line_counter += 1
            if not args.q: status_message(int(line_counter),int(len(log_file)))
            continue

        # Cycle through each of the tests the user specified
        # Each line from the logfile spawns a new thread
        for key in tests:
            t = threading.Thread(target=findIt, args=(line.strip(), line_counter, key, tests[key]))
            try:
                t.start()
            except:
                pass

        t.join()
        sys.stdout.flush()
        line_counter += 1
        if not args.q: status_message(int(line_counter),int(len(log_file)))

    # Show the Results
    if len(attacker) == 0:
        output(bcolors.GREEN + "[info] " + bcolors.ENDC + "No security events found.")

    elif len(attacker) > 0:
        output(bcolors.GREEN + "\n-+-+- Found the following hosts (and associated activity) -+-+-\n" + bcolors.ENDC)

        #TODO - attacker.sort(key=operator.itemgetter('string'))
        for event in attacker:
            output(bcolors.RED    +    "%s :" % event['ip'])
            output(bcolors.YELLOW +    "   Earliest Date Seen:   %s" % event['date_earliest'])
            output(                    "   Earliest Recent Seen: %s" % event['date_recent'])
            if len(event['ua']) != 0:
                output(bcolors.GREEN + "   User-Agents:\n\t- %s" % "\n\t- ".join(sorted(event['ua'])))
            output(bcolors.BLUE +      "   All Attacks Seen:\n\t- %s" % "\n\t- ".join(sorted(event['attacks'])))
            if args.l: output(bcolors.DARKCYAN +  "   Line Numbers Where Attacks were Seen:\n\t- %s" % word_wrap(", ".join(sorted(str(x) for x in event['lines'])), 79, 0, 10, ""))
            output(bcolors.ENDC + "---------------------------------------------------------------")


#=================================================
# START
#=================================================
print bcolors.GREEN + "\n[Start] " + bcolors.CYAN + "Starting the WELP script. Hang on." + bcolors.ENDC

# Command Line Arguments
parser = argparse.ArgumentParser(description='Scan Apache access and IIS logs for known traces of scanners and attack')
parser.add_argument('log_file_to_parse', type=file, help='the log file that you want parsed')
parser.add_argument('-l', action='store_true', default=False, help='Show line numbers in final output (WARNING: There could be a LOT if your system had a scanner run against it.) [DEFAULT: off]')
parser.add_argument('-m', action='store_true', default=True, help='Disable ModSecurity Strings and REGEX searches [DEFAULT: on]')
parser.add_argument('-o', dest='outfile', help='[DEFAULT: stdout/no file] Output file name')
parser.add_argument('-p', action='store_true', default=False, help='Enable PHP-IDS Regexes (False Positive prone) [DEFAULT: off]')
parser.add_argument('-q', action='store_true', default=False, help='Minimal (Quiet) output')
parser.add_argument('-s', action='store_true', default=False, help='Only log 2xx \'Successful\' HTTP Response Codes [DEFAULT: off]')
parser.add_argument('-v', action='store_true', default=False, help='Verbose output')
#TODO - parser.add_argument('-f', dest='out_format', choices='htx', default='t', help='[DEFAULT: T=human readable text]The format you want the output to be in Html, Text, Xml.')
args = parser.parse_args()

if args.p: print bcolors.BLUE + "[info] " + bcolors.ENDC + "PHP-IDS Regular Expressions ENABLED. These are buggy and False Positive prone."
if args.q: print bcolors.BLUE + "[info] " + bcolors.ENDC + "Entering 'Quiet Mode'....shhh! Only important messages and new IPs/Hosts displayed."
if args.v:
    print bcolors.BLUE + "[info] " + bcolors.ENDC + "Entering 'Verbose Mode'....brace yourself for additional information."
else:
    print bcolors.BLUE + "[info] " + bcolors.ENDC + "Maintaining 'Normal Mode'. We'll only show you errors and new hosts. Additional host events only shown in VERBOSE mode."

if args.outfile:
    out_file = open(args.outfile, 'w')
    print bcolors.BLUE + "[info] " + bcolors.ENDC + "Saving all further output to %s" % args.outfile


if __name__ == "__main__": main()

output(bcolors.GREEN + "\n[Finished] " + bcolors.CYAN + "WELP script completed.\n")
if args.outfile: out_file.close()
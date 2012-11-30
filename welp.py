======================================
# START
#=================================================
print bcolors.GREEN + "\n[Start] " + bcolors.CYAN + "Starting the WELP script. Hang on." + bcolors.ENDC

# Command Line Arguments
parser = argparse.ArgumentParser(description='Scan Apache access logs for known traces of scanners and attack')
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
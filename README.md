welp - Web Event Log Processor
====

<u><b>Purpose:</b></u> <br>
So you are running a web server on the Interwebs and wanna know if/who has been running scans and attacking it. Enter Welp. You feed Welp an Apache "access.log" or IIS event log and it'll parse it looking for signs of attack. Currently it looks for:
<br>
   - User agents of attack tools - Pulled from ModSecurity and other sources<br>
   - All the attacks that PHP-IDS looks for in the default-filters.xml file (this file required during run-time)</ul>

There are some caveats for using WELP:<br>
   - Right now it only works for Apache 2.x access and IIS 6.0/7.5 logs.<br>
   - This will only see HTTP GET request parameters. POSTS and other methods will not be seen in the logs.<br>

@WebBreacher

<u><b>Usage:</b></u><br>
<pre>
welp.py [-h] [-l] [-m] [-o OUTFILE] [-p] [-q] [-s] [-v] log_file_to_parse

Scan Apache access and IIS logs for known traces of scanners and attack

positional arguments:
    log_file_to_parse  the log file that you want parsed

optional arguments:
  -h, --help         show this help message and exit
  -l                 Show line numbers in final output (WARNING: There could
                     be a LOT if your system had a scanner run against it.) [DEFAULT: off]
  -m                 Disable ModSecurity Strings and REGEX searches [DEFAULT: on]
  -o OUTFILE         [DEFAULT: stdout/no file] Output file name
  -p                 Enable PHP-IDS Regexes (False Positive prone) [DEFAULT: off]
  -q                 Minimal (Quiet) output
  -s                 Only log 2xx 'Successful' HTTP Response Codes [DEFAULT: off]
  -v                 Verbose output</pre>

<u><b>Output:</b></u>
<pre>
-+-+- Found the following hosts (and associated activity) -+-+-

123.hsd1.va.comcast.net :
   Earliest Date Seen:   2012-10-01 00:17:16
   Most Recent Seen:     2012-10-01 00:17:16
   All Attacks Seen:
   - HTTP Methods - POTATO
---------------------------------------------------------------
homeuser.example.com :
   Earliest Date Seen:   2012-10-01 03:59:55
   Most Recent Seen:     2012-12-01 04:15:10
   All Attacks Seen:
	- HTTP Methods - TRACE
	- HTTP Methods - TRACK
	- ModSecurity SQLi Strings - password
	- ModSecurity XSS Regex - Applet
	- UserAgent - nmap
	- ModSecurity XSS Regex - Frame/iFrame

</pre>

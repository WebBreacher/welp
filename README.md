welp - Web Error Log Processor
====

<u><b>Purpose:</b></u> <br>
So you are running a web server on the Interwebs and wanna know if/who has been running scans and attacking it. Enter Welp. You feed Welp an Apache "access.log" and it'll parse it looking for signs of attack. Currently it looks for:
<br>
   - User agents of attack tools - Pulled from ModSecurity and other sources<br>
   - All the attacks that PHP-IDS looks for in the default-filters.xml file (this file required during run-time)</ul>

There are some caveats for using WELP:<br>
   - Right now it only works for Apache 2.x access.logs. Will do error.log files soon<br>
   - This will only see HTTP GET request parameters. POSTS and other methods will not be seen in the logs.<br>
   - It is, um, slow. I'll be working to parallelize the processing of the logs soon</ul>

This script is my first real python script so suggestions for improvement are welcome.<br>

@WebBreacher

<u><b>Usage:</b></u><br>
<code>welp.py [apache_access_log_file_name]</code>

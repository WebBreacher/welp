#!/usr/bin/python
'''
-------------------------------------------------------------------------------
Name:        WELP Core Functions and Such
Author:      Micah Hoffman (@WebBreacher)
-------------------------------------------------------------------------------
'''

import os, sys

PERCENTS = { .1:10, .2:20, .3:30, .4:40, .5:50, .6:60, .7:70, .8:80, .9:90, .95:95}

def status_message(line_number, total):
    progress = float(line_number)/float(total)
    if progress in PERCENTS:
        print bcolors.BLUE + "[info] " + bcolors.ENDC + "%d%% complete parsing the log." % PERCENTS.get(progress)

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

# The entire bcolors class was taken verbatim from the Social Engineer's Toolkit (ty @SET)

# check operating system or if we have an output file, don't colorize text

def check_os():
    if os.name == "nt":
        operating_system = "windows"
    if os.name == "posix":
        operating_system = "posix"
    return operating_system

#
# Class for colors
#
if check_os() == "posix":
    class bcolors:
        PURPLE = '\033[95m'
        CYAN = '\033[96m'
        DARKCYAN = '\033[36m'
        BLUE = '\033[94m'
        GREEN = '\033[92m'
        YELLOW = '\033[93m'
        RED = '\033[91m'
        BOLD = '\033[1m'
        UNDERL = '\033[4m'
        ENDC = '\033[0m'
        backBlack = '\033[40m'
        backRed = '\033[41m'
        backGreen = '\033[42m'
        backYellow = '\033[43m'
        backBlue = '\033[44m'
        backMagenta = '\033[45m'
        backCyan = '\033[46m'
        backWhite = '\033[47m'

        def disable(self):
            self.PURPLE = ''
            self.CYAN = ''
            self.BLUE = ''
            self.GREEN = ''
            self.YELLOW = ''
            self.RED = ''
            self.ENDC = ''
            self.BOLD = ''
            self.UNDERL = ''
            self.backBlack = ''
            self.backRed = ''
            self.backGreen = ''
            self.backYellow = ''
            self.backBlue = ''
            self.backMagenta = ''
            self.backCyan = ''
            self.backWhite = ''
            self.DARKCYAN = ''

# if we are windows or something like that then define colors as nothing
else:
    class bcolors:
        PURPLE = ''
        CYAN = ''
        DARKCYAN = ''
        BLUE = ''
        GREEN = ''
        YELLOW = ''
        RED = ''
        BOLD = ''
        UNDERL = ''
        ENDC = ''
        backBlack = ''
        backRed = ''
        backGreen = ''
        backYellow = ''
        backBlue = ''
        backMagenta = ''
        backCyan = ''
        backWhite = ''

        def disable(self):
            self.PURPLE = ''
            self.CYAN = ''
            self.BLUE = ''
            self.GREEN = ''
            self.YELLOW = ''
            self.RED = ''
            self.ENDC = ''
            self.BOLD = ''
            self.UNDERL = ''
            self.backBlack = ''
            self.backRed = ''
            self.backGreen = ''
            self.backYellow = ''
            self.backBlue = ''
            self.backMagenta = ''
            self.backCyan = ''
            self.backWhite = ''
            self.DARKCYAN = ''

'''
Regexes and Search Strings
'''
class strings_and_regexes:
    # Pulled from ModSecurity modsecurity_35_scanners.data
    USER_AGENT_STRINGS = [".nasl", "absinthe", "acunetix", "arachni", "bilbo", "black widow", "blackwidow", "brutus", "bsqlbf", "burp", "cgichk", "dirbuster", "grabber", "grendel", "havij", "hydra", "jaascois", "metis", "mozilla/4.0 (compatible)", "mozilla/4.0 (compatible; msie 6.0; win32)", "mozilla/5.0 sf//", "n-stealth", "nessus", "netsparker", "nikto", "nmap nse", "nsauditor", "pangolin", "paros", "pmafind", "python-httplib2", "sql power injector", "sqlmap", "sqlninja", "w3af", "webinspect", "webshag", "webtrends security analyzer", "whatweb"]

    # Frequently used HTTP Methods that do not get flagged in the script. All else will get flagged.
    HTTP_METHODS = ["GET", "POST", "OPTIONS", "HEAD"]

    # From ModSecurity modsecurity_crs_41_xss_attacks 11/22/2012
    MODSEC_XSS = [ '.addimport', '.execscript', '.fromcharcode', '.innerhtml', '@import', 'activexobject', '>alert\(', 'application', 'asfunction:', 'background', 'background-image:', 'bexpression', 'copyparentfolder', 'createtextrange', 'document', 'ecmascript', 'getparentfolder', 'getspecialfolder', 'iframe', 'javascript', 'jscript', 'livescript:', 'lowsrc', 'meta', 'mocha:', 'onabort', 'onblur', 'onchange', 'onclick', 'ondragdrop', 'onerror', 'onfocus', 'onkeydown', 'onkeypress', 'onkeyup', 'onmousedown', 'onmousemove', 'onmouseout', 'onmouseover', 'onmouseup', 'onmove', 'onresize', 'onselect', 'onsubmit', 'onunload', 'script', 'settimeout', 'shell:', 'vbscript', 'vbscript:', 'x-javascript' ]

    # From ModSecurity modsecurity_41_sql_injection_attacks 11/22/2012
    MODSEC_SQLI = [ 'dbo', 'msdasql', 'sqloledb', '@@spid', '@@version', 'adddate', 'addtime', 'aes_decrypt', 'aes_encrypt', 'all_objects', 'ascii', 'attnotnull', 'attrelid', 'atttypid', 'autonomous_transaction', 'bit_and', 'bit_count', 'bit_length', 'bit_or', 'bit_xor', 'cast', 'char', 'character_length', 'charindex', 'charset', 'char_length', 'cieling', 'coalesce', 'coercibility', 'collation', 'column_id', 'column_name', 'concat', 'concat_ws', 'connection_id', 'constraint_type', 'convert_tz', 'cr32', 'curdate', 'current_date', 'current_time', 'current_timestamp', 'current_user', 'curtime', 'database', 'data_type', 'datediff', 'dba_users', 'dbms_java', 'dbms_pipe.receive_message', 'decode', 'des_', 'drop', 'dump', 'dumpfile', 'encode', 'encrypt', 'export_set', 'extract', 'field', 'find_in_set', 'floor', 'format', 'found_rows', 'from', 'get_', 'greatest', 'group_concat', 'having', 'ifnull', 'infile', 'inner', 'insert', 'instr', 'interval', 'isnull', 'is_srvrolemember', 'lcase', 'least', 'length', 'ln', 'load_file', 'local', 'locate', 'lower', 'lpad', 'ltrim', 'makedate', 'make_set', 'master_pos_wait', 'mb_users', 'md5', 'microsecond', 'minute', 'msysaces', 'msyscolumns', 'msysobjects', 'msysqueriessubstr', 'msysrelationships', 'mysql.', 'name_const', 'not_in', 'nullif', 'nvarchar', 'object_id', 'object_name', 'object_type', 'old_password', 'openquery', 'outfile', 'owa_util', 'password', 'period_', 'pg_attribute', 'pg_class', 'procedure_analyse', 'quarter', 'quote', 'radians', 'rand', 'release_lock', 'replace', 'reverse', 'round', 'rownum', 'row_count', 'rpad', 'rtrim', 'schema', 'second', 'sec_to_time', 'session_user', 'sha', 'shutdown', 'soundex', 'sp_execute', 'sp_executesql', 'sp_help', 'sp_makewebtask', 'sp_oacreate', 'sp_password', 'sql_longvarchar', 'sql_variant', 'sqrt', 'std', 'stddev', 'strcmp', 'str_to_date', 'subdate', 'substr', 'substring', 'subtime', 'sys.all_tables', 'sys.tab', 'sys.user_catalog', 'sys.user_constraints', 'sys.user_objects', 'sys.user_tables', 'sys.user_tab_columns', 'sys.user_triggers', 'sys.user_views', 'syscat', 'syscolumns', 'sysconstraints', 'sysdate', 'sysdba', 'sysfilegroups', 'sysibm', 'sysobjects', 'sysprocesses', 'systables', 'system_user', 'table_name', 'tbcreator', 'textpos', 'to_', 'to_number', 'trim', 'truncate', 'ucase', 'uncompress', 'uncompressed_length', 'unhex', 'unix_timestamp', 'updatexml', 'upper', 'user_constraints', 'user_group', 'user_ind_columns', 'user_objects', 'user_password', 'user_tables', 'user_tab_columns', 'user_users', 'utc_', 'utl_file', 'utl_http', 'uuid', 'values', 'varchar', 'variance', 'var_pop', 'var_samp', 'version', 'waitfor', 'weight_string', 'xmltype', 'xp_availablemedia', 'xp_cmdshell', 'xp_dirtree', 'xp_enumdsn', 'xp_execresultset', 'xp_filelist', 'xp_loginconfig', 'xp_makecab', 'xp_ntsec', 'xp_regaddmultistring', 'xp_regdeletekey', 'xp_regdeletevalue', 'xp_regenumkeys', 'xp_regenumvalues', 'xp_regread', 'xp_regremovemultistring', 'xp_regwrite', 'xp_terminate_process', 'xtype' ]

    # From http://www.symantec.com/connect/articles/detection-sql-injection-and-cross-site-scripting-attacks
    SYMANTEC_REGEX = {	'SQL Metachars': '/(\%27)|(\')|(\-\-)|(\%23)|(#)/',
					    'SQL Metachars2': '/((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))/',
					    'SQL Injection (typical)': '/\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))/',
					    'SQL Injection (UNION)': '/((\%27)|(\'))union/',
					    'SQL Injection (MSSQL)': '/exec(\s|\+)+(s|x)p\w+/',
					    'XSS (typical)': '/((\%3C)|<)((\%2F)|\/)*[a-z0-9\%]+((\%3E)|>)/',
					    'XSS (img src)': '/((\%3C)|<)((\%69)|i|(\%49))((\%6D)|m|(\%4D))((\%67)|g|(\%47))[^\n]+((\%3E)|>)/',
					    'XSS (paranoid)': '/((\%3C)|<)[^\n]+((\%3E)|>)/'
					 }

    # TODO - Get this to work - Pulled from ModSecurity modsecurity_crs_41_sql_injection
    MODSEC_SQLI_REGEX = { "a": '1'}

    #TODO compile these like SYMANTEC
    MODSEC_XSS_REGEX = { 'Style1': '<style.*?>.*?((@[i\\\\])|(([:=]|(&[#\(\)=]x?0*((58)|(3A)|(61)|(3D));?)).*?([(\\\\]|(&[#()=]x?0*((40)|(28)|(92)|(5C));?))))',
                         'Style2': 'style.*?=.*?([:=]|(&[#()=]x?0*((58)|(3A)|(61)|(3D));?)).*?([(\\\\]|(&[#()=]x?0*((40)|(28)|(92)|(5C));?))',
					     'Object': '<object.*?((type)|(codetype)|(classid)|(code)|(data)).*?=',
					     'Applet': '<applet.*?code.*?=',
					     'Datasrc': 'datasrc.*?=',
					     'HREF': '<(base|link).*?href.*?=',
					     'META': '<meta.*?http-equiv.*?=',
					     'Import': '<\?import.*?implementation.*?=',
					     'Embed': '<embed.*?src.*?=',
					     'On Events': '\bon\c\c\c+?\b*?=.',
					     'Frame/iFrame': '<i?frame.*?src.*?=',
					     'IsIndex': '<isindex.*?',
					     'Form': '</?form.*?>',
					     'Script': '</?script.*?>',
					     'Unicode': '(([^a-z0-9~_:\'\"\b])|(in)).*?(((l|(\\\\u006C))(o|(\\\\u006F))(c|(\\\\u0063))(a|(\\\\u0061))(t|(\\\\u0074))(i|(\\\\u0069))(o|(\\\\u006F))(n|(\\\\u006E)))|((n|(\\\\u006E))(a|(\\\\u0061))(m|(\\\\u006D))(e|(\\\\u0065)))).*?='}

    # Strings that may be indicative of a certain scanner/tool. Search for the string directly (no regex)
    MISC_TOOLS = {  'waffit scanner': '%3Cinvalid%3Ehello.html',
                    'xsser scanner': '\">',
                    'htexploit scanner': 'POTATO /index.php'
                    }


    # From ModSecurity Rules
    RESTRICTED_EXT = ['\.asa', '\.asax', '\.ascx', '\.axd', '\.backup', '\.bak', '\.bat', '\.cdx', '\.cer', '\.cfg', '\.cmd', '\.com', '\.config', '\.conf',  '\.csproj', '\.csr', '\.dat', '\.db', '\.dbf', '\.dll', '\.dos', '\.htr', '\.htw', '\.ida', '\.idc', '\.idq', '\.inc', '\.ini', '\.key', '\.licx', '\.lnk', '\.log', '\.mdb', '\.old', '\.pass', '\.pdb', '\.pol', '\.printer', '\.pwd', '\.resources', '\.resx', '\.sql', '\.sys', '\.vb', '\.vbs', '\.vbproj', '\.vsdisco', '\.webinfo', '\.xsd', '\.xsx']

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
    MODSEC_XSS = [ '.addimport', '.execscript', '.fromcharcode', '.innerhtml', '@import', 'activexobject', 'alert', 'application', 'asfunction:', 'background', 'background-image:', 'bexpression', 'copyparentfolder', 'createtextrange', 'document', 'ecmascript', 'getparentfolder', 'getspecialfolder', 'iframe', 'javascript', 'jscript', 'livescript:', 'lowsrc', 'meta', 'mocha:', 'onabort', 'onblur', 'onchange', 'onclick', 'ondragdrop', 'onerror', 'onfocus', 'onkeydown', 'onkeypress', 'onkeyup', 'onmousedown', 'onmousemove', 'onmouseout', 'onmouseover', 'onmouseup', 'onmove', 'onresize', 'onselect', 'onsubmit', 'onunload', 'script', 'settimeout', 'shell:', 'vbscript', 'vbscript:', 'x-javascript' ]

    # From ModSecurity modsecurity_41_sql_injection_attacks 11/22/2012
    MODSEC_SQLI = [ 'dbo', 'msdasql', 'sqloledb', '@@spid', '@@version', 'abs', 'acos', 'adddate', 'addtime', 'aes_decrypt', 'aes_encrypt', 'all_objects', 'ascii', 'asin', 'attnotnull', 'attrelid', 'atttypid', 'autonomous_transaction', 'avg', 'benchmark', 'bit_and', 'bit_count', 'bit_length', 'bit_or', 'bit_xor', 'cast', 'char', 'character_length', 'charindex', 'charset', 'char_length', 'chr', 'ciel', 'cieling', 'coalesce', 'coercibility', 'collation', 'column_id', 'column_name', 'concat', 'concat_ws', 'connection_id', 'constraint_type', 'conv', 'convert', 'convert_tz', 'cos', 'cot', 'cr32', 'curdate', 'current_date', 'current_time', 'current_timestamp', 'current_user', 'curtime', 'database', 'data_type', 'datediff', 'dba_users', 'dbms_java', 'dbms_pipe.receive_message', 'decode', 'degrees', 'delete', 'des_', 'drop', 'dump', 'dumpfile', 'elt', 'encode', 'encrypt', 'exp', 'export_set', 'extract', 'field', 'find_in_set', 'floor', 'format', 'found_rows', 'from_', 'get_', 'greatest', 'group_concat', 'having', 'ifnull', 'infile', 'inner', 'insert', 'instr', 'interval', 'isnull', 'is_srvrolemember', 'last', 'lcase', 'least', 'length', 'ln', 'load_file', 'local', 'locate', 'lower', 'lpad', 'ltrim', 'makedate', 'make_set', 'master_pos_wait', 'max', 'mb_users', 'md5', 'microsecond', 'mid', 'min', 'minute', 'mod', 'month', 'msysaces', 'msyscolumns', 'msysobjects', 'msysqueriessubstr', 'msysrelationships', 'mysql.', 'name_const', 'not_in', 'nullif', 'nvarchar', 'object_id', 'object_name', 'object_type', 'oct', 'old_password', 'openquery', 'outfile', 'owa_util', 'password', 'period_', 'pg_attribute', 'pg_class', 'position', 'pow', 'print', 'procedure_analyse', 'quarter', 'quote', 'radians', 'rand', 'release_lock', 'repeat', 'replace', 'reverse', 'round', 'rownum', 'row_count', 'rpad', 'rtrim', 'schema', 'second', 'sec_to_time', 'select', 'session_user', 'sha', 'shutdown', 'sign', 'sin', 'soundex', 'space', 'sp_execute', 'sp_executesql', 'sp_help', 'sp_makewebtask', 'sp_oacreate', 'sp_password', 'sql_longvarchar', 'sql_variant', 'sqrt', 'std', 'stddev', 'strcmp', 'str_to_date', 'subdate', 'substr', 'substring', 'subtime', 'sum', 'sys.all_tables', 'sys.tab', 'sys.user_catalog', 'sys.user_constraints', 'sys.user_objects', 'sys.user_tables', 'sys.user_tab_columns', 'sys.user_triggers', 'sys.user_views', 'syscat', 'syscolumns', 'sysconstraints', 'sysdate', 'sysdba', 'sysfilegroups', 'sysibm', 'sysobjects', 'sysprocesses', 'systables', 'system_user', 'table_name', 'tan', 'tbcreator', 'textpos', 'time', 'to_', 'to_number', 'trim', 'truncate', 'ucase', 'uncompress', 'uncompressed_length', 'unhex', 'unix_timestamp', 'updatexml', 'upper', 'user', 'user_constraints', 'user_group', 'user_ind_columns', 'user_objects', 'user_password', 'user_tables', 'user_tab_columns', 'user_users', 'utc_', 'utl_file', 'utl_http', 'uuid', 'values', 'varchar', 'variance', 'var_pop', 'var_samp', 'version', 'waitfor', 'week', 'weight_string', 'xmltype', 'xp_availablemedia', 'xp_cmdshell', 'xp_dirtree', 'xp_enumdsn', 'xp_execresultset', 'xp_filelist', 'xp_loginconfig', 'xp_makecab', 'xp_ntsec', 'xp_regaddmultistring', 'xp_regdeletekey', 'xp_regdeletevalue', 'xp_regenumkeys', 'xp_regenumvalues', 'xp_regread', 'xp_regremovemultistring', 'xp_regwrite', 'xp_terminate_process', 'xtype' ]


    # TODO - Get this to work - Pulled from ModSecurity modsecurity_crs_41_sql_injection
    MODSEC_SQLI_REGEX = {"Blind SQL injection": "(?i:(?:\b(?:(?:s(?:ys\.(?:user_(?:(?:t(?:ab(?:_column|le)|rigger)|object|view)s|c(?:onstraints|atalog))|all_tables|tab)|elect\b.{0,40}\b(?:substring|users?|ascii))|m(?:sys(?:(?:queri|ac)e|relationship|column|object)s|ysql\.(db|user))|c(?:onstraint_type|harindex)|waitfor\b\W*?\bdelay|attnotnull)\b|(?:locate|instr)\W+\()|\@\@spid\b)|\b(?:(?:s(?:ys(?:(?:(?:process|tabl)e|filegroup|object)s|c(?:o(?:nstraint|lumn)s|at)|dba|ibm)|ubstr(?:ing)?)|user_(?:(?:(?:constrain|objec)t|tab(?:_column|le)|ind_column|user)s|password|group)|a(?:tt(?:rel|typ)id|ll_objects)|object_(?:(?:nam|typ)e|id)|pg_(?:attribute|class)|column_(?:name|id)|xtype\W+\bchar|mb_users|rownum)\b|t(?:able_name\b|extpos\W+\()))",
					    "SQL injection1": "(?i:(?:(?:s(?:t(?:d(?:dev(_pop|_samp)?)?|r(?:_to_date|cmp))|u(?:b(?:str(?:ing(_index)?)?|(?:dat|tim)e)|m)|e(?:c(?:_to_time|ond)|ssion_user)|ys(?:tem_user|date)|ha(1|2)?|oundex|chema|ig?n|pace|qrt)|i(?:s(null|_(free_lock|ipv4_compat|ipv4_mapped|ipv4|ipv6|not_null|not|null|used_lock))?|n(?:et6?_(aton|ntoa)|s(?:ert|tr)|terval)?|f(null)?)|u(?:n(?:compress(?:ed_length)?|ix_timestamp|hex)|tc_(date|time|timestamp)|p(?:datexml|per)|uid(_short)?|case|ser)|l(?:o(?:ca(?:l(timestamp)?|te)|g(2|10)?|ad_file|wer)|ast(_day|_insert_id)?|e(?:(?:as|f)t|ngth)|case|trim|pad|n)|t(?:ime(stamp|stampadd|stampdiff|diff|_format|_to_sec)?|o_(base64|days|seconds|n?char)|r(?:uncate|im)|an)|m(?:a(?:ke(?:_set|date)|ster_pos_wait|x)|i(?:(?:crosecon)?d|n(?:ute)?)|o(?:nth(name)?|d)|d5)|r(?:e(?:p(?:lace|eat)|lease_lock|verse)|o(?:w_count|und)|a(?:dians|nd)|ight|trim|pad)|f(?:i(?:eld(_in_set)?|nd_in_set)|rom_(base64|days|unixtime)|o(?:und_rows|rmat)|loor)|a(?:es_(?:de|en)crypt|s(?:cii(str)?|in)|dd(?:dat|tim)e|(?:co|b)s|tan2?|vg)|p(?:o(?:sition|w(er)?)|eriod_(add|diff)|rocedure_analyse|assword|i)|b(?:i(?:t_(?:length|count|x?or|and)|n(_to_num)?)|enchmark)|e(?:x(?:p(?:ort_set)?|tract(value)?)|nc(?:rypt|ode)|lt)|v(?:a(?:r(?:_(?:sam|po)p|iance)|lues)|ersion)|g(?:r(?:oup_conca|eates)t|et_(format|lock))|o(?:(?:ld_passwo)?rd|ct(et_length)?)|we(?:ek(day|ofyear)?|ight_string)|n(?:o(?:t_in|w)|ame_const|ullif)|(rawton?)?hex(toraw)?|qu(?:arter|ote)|(pg_)?sleep|year(week)?|d?count|xmltype|hour)\W*\(|\b(?:(?:s(?:elect\b(?:.{1,100}?\b(?:(?:length|count|top)\b.{1,100}?\bfrom|from\b.{1,100}?\bwhere)|.*?\b(?:d(?:ump\b.*\bfrom|ata_type)|(?:to_(?:numbe|cha)|inst)r))|p_(?:sqlexec|sp_replwritetovarbin|sp_help|addextendedproc|is_srvrolemember|prepare|sp_password|execute(?:sql)?|makewebtask|oacreate)|ql_(?:longvarchar|variant))|xp_(?:reg(?:re(?:movemultistring|ad)|delete(?:value|key)|enum(?:value|key)s|addmultistring|write)|terminate|xp_servicecontrol|xp_ntsec_enumdomains|xp_terminate_process|e(?:xecresultset|numdsn)|availablemedia|loginconfig|cmdshell|filelist|dirtree|makecab|ntsec)|u(?:nion\b.{1,100}?\bselect|tl_(?:file|http))|d(?:b(?:a_users|ms_java)|elete\b\W*?\bfrom)|group\b.*\bby\b.{1,100}?\bhaving|open(?:rowset|owa_util|query)|load\b\W*?\bdata\b.*\binfile|(?:n?varcha|tbcreato)r|autonomous_transaction)\b|i(?:n(?:to\b\W*?\b(?:dump|out)file|sert\b\W*?\binto|ner\b\W*?\bjoin)\b|(?:f(?:\b\W*?\(\W*?\bbenchmark|null\b)|snull\b)\W*?\()|print\b\W*?\@\@|cast\b\W*?\()|c(?:(?:ur(?:rent_(?:time(?:stamp)?|date|user)|(?:dat|tim)e)|h(?:ar(?:(?:acter)?_length|set)?|r)|iel(?:ing)?|ast|r32)\W*\(|o(?:(?:n(?:v(?:ert(?:_tz)?)?|cat(?:_ws)?|nection_id)|(?:mpres)?s|ercibility|alesce|t)\W*\(|llation\W*\(a))|d(?:(?:a(?:t(?:e(?:(_(add|format|sub))?|diff)|abase)|y(name|ofmonth|ofweek|ofyear)?)|e(?:(?:s_(de|en)cryp|faul)t|grees|code)|ump)\W*\(|bms_pipe\.receive_message\b)|(?:;\W*?\b(?:shutdown|drop)|\@\@version)\b|'(?:s(?:qloledb|a)|msdasql|dbo)'))",
					    "SQL injection2": "\b(?i:having)\b\s+(\d{1,10}|'[^=]{1,10}')\s*?[=<>]|(?i:\bexecute(\s{1,5}[\w\.$]{1,5}\s{0,3})?\()|\bhaving\b ?(?:\d{1,10}|[\'\"][^=]{1,10}[\'\"]) ?[=<>]+|(?i:\bcreate\s+?table.{0,20}?\()|(?i:\blike\W*?char\W*?\()|(?i:(?:(select(.*?)case|from(.*?)limit|order\sby)))|exists\s(\sselect|select\Sif(null)?\s\(|select\Stop|select\Sconcat|system\s\(|\b(?i:having)\b\s+(\d{1,10})|'[^=]{1,10}')",
					    "SQL injection3": "(?i:\bor\b ?(?:\d{1,10}|[\'\"][^=]{1,10}[\'\"]) ?[=<>]+|(?i:'\s+x?or\s+.{1,20}[+\-!<>=])|\b(?i:x?or)\b\s+(\d{1,10}|'[^=]{1,10}')|\b(?i:x?or)\b\s+(\d{1,10}|'[^=]{1,10}')\s*?[=<>])",
					    "SQL injection4": "(?i)\b(?i:and)\b\s+(\d{1,10}|'[^=]{1,10}')\s*?[=]|\b(?i:and)\b\s+(\d{1,10}|'[^=]{1,10}')\s*?[<>]|\band\b ?(?:\d{1,10}|[\'\"][^=]{1,10}[\'\"]) ?[=<>]+|\b(?i:and)\b\s+(\d{1,10}|'[^=]{1,10}')",
					    "SQL injection5": "(?i:\b(?:coalesce\b|root\@))",
					    "SQL injection6": "(?i:(?:(?:s(?:t(?:d(?:dev(_pop|_samp)?)?|r(?:_to_date|cmp))|u(?:b(?:str(?:ing(_index)?)?|(?:dat|tim)e)|m)|e(?:c(?:_to_time|ond)|ssion_user)|ys(?:tem_user|date)|ha(1|2)?|oundex|chema|ig?n|pace|qrt)|i(?:s(null|_(free_lock|ipv4_compat|ipv4_mapped|ipv4|ipv6|not_null|not|null|used_lock))?|n(?:et6?_(aton|ntoa)|s(?:ert|tr)|terval)?|f(null)?)|u(?:n(?:compress(?:ed_length)?|ix_timestamp|hex)|tc_(date|time|timestamp)|p(?:datexml|per)|uid(_short)?|case|ser)|l(?:o(?:ca(?:l(timestamp)?|te)|g(2|10)?|ad_file|wer)|ast(_day|_insert_id)?|e(?:(?:as|f)t|ngth)|case|trim|pad|n)|t(?:ime(stamp|stampadd|stampdiff|diff|_format|_to_sec)?|o_(base64|days|seconds|n?char)|r(?:uncate|im)|an)|m(?:a(?:ke(?:_set|date)|ster_pos_wait|x)|i(?:(?:crosecon)?d|n(?:ute)?)|o(?:nth(name)?|d)|d5)|r(?:e(?:p(?:lace|eat)|lease_lock|verse)|o(?:w_count|und)|a(?:dians|nd)|ight|trim|pad)|f(?:i(?:eld(_in_set)?|nd_in_set)|rom_(base64|days|unixtime)|o(?:und_rows|rmat)|loor)|a(?:es_(?:de|en)crypt|s(?:cii(str)?|in)|dd(?:dat|tim)e|(?:co|b)s|tan2?|vg)|p(?:o(?:sition|w(er)?)|eriod_(add|diff)|rocedure_analyse|assword|i)|b(?:i(?:t_(?:length|count|x?or|and)|n(_to_num)?)|enchmark)|e(?:x(?:p(?:ort_set)?|tract(value)?)|nc(?:rypt|ode)|lt)|v(?:a(?:r(?:_(?:sam|po)p|iance)|lues)|ersion)|g(?:r(?:oup_conca|eates)t|et_(format|lock))|o(?:(?:ld_passwo)?rd|ct(et_length)?)|we(?:ek(day|ofyear)?|ight_string)|n(?:o(?:t_in|w)|ame_const|ullif)|(rawton?)?hex(toraw)?|qu(?:arter|ote)|(pg_)?sleep|year(week)?|d?count|xmltype|hour)\W*?\(|\b(?:(?:s(?:elect\b(?:.{1,100}?\b(?:(?:length|count|top)\b.{1,100}?\bfrom|from\b.{1,100}?\bwhere)|.*?\b(?:d(?:ump\b.*?\bfrom|ata_type)|(?:to_(?:numbe|cha)|inst)r))|p_(?:sqlexec|sp_replwritetovarbin|sp_help|addextendedproc|is_srvrolemember|prepare|sp_password|execute(?:sql)?|makewebtask|oacreate)|ql_(?:longvarchar|variant))|xp_(?:reg(?:re(?:movemultistring|ad)|delete(?:value|key)|enum(?:value|key)s|addmultistring|write)|terminate|xp_servicecontrol|xp_ntsec_enumdomains|xp_terminate_process|e(?:xecresultset|numdsn)|availablemedia|loginconfig|cmdshell|filelist|dirtree|makecab|ntsec)|u(?:nion\b.{1,100}?\bselect|tl_(?:file|http))|d(?:b(?:a_users|ms_java)|elete\b\W*?\bfrom)|group\b.*?\bby\b.{1,100}?\bhaving|open(?:rowset|owa_util|query)|load\b\W*?\bdata\b.*?\binfile|(?:n?varcha|tbcreato)r|autonomous_transaction)\b|i(?:n(?:to\b\W*?\b(?:dump|out)file|sert\b\W*?\binto|ner\b\W*?\bjoin)\b|(?:f(?:\b\W*?\(\W*?\bbenchmark|null\b)|snull\b)\W*?\()|print\b\W*?\@\@|cast\b\W*?\()|c(?:(?:ur(?:rent_(?:time(?:stamp)?|date|user)|(?:dat|tim)e)|h(?:ar(?:(?:acter)?_length|set)?|r)|iel(?:ing)?|ast|r32)\W*?\(|o(?:(?:n(?:v(?:ert(?:_tz)?)?|cat(?:_ws)?|nection_id)|(?:mpres)?s|ercibility|alesce|t)\W*?\(|llation\W*?\(a))|d(?:(?:a(?:t(?:e(?:(_(add|format|sub))?|diff)|abase)|y(name|ofmonth|ofweek|ofyear)?)|e(?:(?:s_(de|en)cryp|faul)t|grees|code)|ump)\W*?\(|bms_pipe\.receive_message\b)|(?:;\W*?\b(?:shutdown|drop)|\@\@version)\b|'(?:s(?:qloledb|a)|msdasql|dbo)'))"}

    # From http://www.symantec.com/connect/articles/detection-sql-injection-and-cross-site-scripting-attacks
    SYMANTEC_REGEX = {	'SQL Metachars':'/(\%27)|(\')|(\-\-)|(\%23)|(#)/ix',
					'SQL Metachars2':'/((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))/i',
					'SQL Injection (typical)':'/\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))/ix',
					'SQL Injection (UNION)':'/((\%27)|(\'))union/ix',
					'SQL Injection (MSSQL)':'/exec(\s|\+)+(s|x)p\w+/ix',
					'XSS (typical)':'/((\%3C)|<)((\%2F)|\/)*[a-z0-9\%]+((\%3E)|>)/ix',
					'XSS (img src)':'/((\%3C)|<)((\%69)|i|(\%49))((\%6D)|m|(\%4D))((\%67)|g|(\%47))[^\n]+((\%3E)|>)/I',
					'XSS (paranoid)':'/((\%3C)|<)[^\n]+((\%3E)|>)/I'}


    #TODO compile these like SYMANTEC
    MODSEC_XSS_REGEX = ['/:<style.*?>.*?((@[i\\\\])|(([:=]|(&[#\(\)=]x?0*((58)|(3A)|(61)|(3D));?)).*?([(\\\\]|(&[#()=]x?0*((40)|(28)|(92)|(5C));?))))/i',
                        '/:[ /+\t\"\'`]style[ /+\t]*?=.*?([:=]|(&[#()=]x?0*((58)|(3A)|(61)|(3D));?)).*?([(\\\\]|(&[#()=]x?0*((40)|(28)|(92)|(5C));?))/i',
					    '/:<object[ /+\t].*?((type)|(codetype)|(classid)|(code)|(data))[ /+\t]*=/i',
					    '/:<applet[ /+\t].*?code[ /+\t]*=/i',
					    '/:[ /+\t\"\'`]datasrc[ +\t]*?=./i',
					    '/:<(base|link)[ /+\t].*?href[ /+\t]*=/i',
					    '/:<meta[ /+\t].*?http-equiv[ /+\t]*=/i',
					    '/:<\?import[ /+\t].*?implementation[ /+\t]*=/i',
					    '/:<embed[ /+\t].*?SRC.*?=/i',
					    '/:[ /+\t\"\'`]on\c\c\c+?[ +\t]*?=./i',
					    '/:<.*[:]vmlframe.*?[ /+\t]*?src[ /+\t]*=/i',
					    '/:<[i]?frame.*?[ /+\t]*?src[ /+\t]*=/i',
					    '/:<isindex[ /+\t>]/i',
					    '/:<form.*?>/i',
					    '/:<script.*?[ /+\t]*?src[ /+\t]*=/i',
					    '/:<script.*?>/i',
					    '/:[\"\'][ ]*(([^a-z0-9~_:\'\" ])|(in)).*?(((l|(\\\\u006C))(o|(\\\\u006F))(c|(\\\\u0063))(a|(\\\\u0061))(t|(\\\\u0074))(i|(\\\\u0069))(o|(\\\\u006F))(n|(\\\\u006E)))|((n|(\\\\u006E))(a|(\\\\u0061))(m|(\\\\u006D))(e|(\\\\u0065)))).*?=/i',
					    '/:[\"\'][ ]*(([^a-z0-9~_:\'\" ])|(in)).+?(([.].+?)|([\[].*?[\]].*?))=/i',
					    '/:[\"\'].*?\[ ]*(([^a-z0-9~_:\'\" ])|(in)).+?\(/i',
					    '/:[\"\'][ ]*(([^a-z0-9~_:\'\" ])|(in)).+?\(.*?\)/i' ]

    # Strings that may be indicative of a certain scanner/tool. Search for the string directly (no regex)
    MISC_TOOLS = {  'waffit scanner': '%3Cinvalid%3Ehello.html',
                    'xsser scanner': '\">',
                    'htexploit scanner': 'POTATO /index.php'
                    }


    # From ModSecurity Rules
    RESTRICTED_EXT = ['\.asa', '\.asax', '\.ascx', '\.axd', '\.backup', '\.bak', '\.bat', '\.cdx', '\.cer', '\.cfg', '\.cmd', '\.com', '\.config', '\.conf', '\.csproj', '\.csr', '\.dat', '\.db', '\.dbf', '\.dll', '\.dos', '\.htr', '\.htw', '\.ida', '\.idc', '\.idq', '\.inc', '\.ini', '\.key', '\.licx', '\.lnk', '\.log', '\.mdb', '\.old', '\.pass', '\.pdb', '\.pol', '\.printer', '\.pwd', '\.resources', '\.resx', '\.sql', '\.sys', '\.vb', '\.vbs', '\.vbproj', '\.vsdisco', '\.webinfo', '\.xsd', '\.xsx']

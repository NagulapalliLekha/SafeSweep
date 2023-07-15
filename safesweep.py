import sys
import argparse
import subprocess
import os
import time
import random
import threading
import re
import random
from urllib.parse import urlsplit


CURSOR_UP_ONE = '\x1b[1A' 
ERASE_LINE = '\x1b[2K'

intervals = (
    ('h', 3600),
    ('m', 60),
    ('s', 1),
    )
def display_time(seconds, granularity=3):
    opt = []
    seconds = seconds + 1
    for name, count in intervals:
        value = seconds // count
        if value:
            seconds -= value * count
            opt.append("{}{}".format(value, name))
    return ' '.join(opt[:granularity])


def terminal_size():
    try:
        rows, columns = subprocess.check_output(['stty', 'size']).split()
        return int(columns)
    except subprocess.CalledProcessError as e:
        return int(20)
    


def url_maker(url):
    if not re.match(r'http(s?)\:', url):
        url = 'http://' + url
    parsed = urlsplit(url)
    host = parsed.netloc
    if host.startswith('www.'):
        host = host[4:]
    return host

def check_internet():
    os.system('ping -c1 github.com > ss_net 2>&1')
    if "0% packet loss" in open('ss_net').read():
        val = 1
    else:
        val = 0
    os.system('rm ss_net > /dev/null 2>&1')
    return val


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    BADFAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

    BG_ERR_TXT  = '\033[41m'
    BG_HEAD_TXT = '\033[100m'
    BG_ENDL_TXT = '\033[46m'
    BG_CRIT_TXT = '\033[45m'
    BG_HIGH_TXT = '\033[41m'
    BG_MED_TXT  = '\033[43m'
    BG_LOW_TXT  = '\033[44m'
    BG_INFO_TXT = '\033[42m'

    BG_SCAN_TXT_START = '\x1b[6;30;42m'
    BG_SCAN_TXT_END   = '\x1b[0m'


def vul_info(val):
    opt =''
    if val == 'c':
        opt = bcolors.BG_CRIT_TXT+" critical "+bcolors.ENDC
    elif val == 'h':
        opt = bcolors.BG_HIGH_TXT+" high "+bcolors.ENDC
    elif val == 'm':
        opt = bcolors.BG_MED_TXT+" medium "+bcolors.ENDC
    elif val == 'l':
        opt = bcolors.BG_LOW_TXT+" low "+bcolors.ENDC
    else:
        opt = bcolors.BG_INFO_TXT+" info "+bcolors.ENDC
    return opt

proc_high = bcolors.BADFAIL + "●" + bcolors.ENDC
proc_med  = bcolors.WARNING + "●" + bcolors.ENDC
proc_low  = bcolors.OKGREEN + "●" + bcolors.ENDC

def vul_remed_info(v1,v2,v3):
    print(bcolors.BOLD+"Vulnerability Threat Level"+bcolors.ENDC)
    print("\t"+vul_info(v2)+" "+bcolors.WARNING+str(tool_resp[v1][0])+bcolors.ENDC)
    print(bcolors.BOLD+"Vulnerability Definition"+bcolors.ENDC)
    print("\t"+bcolors.BADFAIL+str(tools_fix[v3-1][1])+bcolors.ENDC)
    print(bcolors.BOLD+"Vulnerability Remediation"+bcolors.ENDC)
    print("\t"+bcolors.OKGREEN+str(tools_fix[v3-1][2])+bcolors.ENDC)

def helper():
        print(bcolors.OKBLUE+"Information:"+bcolors.ENDC)
        print("------------")
        print("\t./safesweep.py example.com: Scans the domain example.com.")
        print("\t./safesweep.py --update   : Updates the scanner to the latest version.")
        print("\t./safesweep.py --help     : Displays this help context.")
        print(bcolors.OKBLUE+"Interactive:"+bcolors.ENDC)
        print("------------")
        print("\tCtrl+C: Skips current test.")
        print("\tCtrl+Z: Quits SafeSweep.")
        print(bcolors.OKBLUE+"Legends:"+bcolors.ENDC)
        print("--------")
        print("\t["+proc_high+"]: Scan process may take longer times (not predictable).")
        print("\t["+proc_med+"]: Scan process may take less than 10 minutes.")
        print("\t["+proc_low+"]: Scan process may take less than a minute or two.")
        print(bcolors.OKBLUE+"Vulnerability Information:"+bcolors.ENDC)
        print("--------------------------")
        print("\t"+vul_info('c')+": Requires immediate attention as it may lead to compromise or service unavailability.")
        print("\t"+vul_info('h')+"    : May not lead to an immediate compromise, but there are considerable chances for probability.")
        print("\t"+vul_info('m')+"  : Attacker may correlate multiple vulnerabilities of this type to launch a sophisticated attack.")
        print("\t"+vul_info('l')+"     : Not a serious issue, but it is recommended to tend to the finding.")
        print("\t"+vul_info('i')+"    : Not classified as a vulnerability, simply an useful informational alert to be considered.\n")


def clear():
        sys.stdout.write("\033[F")
        sys.stdout.write("\033[K") #clears until EOL

def logo():
    print(bcolors.WARNING)
    logo_ascii = """
                ___   __ _  / _|  ___  ___ __      __ ___   ___  _ __  
               / __| / _` || |_  / _ \/ __|\ \ /\ / // _ \ / _ \| '_ \ 
               \__ \| (_| ||  _||  __/\__ \ \ V  V /|  __/|  __/| |_) |
               |___/ \__,_||_|   \___||___/  \_/\_/  \___| \___|| .__/ 
                                                                |_|    
               """+bcolors.WARNING+"""{ Multiple Web Vulnerability Scanner - Ver 1.0 }
    """
    print(logo_ascii)
    print(bcolors.ENDC)

class Spinner:
    busy = False
    delay = 0.005

    @staticmethod
    def spinning_cursor():
        while 1:
            for cursor in ' ': yield cursor
    def __init__(self, delay=None):
        self.spinner_generator = self.spinning_cursor()
        if delay and float(delay): self.delay = delay
        self.disabled = False

    def spinner_task(self):
        inc = 0
        try:
            while self.busy:
                if not self.disabled:
                    x = bcolors.BG_SCAN_TXT_START+next(self.spinner_generator)+bcolors.BG_SCAN_TXT_END
                    inc = inc + 1
                    print(x,end='')
                    if inc>random.uniform(0,terminal_size()): #30 init
                        print(end="\r")
                        bcolors.BG_SCAN_TXT_START = '\x1b[6;30;'+str(round(random.uniform(40,47)))+'m'
                        inc = 0
                    sys.stdout.flush()
                time.sleep(self.delay)
                if not self.disabled:
                    sys.stdout.flush()

        except (KeyboardInterrupt, SystemExit):
            print("\n\t"+ bcolors.BG_ERR_TXT+"SafeSweep received a series of Ctrl+C hits. Quitting..." +bcolors.ENDC)
            sys.exit(1)

    def start(self):
        self.busy = True
        try:
            threading.Thread(target=self.spinner_task).start()
        except Exception as e:
            print("\n")
        
    def stop(self):
        try:
            self.busy = False
            time.sleep(self.delay)
        except (KeyboardInterrupt, SystemExit):
            print("\n\t"+ bcolors.BG_ERR_TXT+"SafeSweep received a series of Ctrl+C hits. Quitting..." +bcolors.ENDC)
            sys.exit(1)

spinner = Spinner()

tool_meme = [
                #one
                ["host","Host - Checks for existence of IPV6 address.","host",1],

                #two		
                ["aspnet_config_err","ASP.Net Misconfiguration - Checks for ASP.Net Misconfiguration.","wget",1],

                #three
                ["wp_check","WordPress Checker - Checks for WordPress Installation.","wget",1],

                #four
                ["drp_check", "Drupal Checker - Checks for Drupal Installation.","wget",1],

                #five
                ["joom_check", "Joomla Checker - Checks for Joomla Installation.","wget",1],

                #six
                ["uniscan","Uniscan - Checks for robots.txt & sitemap.xml","uniscan",1],

                #seven
                ["wafw00f","Wafw00f - Checks for Application Firewalls.","wafw00f",1],

                #eight
                ["nmap","Nmap - Fast Scan [Only Few Port Checks]","nmap",1],

                #nine
                ["Subfinder","The Subfinder - Enemurate all the subdomains","subfinder",1],

                #ten
                ["dnsrecon","DNSRecon - Attempts Multiple Zone Transfers on Nameservers.","dnsrecon",1],

                #eleven
                ["dnswalk","DNSWalk - Attempts Zone Transfer.","dnswalk",1],

                #twelve
                ["whois","WHOis - Checks for Administrator's Contact Information.","whois",1],

                #thirteen
                ["nmap_header","Nmap [XSS Filter Check] - Checks if XSS Protection Header is present.","nmap",1],

                #fourteen
                ["nmap_sloris","Nmap [Slowloris DoS] - Checks for Slowloris Denial of Service Vulnerability.","nmap",1],

                #fifteen
                ["sslyze_hbleed","SSLyze - Checks only for Heartbleed Vulnerability.","sslyze",1],

                #sixteen
                ["nmap_hbleed","Nmap [Heartbleed] - Checks only for Heartbleed Vulnerability.","nmap",1],

                #seventeen
                ["nmap_poodle","Nmap [POODLE] - Checks only for Poodle Vulnerability.","nmap",1],

                #eighteen
                ["nmap_ccs","Nmap [OpenSSL CCS Injection] - Checks only for CCS Injection.","nmap",1],

                #nineteen
                ["nmap_freak","Nmap [FREAK] - Checks only for FREAK Vulnerability.","nmap",1],

                #twenty	
                ["nmap_logjam","Nmap [LOGJAM] - Checks for LOGJAM Vulnerability.","nmap",1],

                #twentyone
                ["sslyze_ocsp","SSLyze - Checks for OCSP Stapling.","sslyze",1],

                #twentytwo
                ["sslyze_zlib","SSLyze - Checks for ZLib Deflate Compression.","sslyze",1],

                #twentythree
                ["sslyze_reneg","SSLyze - Checks for Secure Renegotiation Support and Client Renegotiation.","sslyze",1],

                #twentyfour
                ["sslyze_resum","SSLyze - Checks for Session Resumption Support with [Session IDs/TLS Tickets].","sslyze",1],

                #twentyfive
                ["lbd","LBD - Checks for DNS/HTTP Load Balancers.","lbd",1],

                #twentysix
                ["golismero_dns_malware","Cryptographic Failures - Checks for Sensitive Data Leak ","golismero",1],

                #twentyseven
                ["golismero_heartbleed","Insecure Design - Checks for Ineffective Secure Design","golismero",1],

                #twentyeight
                ["golismero_brute_url_predictables","Security Misconfiguration - Checks for Security Misconfiguraions","golismero",1],

                #twentynine
                ["golismero_brute_directories","Vulnerable and Outdated Components - Checks for Outdated Components","golismero",1],

                #thirty
                ["golismero_sqlmap","Identification and Authentication Failures - Authentication Failures","golismero",1],

                #thirtyone
                ["dirb","DirB - Brutes the target for Open Directories.","dirb",1],

                #thirtytwo
                ["xsser","XSSer - Checks for Cross-Site Scripting [XSS] Attacks.","xsser",1],

                #thirtythree
                ["golismero_ssl_scan","Software and Data Integrity Failures - Performs SSL related Scans.","golismero",1],

                #thirtyfour
                ["golismero_zone_transfer","Security Logging and Monitoring - Log Files Disclosure","golismero",1],

                #thirtyfive
                ["golismero_nikto","Git File Exposure - Checks for Git Folders","golismero",1],

                #thirtysix
                ["golismero_brute_subdomains","Server-Side Request Forgery - Checks for url parameter","golismero",1],

                #thirtyseven
                ["dnsenum_zone_transfer","DNSEnum - Attempts Zone Transfer.","dnsenum",1],

                #thirtyeight
                ["fierce_brute_subdomains","Fierce Subdomains Bruter - Brute Forces Subdomain Discovery.","fierce",1],

                #thirtynine
                ["dmitry_email","DMitry - Passively Harvests Emails from the Domain.","dmitry",1],

                #fourty
                ["dmitry_subdomains","DMitry - Passively Harvests Subdomains from the Domain.","dmitry",1],

                #fourtyone
                ["nmap_telnet","Nmap [TELNET] - Checks if TELNET service is running.","nmap",1],

                #fourtytwo
                ["nmap_ftp","Nmap [FTP] - Checks if FTP service is running.","nmap",1],

                #fourtythree
                ["nmap_stuxnet","Nmap [STUXNET] - Checks if the host is affected by STUXNET Worm.","nmap",1],

                #fourtyfour
                ["webdav","WebDAV - Checks if WEBDAV enabled on Home directory.","davtest",1],

                #fourtyfive
                ["golismero_finger","Golismero - Does a fingerprint on the Domain.","golismero",1],

                #fourtysix
                ["uniscan_filebrute","Uniscan - Brutes for Filenames on the Domain.","uniscan",1],

                #fourtyseven
                ["uniscan_dirbrute", "Broken Link Checker - Checks for Broken Links","uniscan",1],

                #fourtyeight
                ["uniscan_ministresser", "LFI - Checks for LFI","uniscan",1],

                #fourtynine
                ["uniscan_rfi","RCE - Checks for RCE","uniscan",1],

                #fifty
                ["uniscan_xss","Uniscan - Checks for XSS, SQLi, BSQLi & Other Checks.","uniscan",1],

                #fiftyone
                ["nikto_xss","Nikto - Checks for Apache Expect XSS Header.","nikto",1],

                #fiftytwo
                ["nikto_subrute","Sensitive Data Exposure - Checks for Sensitive info","nikto",1],

                #fiftythree
                ["nikto_shellshock","Nikto - Checks for Shellshock Bug.","nikto",1],

                #fiftyfour
                ["nikto_internalip","Nikto - Checks for Internal IP Leak.","nikto",1],

                #fiftyfive
                ["nikto_putdel","Broken Access Control - Checks for BAAC","nikto",1],

                #fiftysix
                ["nikto_headers","Nikto - Checks the Domain Headers.","nikto",1],
                
                #fiftyseven
                ["nikto_ms01070","Nikto - Checks for MS10-070 Vulnerability.","nikto",1],

                #fiftyeight
                ["nikto_servermsgs","Nikto - Checks for Server Issues.","nikto",1],

                #fiftynine
                ["nikto_outdated","Nikto - Checks if Server is Outdated.","nikto",1],

                #sixty
                ["nikto_httpoptions","Nikto - Checks for HTTP Options on the Domain.","nikto",1],

                #sixtyone
                ["nikto_cgi","Nikto - Enumerates CGI Directories.","nikto",1],

                #sixtytwo
                ["nikto_ssl","Nikto - Performs SSL Checks.","nikto",1],

                #sixtythree
                ["nikto_sitefiles","Nikto - Checks for any interesting files on the Domain.","nikto",1],

                #sixtyfour
                ["nikto_paths","Nikto - Checks for Injectable Paths.","nikto",1],

                #sixtyfive
                ["dnsmap_brute","DNSMap - Brutes Subdomains.","dnsmap",1],

                #sixtysix
                ["nmap_sqlserver","Nmap - Checks for MS-SQL Server DB","nmap",1],

                #sixtyseven
                ["nmap_mysql", "Nmap - Checks for MySQL DB","nmap",1],

                #sixtyeight
                ["nmap_oracle", "Nmap - Checks for ORACLE DB","nmap",1],

                #sixtynine
                ["nmap_rdp_udp","Nmap - Checks for Remote Desktop Service over UDP","nmap",1],

                #seventy
                ["nmap_rdp_tcp","Nmap - Checks for Remote Desktop Service over TCP","nmap",1],

                #seventyone
                ["nmap_full_ps_tcp","Nmap - Performs a Full TCP Port Scan","nmap",1],

                #seventytwo
                ["nmap_full_ps_udp","Nmap - Performs a Full UDP Port Scan","nmap",1],

                #seventythree
                ["nmap_snmp","Nmap - Checks for SNMP Service","nmap",1],

                #seventyfour
                ["aspnet_elmah_axd","Checks for ASP.net Elmah Logger","wget",1],

                #seventyfive
                ["nmap_tcp_smb","Checks for SMB Service over TCP","nmap",1],

                #seventysix
                ["nmap_udp_smb","Checks for SMB Service over UDP","nmap",1],

                #seventyseven
                ["wapiti","Wapiti - Checks for SQLi, RCE, XSS and Other Vulnerabilities","wapiti",1],

                #seventyeight
                ["nmap_iis","Nmap - Checks for IIS WebDAV","nmap",1],

                #seventynine
                ["whatweb","WhatWeb - Checks for X-XSS Protection Header","whatweb",1],

            ]

tool_cmd   = [
                ["host ",""],

                
                ["wget -O /tmp/safesweep_temp_aspnet_config_err --tries=1 ","/%7C~.aspx"],

                
                ["wget -O /tmp/safesweep_temp_wp_check --tries=1 ","/wp-admin"],

                
                ["wget -O /tmp/safesweep_temp_drp_check --tries=1 ","/user"],

                
                ["wget -O /tmp/safesweep_temp_joom_check --tries=1 ","/administrator"],

                
                ["uniscan -e -u ",""],

                
                ["wafw00f ",""],

                
                ["nmap -F --open -Pn ",""],

                
                ["subfinder -d ",""],

                
                ["dnsrecon -d ",""],

                
                ["amass -d ",""],

                
                ["dnswalk -d ","."],

                
                ["whois ",""],

                
                ["nmap -p80 --script http-security-headers -Pn ",""],

                
                ["nmap -p80,443 --script http-slowloris --max-parallelism 500 -Pn ",""],

                
                ["sslyze --heartbleed ",""],

                
                ["nmap -p443 --script ssl-heartbleed -Pn ",""],

                
                ["nmap -p443 --script ssl-poodle -Pn ",""],

                
                ["nmap -p443 --script ssl-ccs-injection -Pn ",""],

                
                ["nmap -p443 --script ssl-enum-ciphers -Pn ",""],

                
                ["nmap -p443 --script ssl-dh-params -Pn ",""],

                
                ["sslyze --certinfo=basic ",""],

                
                ["sslyze --compression ",""],

                
                ["sslyze --reneg ",""],

                
                ["sslyze --resum ",""],

                
                ["lbd ",""],

                
                ["golismero -e dns_malware scan ",""],

                
                ["golismero -e heartbleed scan ",""],

                
                ["golismero -e brute_url_predictables scan ",""],

                
                ["golismero -e brute_directories scan ",""],

                
                ["golismero -e sqlmap scan ",""],

                
                ["dirb http://"," -fi"],

                
                ["xsser --all=http://",""],

                
                ["golismero -e sslscan scan ",""],

                
                ["golismero -e zone_transfer scan ",""],

                
                ["golismero -e nikto scan ",""],

                
                ["golismero -e brute_dns scan ",""],

                
                ["dnsenum ",""],

                
                ["fierce --domain ",""],

                
                ["dmitry -e ",""],

                
                ["dmitry -s ",""],

                
                ["nmap -p23 --open -Pn ",""],

                
                ["nmap -p21 --open -Pn ",""],

                
                ["nmap --script stuxnet-detect -p445 -Pn ",""],

                
                ["davtest -url http://",""],

                
                ["golismero -e fingerprint_web scan ",""],

                
                ["uniscan -w -u ",""],

                
                ["uniscan -q -u ",""],

                
                ["uniscan -r -u ",""],

                
                ["uniscan -s -u ",""],

                
                ["uniscan -d -u ",""],

                
                ["nikto -Plugins 'apache_expect_xss' -host ",""],

                
                ["nikto -Plugins 'subdomain' -host ",""],

                
                ["nikto -Plugins 'shellshock' -host ",""],

                
                ["nikto -Plugins 'cookies' -host ",""],

                
                ["nikto -Plugins 'put_del_test' -host ",""],

                
                ["nikto -Plugins 'headers' -host ",""],

                
                ["nikto -Plugins 'ms10-070' -host ",""],

                
                ["nikto -Plugins 'msgs' -host ",""],

                
                ["nikto -Plugins 'outdated' -host ",""],

                
                ["nikto -Plugins 'httpoptions' -host ",""],

                
                ["nikto -Plugins 'cgi' -host ",""],

                
                ["nikto -Plugins 'ssl' -host ",""],

                
                ["nikto -Plugins 'sitefiles' -host ",""],

                
                ["nikto -Plugins 'paths' -host ",""],

                
                ["dnsmap ",""],

                
                ["nmap -p1433 --open -Pn ",""],

                
                ["nmap -p3306 --open -Pn ",""],

                
                ["nmap -p1521 --open -Pn ",""],

                
                ["nmap -p3389 --open -sU -Pn ",""],

                
                ["nmap -p3389 --open -sT -Pn ",""],

                
                ["nmap -p1-65535 --open -Pn ",""],

                
                ["nmap -p1-65535 -sU --open -Pn ",""],

                
                ["nmap -p161 -sU --open -Pn ",""],

                
                ["wget -O /tmp/safesweep_temp_aspnet_elmah_axd --tries=1 ","/elmah.axd"],

                
                ["nmap -p445,137-139 --open -Pn ",""],

                
                ["nmap -p137,138 --open -Pn ",""],

                
                ["wapiti "," -f txt -o safesweep_temp_wapiti"],

                
                ["nmap -p80 --script=http-iis-webdav-vuln -Pn ",""],
                
                
                ["whatweb "," -a 1"],

                
                ["amass enum -d ",""],
               
                
                ["subfinder -d ",""]
            ]

tool_resp   = [
                #1
                ["Does not have an IPv6 Address. It is good to have one.","i",1],

                #2
                ["ASP.Net is misconfigured to throw server stack errors on screen.","m",2],

                #3
                ["WordPress Installation Found. Check for vulnerabilities corresponds to that version.","i",3],

                #4
                ["Drupal Installation Found. Check for vulnerabilities corresponds to that version.","i",4],

                #5
                ["Joomla Installation Found. Check for vulnerabilities corresponds to that version.","i",5],

                #6
                ["robots.txt/sitemap.xml found. Check those files for any information.","i",6],

                #7
                ["No Web Application Firewall Detected","m",7],

                #8
                ["Some ports are open. Perform a full-scan manually.","l",8],

                #9
                ["Email Addresses Found.","l",9],

                #10
                ["Zone Transfer Successful using DNSRecon. Reconfigure DNS immediately.","h",10],

                #11
                #["Zone Transfer Successful using fierce. Reconfigure DNS immediately.","h",10],

                #12
                ["Zone Transfer Successful using dnswalk. Reconfigure DNS immediately.","h",10],

                #13
                ["Whois Information Publicly Available.","i",11],

                #14
                ["XSS Protection Filter is Disabled.","m",12],

                #15
                ["Vulnerable to Slowloris Denial of Service.","c",13],

                #16
                ["HEARTBLEED Vulnerability Found with SSLyze.","h",14],

                #17
                ["HEARTBLEED Vulnerability Found with Nmap.","h",14],

                #18
                ["POODLE Vulnerability Detected.","h",15],

                #19
                ["OpenSSL CCS Injection Detected.","h",16],

                #20
                ["FREAK Vulnerability Detected.","h",17],

                #21
                ["LOGJAM Vulnerability Detected.","h",18],

                #22
                ["Unsuccessful OCSP Response.","m",19],

                #23
                ["Server supports Deflate Compression.","m",20],

                #24
                ["Secure Client Initiated Renegotiation is supported.","m",21],

                #25
                ["Secure Resumption unsupported with (Sessions IDs/TLS Tickets).","m",22],

                #26
                ["No DNS/HTTP based Load Balancers Found.","l",23],

                #27
                ["Domain is spoofed/hijacked.","h",24],

                #28
                ["HEARTBLEED Vulnerability Found with Golismero.","h",14],

                #29
                ["Open Files Found with Golismero BruteForce.","m",25],

                #30
                ["Open Directories Found with Golismero BruteForce.","m",26],

                #31
                ["DB Banner retrieved with SQLMap.","l",27],

                #32
                ["Open Directories Found with DirB.","m",26],

                #33
                ["XSSer found XSS vulnerabilities.","c",28],

                #34
                ["Found SSL related vulnerabilities with Golismero.","m",29],

                #35
                ["Zone Transfer Successful with Golismero. Reconfigure DNS immediately.","h",10],

                #36
                ["Golismero Nikto Plugin found vulnerabilities.","m",30],

                #37
                ["Found Subdomains with Golismero.","m",31],

                #38
                ["Zone Transfer Successful using DNSEnum. Reconfigure DNS immediately.","h",10],

                #39
                ["Found Subdomains with Fierce.","m",31],

                #40
                ["Email Addresses discovered with DMitry.","l",9],

                #41
                ["Subdomains discovered with DMitry.","m",31],

                #42
                ["Telnet Service Detected.","h",32],

                #43
                ["FTP Service Detected.","c",33],

                #44
                ["Vulnerable to STUXNET.","c",34],

                #45
                ["WebDAV Enabled.","m",35],

                #46
                ["Found some information through Fingerprinting.","l",36],

                #47
                ["Open Files Found with Uniscan.","m",25],

                #48
                ["Open Directories Found with Uniscan.","m",26],

                #49
                ["Vulnerable to Stress Tests.","h",37],

                #50
                ["Uniscan detected possible LFI, RFI or RCE.","h",38],

                #51
                ["Uniscan detected possible XSS, SQLi, BSQLi.","h",39],

                #52
                ["Apache Expect XSS Header not present.","m",12],

                #53
                ["Found Subdomains with Nikto.","m",31],

                #54
                ["Webserver vulnerable to Shellshock Bug.","c",40],

                #55
                ["Webserver leaks Internal IP.","l",41],

                #56
                ["HTTP PUT DEL Methods Enabled.","m",42],

                #57
                ["Some vulnerable headers exposed.","m",43],

                #58
                ["Webserver vulnerable to MS10-070.","h",44],

                #59
                ["Some issues found on the Webserver.","m",30],

                #60
                ["Webserver is Outdated.","h",45],

                #61
                ["Some issues found with HTTP Options.","l",42],

                #62
                ["CGI Directories Enumerated.","l",26],

                #63
                ["Vulnerabilities reported in SSL Scans.","m",29],

                #64
                ["Interesting Files Detected.","m",25],

                #65
                ["Injectable Paths Detected.","l",46],

                #66
                ["Found Subdomains with DNSMap.","m",31],

                #67
                ["MS-SQL DB Service Detected.","l",47],

                #68
                ["MySQL DB Service Detected.","l",47],

                #69
                ["ORACLE DB Service Detected.","l",47],

                #70
                ["RDP Server Detected over UDP.","h",48],

                #71
                ["RDP Server Detected over TCP.","h",48],

                #72
                ["TCP Ports are Open","l",8],

                #73
                ["UDP Ports are Open","l",8],

                #74
                ["SNMP Service Detected.","m",49],

                #75
                ["Elmah is Configured.","m",50],

                #76
                ["SMB Ports are Open over TCP","m",51],

                #77
                ["SMB Ports are Open over UDP","m",51],

                #78
                ["Wapiti discovered a range of vulnerabilities","h",30],

                #79
                ["IIS WebDAV is Enabled","m",35],

                #80
                ["X-XSS Protection is not Present","m",12],

                #81
                ["Found Subdomains with AMass","m",31]



            ]

tool_status = [
                #1
                ["has IPv6",1,proc_low," < 15s","ipv6",["not found","has IPv6"]],

                #2
                ["Server Error",0,proc_low," < 30s","asp.netmisconf",["unable to resolve host address","Connection timed out"]],

                #3
                ["wp-login",0,proc_low," < 30s","wpcheck",["unable to resolve host address","Connection timed out"]],

                #4
                ["drupal",0,proc_low," < 30s","drupalcheck",["unable to resolve host address","Connection timed out"]],

                #5
                ["joomla",0,proc_low," < 30s","joomlacheck",["unable to resolve host address","Connection timed out"]],

                #6
                ["[+]",0,proc_low," < 40s","robotscheck",["Use of uninitialized value in unpack at"]],

                #7
                ["No WAF",0,proc_low," < 45s","wafcheck",["appears to be down"]],

                #8
                ["tcp open",0,proc_med," <  2m","nmapopen",["Failed to resolve"]],

                #9
                ["No emails found",1,proc_med," <  3m","harvester",["No hosts found","No emails found"]],

                #10
                ["[+] Zone Transfer was successful!!",0,proc_low," < 20s","dnsreconzt",["Could not resolve domain"]],

                #11
                #["Whoah, it worked",0,proc_low," < 30s","fiercezt",["none"]],

                #12
                ["0 errors",0,proc_low," < 35s","dnswalkzt",["!!!0 failures, 0 warnings, 3 errors."]],

                #13
                ["Admin Email:",0,proc_low," < 25s","whois",["No match for domain"]],

                #14
                ["XSS filter is disabled",0,proc_low," < 20s","nmapxssh",["Failed to resolve"]],

                #15
                ["VULNERABLE",0,proc_high," < 45m","nmapdos",["Failed to resolve"]],

                #16
                ["Server is vulnerable to Heartbleed",0,proc_low," < 40s","sslyzehb",["Could not resolve hostname"]],

                #17
                ["VULNERABLE",0,proc_low," < 30s","nmap1",["Failed to resolve"]],

                #18
                ["VULNERABLE",0,proc_low," < 35s","nmap2",["Failed to resolve"]],

                #19
                ["VULNERABLE",0,proc_low," < 35s","nmap3",["Failed to resolve"]],

                #20
                ["VULNERABLE",0,proc_low," < 30s","nmap4",["Failed to resolve"]],

                #21
                ["VULNERABLE",0,proc_low," < 35s","nmap5",["Failed to resolve"]],

                #22
                ["ERROR - OCSP response status is not successful",0,proc_low," < 25s","sslyze1",["Could not resolve hostname"]],

                #23
                ["VULNERABLE",0,proc_low," < 30s","sslyze2",["Could not resolve hostname"]],

                #24
                ["VULNERABLE",0,proc_low," < 25s","sslyze3",["Could not resolve hostname"]],

                #25
                ["VULNERABLE",0,proc_low," < 30s","sslyze4",["Could not resolve hostname"]],

                #26
                ["does NOT use Load-balancing",0,proc_med," <  4m","lbd",["NOT FOUND"]],

                #27
                ["No vulnerabilities found",1,proc_low," < 45s","golism1",["Cannot resolve domain name","No vulnerabilities found"]],

                #28
                ["No vulnerabilities found",1,proc_low," < 40s","golism2",["Cannot resolve domain name","No vulnerabilities found"]],

                #29
                ["No vulnerabilities found",1,proc_low," < 45s","golism3",["Cannot resolve domain name","No vulnerabilities found"]],

                #30
                ["No vulnerabilities found",1,proc_low," < 40s","golism4",["Cannot resolve domain name","No vulnerabilities found"]],

                #31
                ["No vulnerabilities found",1,proc_low," < 45s","golism5",["Cannot resolve domain name","No vulnerabilities found"]],

                #32
                ["FOUND: 0",1,proc_high," < 35m","dirb",["COULDNT RESOLVE HOST","FOUND: 0"]],

                #33
                ["Could not find any vulnerability!",1,proc_med," <  4m","xsser",["XSSer is not working propertly!","Could not find any vulnerability!"]],

                #34
                ["Occurrence ID",0,proc_low," < 45s","golism6",["Cannot resolve domain name"]],

                #35
                ["DNS zone transfer successful",0,proc_low," < 30s","golism7",["Cannot resolve domain name"]],

                #36
                ["Nikto found 0 vulnerabilities",1,proc_med," <  4m","golism8",["Cannot resolve domain name","Nikto found 0 vulnerabilities"]],

                #37
                ["Possible subdomain leak",0,proc_high," < 30m","golism9",["Cannot resolve domain name"]],

                #38
                ["AXFR record query failed:",1,proc_low," < 45s","dnsenumzt",["NS record query failed:","AXFR record query failed","no NS record for"]],

                #39
                ["Found 0 entries",1,proc_high," < 75m","fierce2",["Found 0 entries","is gimp"]],

                #40
                ["Found 0 E-Mail(s)",1,proc_low," < 30s","dmitry1",["Unable to locate Host IP addr","Found 0 E-Mail(s)"]],

                #41
                ["Found 0 possible subdomain(s)",1,proc_low," < 35s","dmitry2",["Unable to locate Host IP addr","Found 0 possible subdomain(s)"]],

                #42
                ["open",0,proc_low," < 15s","nmaptelnet",["Failed to resolve"]],

                #43
                ["open",0,proc_low," < 15s","nmapftp",["Failed to resolve"]],

                #44
                ["open",0,proc_low," < 20s","nmapstux",["Failed to resolve"]],

                #45
                ["SUCCEED",0,proc_low," < 30s","webdav",["is not DAV enabled or not accessible."]],

                #46
                ["No vulnerabilities found",1,proc_low," < 15s","golism10",["Cannot resolve domain name","No vulnerabilities found"]],

                #47
                ["[+]",0,proc_med," <  2m","uniscan2",["Use of uninitialized value in unpack at"]],

                #48
                ["[+]",0,proc_med," <  5m","uniscan3",["Use of uninitialized value in unpack at"]],

                #49
                ["[+]",0,proc_med," <  9m","uniscan4",["Use of uninitialized value in unpack at"]],

                #50
                ["[+]",0,proc_med," <  8m","uniscan5",["Use of uninitialized value in unpack at"]],

                #51
                ["[+]",0,proc_med," <  9m","uniscan6",["Use of uninitialized value in unpack at"]],

                #52
                ["0 item(s) reported",1,proc_low," < 35s","nikto1",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #53
                ["0 item(s) reported",1,proc_low," < 35s","nikto2",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #54
                ["0 item(s) reported",1,proc_low," < 35s","nikto3",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #55
                ["0 item(s) reported",1,proc_low," < 35s","nikto4",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #56
                ["0 item(s) reported",1,proc_low," < 35s","nikto5",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #57
                ["0 item(s) reported",1,proc_low," < 35s","nikto6",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #58
                ["0 item(s) reported",1,proc_low," < 35s","nikto7",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #59
                ["0 item(s) reported",1,proc_low," < 35s","nikto8",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #60
                ["0 item(s) reported",1,proc_low," < 35s","nikto9",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #61
                ["0 item(s) reported",1,proc_low," < 35s","nikto10",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #62
                ["0 item(s) reported",1,proc_low," < 35s","nikto11",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #63
                ["0 item(s) reported",1,proc_low," < 35s","nikto12",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #64
                ["0 item(s) reported",1,proc_low," < 35s","nikto13",["ERROR: Cannot resolve hostname","0 item(s) reported","No web server found","0 host(s) tested"]],

                #65
                ["0 item(s) reported",1,proc_low," < 35s","nikto14","ERROR: Cannot resolve hostname , 0 item(s) reported"],

                #66
                ["#1",0,proc_high," < 30m","dnsmap_brute",["[+] 0 (sub)domains and 0 IP address(es) found"]],

                #67
                ["open",0,proc_low," < 15s","nmapmssql",["Failed to resolve"]],

                #68
                ["open",0,proc_low," < 15s","nmapmysql",["Failed to resolve"]],

                #69
                ["open",0,proc_low," < 15s","nmaporacle",["Failed to resolve"]],

                #70
                ["open",0,proc_low," < 15s","nmapudprdp",["Failed to resolve"]],

                #71
                ["open",0,proc_low," < 15s","nmaptcprdp",["Failed to resolve"]],

                #72
                ["open",0,proc_high," > 50m","nmapfulltcp",["Failed to resolve"]],

                #73
                ["open",0,proc_high," > 75m","nmapfulludp",["Failed to resolve"]],

                #74
                ["open",0,proc_low," < 30s","nmapsnmp",["Failed to resolve"]],

                #75
                ["Microsoft SQL Server Error Log",0,proc_low," < 30s","elmahxd",["unable to resolve host address","Connection timed out"]],

                #76
                ["open",0,proc_low," < 20s","nmaptcpsmb",["Failed to resolve"]],

                #77
                ["open",0,proc_low," < 20s","nmapudpsmb",["Failed to resolve"]],

                #78
                ["Host:",0,proc_med," < 5m","wapiti",["none"]],

                #79
                ["WebDAV is ENABLED",0,proc_low," < 40s","nmapwebdaviis",["Failed to resolve"]],

                #80
                ["X-XSS-Protection[1",1,proc_med," < 3m","whatweb",["Timed out","Socket error","X-XSS-Protection[1"]],

                #81
                ["No names were discovered",1,proc_med," < 15m","amass",["The system was unable to build the pool of resolvers"]]



            ]

tools_fix = [
                    [1, "Just a warning with some information—not a vulnerability. The host does not support IPv6. As IPSec, which is in charge of CIA (Confidentiality, Integrity, and Availability), is incorporated into this paradigm, IPv6 offers additional security. So having IPv6 support is a good thing.",
                            "Implementing IPv6 is advised. This resource has more information on how to implement IPv6. https://www.cisco.com/c/en/us/solutions/collateral/enterprise/cisco-on-cisco/IPv6-Implementation_CS.html"],
                    [2, "Leakage of Sensitive Information Found. Illegal characters in the URL are not filtered out by the ASP.Net application. In order to have the program spew sensitive information about the server stack, the attacker injects a particular character (%7C.aspx).",
                            "Instead of displaying standard error messages in these circumstances, it is advised to filter out special characters in the URL and define a bespoke error page. With the aid of this resource, you can customize the error page for a Microsoft.Net application. https://docs.microsoft.com/en-us/aspnet/web-forms/overview/older-versions-getting-started/deploying-web-site-projects/displaying-a-custom-error-page-cs"],
                    [3, "Having a CMS in WordPress is not a negative thing. There is a possibility that the version or any third-party scripts linked with it contain vulnerabilities.",
                            "It is advised to hide the WordPress version. Detailed instructions on how to protect your WordPress blog may be found in this page. https://codex.wordpress.org/Hardening_WordPress"],
                    [4, "It's not a bad idea to have a CMS in Drupal. There is a possibility that the version or any third-party scripts linked with it contain vulnerabilities.",
                            "It is advised that the Drupal version be hidden. More information about securing your Drupal blog may be found in this page. https://www.drupal.org/docs/7/site-building-best-practices/ensure-that-your-site-is-secure"],
                    [5, "It's not a bad idea to have a CMS in Joomla. There is a possibility that the version or any third-party scripts linked with it contain vulnerabilities.",
                            "It is advised that the Joomla version be hidden. More information about securing your Joomla Blog may be found in this link. https://www.incapsula.com/blog/10-tips-to-improve-your-joomla-website-security.html"],
                    [6, "Robots.txt or sitemap.xml files may occasionally contain directives that prevent crawlers and search engines from accessing or indexing particular links. Although search engines could overlook some links, attackers can still obtain the information directly.",
                            "Not include sensitive links in the robots or sitemap files is a recommended practice."],
                    [7, "In the absence of a Web Application Firewall, an attacker may attempt to inject various attack patterns manually or through automated scanners. An automated scanner may send swarms of attack vectors and patterns to validate an attack; however, the application may be DoS'ed (Denial of Service)",
                            "Web Application Firewalls provide excellent protection against common web attacks such as XSS, SQLi, and others. They also add another layer of protection to your security infrastructure. This resource provides information on web application firewalls that may be appropriate for your application."],
                    [8, "Open Ports give attackers a hint to exploit the services. Attackers attempt to retrieve banner information via ports in order to determine what type of service the host is providing.",
                            "It is recommended that unused service ports be closed and that a firewall be used to filter ports as needed. This resource may provide additional information. https://security.stackexchange.com/a/145781/6137"],
                    [9, "It is recommended that unused service ports be closed and that a firewall be used to filter ports as needed. This resource may provide additional information.",
                            "There is no need to take action because the chances of exploitation are slim. Choosing different usernames for different services would be a more thoughtful solution."],
                    [10, "Zone Transfer reveals important topological data about the target. The attacker will be able to query all records and will have a good understanding of your host.",
                            "It is best practice to limit Zone Transfer by informing the Master of the IP addresses of the slaves that can be granted access for the query. More details are available in this SANS resource. https://www.sans.org/reading-room/whitepapers/dns/securing-dns-zone-transfer-868"],
                    [11, "The administrator's email address and other contact information (address, phone number, etc.) are public. An attacker could use this information to launch an attack. Because this is not a vulnerability, it cannot be used to launch a direct attack. An attacker, on the other hand, uses this information to learn more about the target.",
                            "Some administrators may have purposefully made this information public; in this case, it can be ignored. If not, it is recommended that the information be hidden. This site has information on how to do it. http://www.name.com/blog/how-tos/tutorial-2/2013/06/protect-your-personal-information-with-whois-privacy/"],
                    [12, "Because the target lacks this header, older browsers are vulnerable to Reflected XSS attacks.",
                            "Modern browsers are not affected by this vulnerability (missing headers). However, it is strongly advised that older browsers be upgraded."],
                    [13, "This attack works by opening multiple concurrent connections to the web server and keeping them alive for as long as possible by sending partial HTTP requests that are never completed. They can easily bypass IDS by sending partial requests.",
                            "If you're using Apache Module,'mod antiloris' will come in handy. This resource contains more detailed remediation for other setups. https://www.acunetix.com/blog/articles/slow-http-dos-attacks-mitigate-apache-http-server/"],
                    [14, "This vulnerability exposes sensitive information about your host. An attacker can maintain the TLS connection and retrieve up to 64K of data per heartbeat.",
                            "To make decryption more difficult, PFS (Perfect Forward Secrecy) can be used. Complete remediation and resource information can be found on this page. http://heartbleed.com/"],
                    [15, "By exploiting this vulnerability, an attacker can gain access to sensitive data in an encrypted session, such as session ids and cookies, and then use that data to impersonate that specific user.",
                            "This is a vulnerability in the SSL 3.0 protocol. A better solution would be to disable the use of the SSL 3.0 protocol.  https://www.us-cert.gov/ncas/alerts/TA14-290A"],
                    [16, "This attack occurs during the SSL Negotiation (Handshake), rendering the client unaware of the attack. By successfully altering the handshake, the attacker will gain access to all information sent from the client to the server and vice versa.",
                            "Upgrading OpenSSL to the latest versions will solve this problem. More information about the vulnerability and the associated remediation can be found in this resource. http://ccsinjection.lepidum.co.jp/"],
                    [17, "With this vulnerability the attacker will be able to perform a MiTM attack and thus compromising the confidentiality factor.",
                            "Upgrading OpenSSL to the latest version will solve this problem. Versions prior to 1.1.0 are vulnerable to this flaw. This resource contains additional information. https://bobcares.com/blog/how-to-fix-sweet32-birthday-attacks-vulnerability-cve-2016-2183/"],
                    [18, "The LogJam attack allows the attacker to downgrade the TLS connection, allowing the attacker to read and modify any data passed over the connection.",
                            "Check that any TLS libraries you use are up to date, that servers use 2048-bit or larger primes, and that clients reject Diffie-Hellman primes smaller than 1024 bits. This resource contains additional information. https://weakdh.org/"],
                    [19, "Allows remote attackers to cause a denial of service (crash) and potentially obtain sensitive information in OpenSSL-enabled applications by sending a malformed ClientHello handshake message that results in an out-of-bounds memory access.",
                            " Versions of OpenSSL 0.9.8h through 0.9.8q, as well as 1.0.0 through 1.0.0c, are vulnerable. It is strongly advised to upgrade the OpenSSL version. More resources and information are available here. https://www.openssl.org/news/secadv/20110208.txt"],
                    [20, "The BREACH atack, as it is also known, takes advantage of compression in the underlying HTTP protocol. An attacker can obtain email addresses, session tokens, and other information from TLS encrypted web traffic.",
                            "This vulnerability is not mitigated by disabling TLS compression. The first step in mitigation is to turn off Zlib compression, followed by the other measures listed in this resource. http://breachattack.com/"],
                    [21, "MiTM attackers can insert data into HTTPS sessions, and possibly other types of sessions protected by TLS or SSL, by sending an unauthenticated request that is processed retroactively by a server in a post-renegotiation context.",
                            "These resources contain detailed steps for remediation. https://securingtomorrow.mcafee.com/technical-how-to/tips-securing-ssl-renegotiation/ https://www.digicert.com/news/2011-06-03-ssl-renego/ "],
                    [22, "This flaw allows attackers to steal users' existing TLS sessions.",
                            "It is better to disable session resumption. Follow this resource for more information on hardening session resumption. https://wiki.crashtest-security.com/display/KB/Harden+TLS+Session+Resumption"],
                    [23, "This has nothing to do with security risks, but attackers may exploit the lack of load balancers to launch a denial of service attack against specific services or the entire application.",
                            "Load balancers are strongly recommended for any web application. They improve performance as well as data availability during server outages. Check out this resource for more information on load balancers and how to set them up. https://www.digitalocean.com/community/tutorials/what-is-load-balancing"],
                    [24, "An attacker can redirect requests to a legitimate URL or web application to a third-party address or the attacker's location, where malware can be served and affect the end user's machine.",
                            "It is strongly advised to install DNSSec on the host target. The full implementation of DNSSEC ensures that the end user is connecting to the actual web site or other service associated with a specific domain name. See this website for more information. https://www.cloudflare.com/dns/dnssec/how-dnssec-works/"],
                    [25, "These files may contain a significant amount of information that attackers can use. These files may also provide attackers with access to sensitive information.",
                            "It is recommended that access to these files be blocked or restricted unless absolutely necessary."],
                    [26, "These directories can provide attackers with a wealth of information. These directories may also provide attackers with access to sensitive information.",
                            "It is recommended that access to these directories be blocked or restricted unless absolutely necessary."],
                    [27, "SQLi vulnerability may not exist. An attacker will be able to determine that the host is running on a backend.",
                            "Banner grabbing should be restricted, and external access to services should be kept to a minimum."],
                    [28, "An attacker can steal cookies, deface web applications, and redirect to any third-party address that can serve malware.",
                            "Cross Site Scripting (XSS) attacks can be completely avoided with input validation and output sanitization. XSS attacks can be avoided in the future by adhering to a secure coding methodology. The comprehensive resource listed below contains detailed information on how to fix this vulnerability. https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet"],
                    [29, "SSL vulnerabilities compromise the confidentiality factor. An attacker could use a MiTM attack to intercept and eavesdrop on the communication.",
                            "When it comes to preventing SSL-related vulnerabilities, proper implementation and upgraded versions of SSL and TLS libraries are critical."],
                    [30, "A specific Scanner discovered multiple vulnerabilities that an attacker could exploit to gain access to the target."
"Once the scan is complete, refer to RS-Vulnerability-Report to view the complete information of the vulnerability."],
                    [31, "Subdomains related to the parent domain may provide additional information to attackers. Attackers may also discover other services from the subdomains and attempt to learn the target's architecture. As the attack surface expands and more subdomains are discovered, the attacker has a better chance of discovering vulnerabilities.",
                            "It is sometimes prudent to restrict access to subdomains such as development and staging to the outside world, as this provides the attacker with more information about the tech stack. Complex naming practices also help to reduce the attack surface by making it difficult for attackers to perform subdomain bruteforcing using dictionaries and wordlists."],
                    [32, "An attacker may be able to perform MiTM and other complex attacks using this deprecated protocol.",
                            "It is strongly advised to discontinue use of this service, which is out of date. TELNET can be replaced with SSH. See this link for more information. https://www.ssh.com/ssh/telnet"],
                    [33, "This protocol does not support secure communication, and the attacker has a high chance of intercepting the communication. Furthermore, many FTP programs have web-based exploits that allow an attacker to either directly crash the application or gain SHELL access to that target.",
                            "The proper solution is to use SSH instead of FTP. It enables secure communication, and MiTM attacks are extremely unlikely."],
                    [34, "The StuxNet worm is a level 3 worm that exposes sensitive information about the target organization. It was a cyber weapon designed to disrupt Iran's nuclear intelligence. I'm curious how it got here. Nmap, I hope this isn't a false positive ;)",
                            "It is strongly advised to run a full rootkit scan on the host. Refer to this resource for more information.https://www.symantec.com/security_response/writeup.jsp?docid=2010-071400-3123-99&tabid=3"],
                    [35, "WebDAV is supposed to have a number of flaws. In some cases, an attacker may conceal a malicious DLL file in the WebDAV share and, after convincing the user to open a perfectly harmless and legitimate file, execute code in that user's context.",
                            "It is recommended that WebDAV be disabled. This URL contains some critical information about disabling WebDAV. https://www.networkworld.com/article/2202909/network-security/-webdav-is-bad---says-security-researcher.html"],
                    [36, "Before launching an attack, attackers always perform a fingerprint on any server. Fingerprinting provides information about the server type, the content they are serving, the last modification times, and so on, allowing an attacker to learn more about the target.",
                            "Obfuscating information to the outside world is a good practice. As a result, attackers will have a difficult time understanding the server's technology stack and thus leveraging an attack."],
                    [37, "Attackers typically try to render web applications or services useless by flooding the target, preventing legitimate users from accessing them. This can have an impact on a company's or organization's business as well as its reputation.",
                            "Such attacks can be significantly mitigated by ensuring proper load balancers are in place, configuring rate limits, and multiple connection restrictions."],
                    [38, "Intruders will be able to remotely include shell files and thus gain access to the core file system, as well as read all files. The attacker has a better chance of remotely executing code on the file system.",
                            "Most LFI, RFI, and RCE attacks can be avoided by using secure code practices. The following resource provides in-depth information on secure coding practices. https://wiki.sei.cmu.edu/confluence/display/seccode/Top+10+Secure+Coding+Practices"],
                    [39, "Hackers will be able to steal data from the backend, authenticate themselves to the website, and impersonate any user because they have complete control over the backend. They have the ability to completely destroy the database. Attackers can also steal an authenticated user's cookie information and redirect the target to any malicious address or completely deface the application.",
                            "Prior to directly querying the database information, proper input validation must be performed. A developer should remember not to rely on end-user feedback. By employing a secure coding methodology, attacks such as SQLi, XSS, and BSQLi can be avoided. The resources listed below explain how to use secure coding methodology in application development.https://wiki.sei.cmu.edu/confluence/display/seccode/Top+10+Secure+Coding+Practices"],
                    [40, "Attackers use the BASH vulnerability to execute remote code on the target. An experienced attacker can easily take over the target system and gain access to the machine's internal sources.",
                            "This vulnerability can be mitigated by updating the BASH version. The resource below provides a detailed analysis of the vulnerability and how to mitigate it. https://www.symantec.com/connect/blogs/shellshock-all-you-need-know-about-bash-bug-vulnerability https://www.digitalocean.com/community/tutorials/how-to-protect-your-server-against-the-shellshock-bash-vulnerability"],
                    [41, "Provides the attacker with information about how address scheming is done internally on the organizational network. Discovering an organization's private addresses can aid attackers in carrying out network-layer attacks aimed at breaching the organization's internal infrastructure.",
                            "Restrict the revealing service's banner information to the outside world. More information on how to protect against this vulnerability can be found here. https://portswigger.net/kb/issues/00600300_private-ip-addresses-disclosed"],
                    [42, "An attacker has the ability to manipulate files on the webserver.",
                            "If you do not use any REST API Services, it is recommended that you disable the HTTP PUT and DEL methods. The resources listed below will show you how to disable these methods. http://www.techstacks.com/howto/disable-http-methods-in-tomcat.html https://docs.oracle.com/cd/E19857-01/820-5627/gghwc/index.html https://developer.ibm.com/answers/questions/321629/how-to-disable-http-methods-head-put-delete-option/"],
                    [43, "The amount of information exposed in the headers allows attackers to learn more about the target. An attacker may be aware of the type of technology stack emphasized by a web application, among other things.",
                            "Banner grabbing should be restricted, and external access to services should be kept to a minimum."],
                    [44, "An attacker who successfully exploited this vulnerability could read data encrypted by the server, such as the view state. This vulnerability can also be used for data tampering, which could be used to decrypt and tamper with the data encrypted by the server if successfully exploited.",
                            "Microsoft has issued a set of patches to address this issue, which can be found on their website. This resource contains the information needed to fix this vulnerability. https://docs.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-070"],
                    [45, "Because their support has lapsed, any outdated web server may contain multiple vulnerabilities. An attacker may take advantage of such an opportunity to launch an attack.",
                            "It is strongly advised to upgrade the web server to the most recent version available."],
                    [46, "Hackers will be able to easily manipulate the URLs via a GET/POST request. They will be able to easily inject multiple attack vectors into the URL while also monitoring the response.",
                            "It will be impossible for the attacker to penetrate through if proper sanitization techniques and secure coding practices are used. The following resource provides in-depth information on secure coding practices. https://wiki.sei.cmu.edu/confluence/display/seccode/Top+10+Secure+Coding+Practices"],
                    [47, "Since the attacker has knowledge about the particular type of backend the target is running, they will be able to launch a targetted exploit for the particular version. They may also try to authenticate with default credentials to get themselves through.",
                            "Timely security patches for the backend has to be installed. Default credentials has to be changed. If possible, the banner information can be changed to mislead the attacker. The following resource gives more information on how to secure your backend. http://kb.bodhost.com/secure-database-server/"],
                    [48, "Attackers may launch remote exploits to either crash the service or tools like ncrack to try brute-forcing the password on the target.",
                            "It is recommended to block the service to outside world and made the service accessible only through the a set of allowed IPs only really neccessary. The following resource provides insights on the risks and as well as the steps to block the service. https://www.perspectiverisk.com/remote-desktop-service-vulnerabilities/"],
                    [49, "Hackers will be able to read community strings through the service and enumerate quite a bit of information from the target. Also, there are multiple Remote Code Execution and Denial of Service vulnerabilities related to SNMP services.",
                            "Use a firewall to block the ports from the outside world. The following article gives wide insight on locking down SNMP service. https://www.techrepublic.com/article/lock-it-down-dont-allow-snmp-to-compromise-network-security/"],
                    [50, "Attackers will be able to find the logs and error information generated by the application. They will also be able to see the status codes that was generated on the application. By combining all these information, the attacker will be able to leverage an attack.",
                            "By restricting access to the logger application from the outside world will be more than enough to mitigate this weakness."],
                    [51, "Cyber criminals primarily target this service because it is much easier for them to conduct a remote attack using exploits.One such example is the WannaCry Ransomware.",
"Exposing SMB Service to the outside world is a bad idea; it is recommended to install the most recent patches for the service to avoid compromise. The following resource contains comprehensive information on SMB Hardening concepts. https://kb.iweb.com/hc/en-us/articles/115000274491-Securing-Windows-SMB-and-NetBios-NetBT-Services"]
            ]

tools_precheck = [
                    ["wapiti"], ["whatweb"], ["nmap"], ["golismero"], ["host"], ["wget"], ["uniscan"], ["wafw00f"], ["dirb"], ["davtest"], ["subfinder"], ["xsser"], ["dnsrecon"],["fierce"], ["dnswalk"], ["whois"], ["sslyze"], ["lbd"], ["golismero"], ["dnsenum"],["dmitry"], ["davtest"], ["nikto"], ["dnsmap"], ["sqlmap"], ["gau"], ["gf"], ["waybackurls"]
                 ]

def get_parser():

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('-h', '--help', action='store_true', 
                        help='Show help message and exit.')
    parser.add_argument('-u', '--update', action='store_true', 
                        help='Update SafeSweep.')
    parser.add_argument('-s', '--skip', action='append', default=[],
                        help='Skip some tools', choices=[t[0] for t in tools_precheck])
    parser.add_argument('-n', '--nospinner', action='store_true', 
                        help='Disable the idle loader/spinner.')
    parser.add_argument('target', nargs='?', metavar='URL', help='URL to scan.', default='', type=str)
    return parser

scan_shuffle = list(zip(tool_meme, tool_cmd, tool_resp, tool_status))
random.shuffle(scan_shuffle)
tool_meme, tool_cmd, tool_resp, tool_status = zip(*scan_shuffle)
tool_checks = (len(tool_meme) + len(tool_resp) + len(tool_status)) / 3
tool_checks = round(tool_checks)

tool = 0

runTest = 1

arg1 = 0
arg2 = 1
arg3 = 2
arg4 = 3
arg5 = 4
arg6 = 5

ss_vul_list = list()
ss_vul_num = 0
ss_vul = 0

ss_avail_tools = 0


if len(sys.argv) == 1:
    logo()
    helper()
    sys.exit(1)

args_namespace = get_parser().parse_args()

if args_namespace.nospinner:
    spinner.disabled = True

if args_namespace.help or (not args_namespace.update \
    and not args_namespace.target):
    logo()
    helper()
elif args_namespace.update:
    logo()
    print("SafeSweep is updating....Please wait.\n")
    spinner.start()
    ss_internet_availability = check_internet()
    if ss_internet_availability == 0:
        print("\t"+ bcolors.BG_ERR_TXT + "There seems to be some problem connecting to the internet. Please try again or later." +bcolors.ENDC)
        spinner.stop()
        sys.exit(1)
    cmd = 'sha1sum safesweep.py | grep .... | cut -c 1-40'
    oldversion_hash = subprocess.check_output(cmd, shell=True)
    oldversion_hash = oldversion_hash.strip()
    os.system('wget -N https://raw.githubusercontent.com/cybercatofficial/safesweep/master/safesweep.py -O safesweep.py > /dev/null 2>&1')
    newversion_hash = subprocess.check_output(cmd, shell=True)
    newversion_hash = newversion_hash.strip()
    if oldversion_hash == newversion_hash :
        clear()
        print("\t"+ bcolors.OKBLUE +"You already have the latest version of SafeSweep." + bcolors.ENDC)
    else:
        clear()
        print("\t"+ bcolors.OKGREEN +"SafeSweep successfully updated to the latest version." +bcolors.ENDC)
    spinner.stop()
    sys.exit(1)

elif args_namespace.target:
    target = url_maker(args_namespace.target)
    os.system('rm /tmp/safesweep* > /dev/null 2>&1') # Clearing previous scan files
    os.system('clear')
    os.system('setterm -cursor off')
    logo()
    print(bcolors.BG_HEAD_TXT+"[ Checking Available Security Scanning Tools Phase... Initiated. ]"+bcolors.ENDC)
    unavail_tools_meme = list()
    while (ss_avail_tools < len(tools_precheck)):
        precmd = str(tools_precheck[ss_avail_tools][arg1])
        try:
            p = subprocess.Popen([precmd], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,shell=True)
            output, err = p.communicate()
            val = output + err
        except:
            print("\t"+bcolors.BG_ERR_TXT+"SafeSweep was terminated abruptly..."+bcolors.ENDC)
            sys.exit(1)
        if b"not found" in val or tools_precheck[ss_avail_tools][arg1] in args_namespace.skip :
            if b"not found" in val:
                print("\t"+bcolors.OKBLUE+tools_precheck[ss_avail_tools][arg1]+bcolors.ENDC+bcolors.BADFAIL+"...unavailable."+bcolors.ENDC)
            elif tools_precheck[ss_avail_tools][arg1] in args_namespace.skip :
                print("\t"+bcolors.OKBLUE+tools_precheck[ss_avail_tools][arg1]+bcolors.ENDC+bcolors.BADFAIL+"...skipped."+bcolors.ENDC)
            
            for scanner_index, scanner_val in enumerate(tool_meme):
                if scanner_val[2] == tools_precheck[ss_avail_tools][arg1]:
                    scanner_val[3] = 0 # disabling scanner as it's not available.
                    unavail_tools_meme.append(tools_precheck[ss_avail_tools][arg1])

        else:
            print("\t"+bcolors.OKBLUE+tools_precheck[ss_avail_tools][arg1]+bcolors.ENDC+bcolors.OKGREEN+"...available."+bcolors.ENDC)
        ss_avail_tools = ss_avail_tools + 1
        clear()
    unavail_tools_meme = list(set(unavail_tools_meme))
    if len(unavail_tools_meme) == 0:
        print("\t"+bcolors.OKGREEN+"All Scanning Tools are available. Complete vulnerability checks will be performed by SafeSweep."+bcolors.ENDC)
    else:
        print("\t"+bcolors.WARNING+"Some of these tools "+bcolors.BADFAIL+str(unavail_tools_meme)+bcolors.ENDC+bcolors.WARNING+" are unavailable or will be skipped. SafeSweep will still perform the rest of the tests. Install these tools to fully utilize the functionality of SafeSweep."+bcolors.ENDC)
    print(bcolors.BG_ENDL_TXT+"[ Checking Available Security Scanning Tools Phase... Completed. ]"+bcolors.ENDC)
    print("\n")
    print(bcolors.BG_HEAD_TXT+"[ Preliminary Scan Phase Initiated... Loaded "+str(tool_checks)+" vulnerability checks. ]"+bcolors.ENDC)
    #while (tool < 1):
    while(tool < len(tool_meme)):
        print("["+tool_status[tool][arg3]+tool_status[tool][arg4]+"] Deploying "+str(tool+1)+"/"+str(tool_checks)+" | "+bcolors.OKBLUE+tool_meme[tool][arg2]+bcolors.ENDC,)
        if tool_meme[tool][arg4] == 0:
            print(bcolors.OKBLUE+"\nScan Completed in "+display_time(int(elapsed))+bcolors.ENDC, end='\r', flush=True)
            tool = tool + 1
            continue
        try:
            spinner.start()
        except Exception as e:
            print("\n")
        scan_start = time.time()
        temp_file = "/tmp/safesweep_temp_"+tool_meme[tool][arg1]
        cmd = tool_cmd[tool][arg1]+target+tool_cmd[tool][arg2]+" > "+temp_file+" 2>&1"

        try:
            subprocess.check_output(cmd, shell=True)
        except KeyboardInterrupt:
            runTest = 0
        except:
            runTest = 1

        if runTest == 1:
                spinner.stop()
                scan_stop = time.time()
                elapsed = scan_stop - scan_start
                sys.stdout.write(ERASE_LINE)
                print(bcolors.OKBLUE+"\nScan Completed in "+display_time(int(elapsed))+bcolors.ENDC, end='\r', flush=True)
                print("\n")
                ss_tool_output_file = open(temp_file).read()
                if tool_status[tool][arg2] == 0:
                    if tool_status[tool][arg1].lower() in ss_tool_output_file.lower():
                        vul_remed_info(tool,tool_resp[tool][arg2],tool_resp[tool][arg3])
                        ss_vul_list.append(tool_meme[tool][arg1]+"*"+tool_meme[tool][arg2])
                else:
                    if any(i in ss_tool_output_file for i in tool_status[tool][arg6]):
                        m = 1
                    else:
                        vul_remed_info(tool,tool_resp[tool][arg2],tool_resp[tool][arg3])
                        ss_vul_list.append(tool_meme[tool][arg1]+"*"+tool_meme[tool][arg2])
        else:
                runTest = 1
                spinner.stop()
                scan_stop = time.time()
                elapsed = scan_stop - scan_start 
                sys.stdout.write(ERASE_LINE)
                print(bcolors.OKBLUE+"\nScan Interrupted in "+display_time(int(elapsed))+bcolors.ENDC, end='\r', flush=True)
                print("\n"+bcolors.WARNING + "\tTest Skipped. Performing Next. Press Ctrl+Z to Quit SafeSweep.\n" + bcolors.ENDC)

        tool=tool+1

    print(bcolors.BG_ENDL_TXT+"[ Preliminary Scan Phase Completed. ]"+bcolors.ENDC)
    print("\n")
    date = subprocess.Popen(["date", "+%Y-%m-%d"],stdout=subprocess.PIPE).stdout.read()[:-1].decode("utf-8")
    debuglog = "ss.dbg.%s.%s" % (target, date) 
    vulreport = "vulnreport.%s.%s" % (target, date)
    print(bcolors.BG_HEAD_TXT+"[ Report Generation Phase Initiated. ]"+bcolors.ENDC)
    if len(ss_vul_list)==0:
        print("\t"+bcolors.OKGREEN+"No Vulnerabilities Detected."+bcolors.ENDC)
    else:
        with open(vulreport, "a") as report:
            while(ss_vul < len(ss_vul_list)):
                vuln_info = ss_vul_list[ss_vul].split('*')
                report.write(vuln_info[arg2])
                report.write("\n------------------------\n\n")
                temp_report_name = "/tmp/safesweep_temp_"+vuln_info[arg1]
                with open(temp_report_name, 'r') as temp_report:
                    data = temp_report.read()
                    report.write(data)
                    report.write("\n\n")
                temp_report.close()
                ss_vul = ss_vul + 1

            print("\tComplete Vulnerability Report for "+bcolors.OKBLUE+target+bcolors.ENDC+" named "+bcolors.OKGREEN+vulreport+bcolors.ENDC+" is available under the same directory SafeSweep resides.")

        report.close()
    for file_index, file_name in enumerate(tool_meme):
        with open(debuglog, "a") as report:
            try:
                with open("/tmp/safesweep_temp_"+file_name[arg1], 'r') as temp_report:
                        data = temp_report.read()
                        report.write(file_name[arg2])
                        report.write("\n------------------------\n\n")
                        report.write(data)
                        report.write("\n\n")
                temp_report.close()
            except:
                break
        report.close()
    print("\tTotal Number of Vulnerability Checks        : "+bcolors.BOLD+bcolors.OKGREEN+str(len(tool_meme))+bcolors.ENDC)
    print("\tTotal Number of Vulnerabilities Detected    : "+bcolors.BOLD+bcolors.BADFAIL+str(len(ss_vul_list))+bcolors.ENDC)
    print("\n")
    print("\tFor Debugging Purposes, You can view the complete output generated by all the tools named "+bcolors.OKBLUE+debuglog+bcolors.ENDC+" under the same directory.")
    print(bcolors.BG_ENDL_TXT+"[ Report Generation Phase Completed. ]"+bcolors.ENDC)

    os.system('setterm -cursor on')
    os.system('rm /tmp/safesweep_te* > /dev/null 2>&1')

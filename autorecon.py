#! /usr/bin/python2

import argparse
import re
import sys
from tld import get_fld
from email_validator import validate_email, EmailNotValidError
# prevent creation of compiled bytecode files
sys.dont_write_bytecode = True
from recon.core import base
from recon.core.framework import Colors
from recon.core.framework import Framework

def output(string):
    print('{}[*]{} {}'.format(Colors.B, Colors.N, string))

def init_keys(config_file):
    try:
        key_conf = open(config_file)
    except IOError as e:
        output('Reading configure file error: {}'.format(str(e)))
        exit(-1)
    x = base.Recon(mode=base.Mode.CLI)
    # init workspace
    x.init_workspace('default')
    for line in key_conf.readlines():
        line = line.strip()
        if not len(line) or line.startswith('#'):
            continue
        key, value = line.split('=')
        if not key:
            output('Config filr error at line:{}'.format(line))
            return
        if not value:
            continue
        x.onecmd('keys add {} {}'.format(key, value))
    key_conf.close()

def search_module(text):
    '''Searches available modules'''
    if not text:
        return
    output('Searfching for {}'.format(text))
    modules = [x for x in Framework._loaded_modules if text in x]
    if not modules:
        output("No modules found containing '{}'.".format(text))
        return
    else:
        return modules

def set_workspace(workspace):
    x = base.Recon(mode=base.Mode.CLI)
    # init workspace
    x.init_workspace(workspace)
    output('WORKSPACE => {}'.format(workspace))
    x.onecmd("set TIMEOUT 30")
    x.onecmd("set THREADS 10")
    x.onecmd('set NAMESERVER 114.114.114.114')
    x.onecmd(('set USER-AGENT Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.1; '
              'Trident/4.0; GTB7.4; InfoPath.2; SV1; .NET CLR 3.3.69573; WOW64; en-US)'))
    output('')
    return x

def autodomain(workspace,domain):
    fld = get_fld(domain, fix_protocol=True, fail_silently=True)
    if not fld:
        output('{} is not a valid domain name or subdomain name'.format(domain))
        return
    x = set_workspace(workspace)
    # search working modules
    domain_modules = search_module('domains-')
    if not domain_modules:
        output('No modules for working')
        return
    # init SOURCE input
    for module in domain_modules:
        y = x.onecmd('load ' + module)
        if 'recon/domains-contacts/metacrawler' == module:
            y.onecmd(' set EXTRACT True')
        if 'recon/domains-hosts/bing_domain_api' == module:
            y.onecmd('set LIMIT 0')
        if 'recon/domains-hosts/builtwith' == module:
            y.onecmd('set SHOW_ALL False')
        if 'recon/domains-hosts/shodan_hostname' == module:
            y.onecmd('set LIMIT 1')
        if 'recon/domains-domains/brute_suffix' == module:
            y.onecmd('set SUFFIXES ata/suffixes.txt')
        if 'recon/domains-hosts/brute_hosts' == module:
            y.onecmd('set WORDLIST data/hostnames.txt')
        if 'recon/domains-vulnerabilities/ghdb' == module:
            y.onecmd('set GHDB_ADVISORIES_AND_VULNERABILITIES False')
            y.onecmd('set GHDB_ERROR_MESSAGES False')
            y.onecmd('set GHDB_FILES_CONTAINING_JUICY_INFO False')
            y.onecmd('set GHDB_FILES_CONTAINING_PASSWORDS False')
            y.onecmd('set GHDB_FILES_CONTAINING_USERNAMES False')
            y.onecmd('set GHDB_FOOTHOLDS False')
            y.onecmd('set GHDB_NETWORK_OR_VULNERABILITY_DATA False')
            y.onecmd('set GHDB_PAGES_CONTAINING_LOGIN_PORTALS False')
            y.onecmd('set GHDB_SENSITIVE_DIRECTORIES False')
            y.onecmd('set GHDB_SENSITIVE_ONLINE_SHOPPING_INFO False')
            y.onecmd('set GHDB_VARIOUS_ONLINE_DEVICES False')
            y.onecmd('set GHDB_VULNERABLE_FILES False')
            y.onecmd('set GHDB_VULNERABLE_SERVERS False')
            y.onecmd('set GHDB_WEB_SERVER_DETECTION False')
            y.onecmd('set DORKS False')
        y.onecmd('set SOURCE ' + fld)
        y.onecmd('run')

def autohost(workspace, host):
    fld = get_fld(host, fix_protocol=True, fail_silently=True)
    if not fld:
        output('{} is not a valid domain name or subdomain name'.host)
        return
    x = set_workspace(workspace)
    # if subd0omjain name, addx it to hosts
    if fld != host:
        x.onecmd('addm hosts {}~~~~~'.format(host))
    y = x.onecmd('load recon/hosts-domains/migrate_hosts')
    y.onecmd('set SOURCE default')
    y.onecmd('run')
    y = x.onecmd('load recon/hosts-hosts/resolve')
    y.onecmd('set SOURCE default')
    y.onecmd('run')
    y = x.onecmd('load recon/hosts-hosts/reverse_resolve')
    y.onecmd('set SOURCE default')
    y.onecmd('run')
    y = x.onecmd('load recon/hosts-ports/shodan_ip')
    y.onecmd('set SOURCE default')
    y.onecmd('run')

def autonetblock(workspace, netblock):
    nb_pattern = re.compile(('(?:(?:2[0-4][0-9]\.)|(?:25[0-5]\.)|(?:1[0-9][0-9]\.)|'
        '(?:[1-9][0-9]\.)|(?:[0-9]\.)){3}(?:(?:2[0-5][0-5])|(?:25[0-5])|'
        '(?:1[0-9][0-9])|(?:[1-9][0-9])|(?:[0-9]))\/(?:\d|[1-2]\d|3[0-2])'))
    if not nb_pattern.match(netblock):
        output('{} is not a valid IP netblock'.format(netblock))
        return
    cidr_string = netblock.split('/')[1]
    if not cidr_string.isdigit():
        output('{} is not a valid number'.format(cidr_string))
        return
    cidr_int = int(cidr_string)
    if cidr_int < 0 or cidr_int > 32:
        output('{} must be in 0~32'.format(cidr_int))
        return
    x = set_workspace(workspace)
    # search working modules
    netblock_modules = search_module('netblocks-')
    if not netblock_modules:
        output('No modules for working')
        return
    for module in netblock_modules:
        y = x.onecmd('load ' + module)
        if 'recon/netblocks-hosts/shodan_net' == module:
            y.onecmd('set LIMIT 1')
        if 'recon/netblocks-ports/censysio' == module:
            y.onecmd('set LIMIT Trye')
            y.onecmd('set RATE 0.2')
        y.onecmd('set SOURCE ' + netblock)
        y.onecmd('run')

def autoemail(workspace, email):
    try:
        v = validate_email(email)  # validate and get info
        email_v = v["email"]  # replace with normalized form
    except EmailNotValidError as e:
        # email is not valid, exception message is human-readable
        output('{} format error'.format(email))
        output(str(e))
        return
    x = set_workspace(workspace)
    # search working modules
    contacts_modules = search_module('contacts-')
    if not contacts_modules:
        output('No modules for working')
        return
    for module in contacts_modules:
        y = x.onecmd('load ' + module)
        y.onecmd('set SOURCE ' + email_v)
        y.onecmd('run')

def autocompany(workspace, company):
    x = set_workspace(workspace)
    # search working modules
    company_modules = search_module('companies-')
    if not company_modules:
        output('No modules for working')
        return
    for module in company_modules:
        y = x.onecmd('load ' + module)
        y.onecmd('set SOURCE ' + company)
        y.onecmd('run')

def autousername(workspace, username):
    x = set_workspace(workspace)
    # search working modules
    username_modules = search_module('profiles-')
    if not username_modules:
        output('No modules for working')
        return
    for module in username_modules:
        y = x.onecmd('load ' + module)
        y.onecmd('set SOURCE ' + username)
        y.onecmd('run')

def autoresport(workspace):
    x = set_workspace(workspace)
    y = x.onecmd('load reporting/json')
    y.onecmd(('set TABLES domains, companies, netblocks, locations, vulnerabilities, ports, '
              'hosts, contacts, credentials, leaks, profiles, repositories'))
    y.onecmd('set FILENAME reports/{}.json'.format(workspace))
    y.onecmd('run')
    y = x.onecmd('load reporting/csv')
    y.onecmd(('set TABLE hosts'))
    y.onecmd('set FILENAME reports/{}.csv'.format(workspace))
    y.onecmd('run')
    y = x.onecmd('load reporting/html')
    y.onecmd('set CREATOR Victor')
    y.onecmd('set CUSTOMER ' + workspace)
    y.onecmd('set FILENAME reports/{}.html'.format(workspace))
    y.onecmd('run')

def do_args_parse():
    description = 'Contact: {}<{}>'.format('Victor', 'victor_xxx@yeah.net')
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('-w', help='load/create a workspace', metavar='workspace',
                        dest='workspace', action='store', required=True)
    parser.add_argument('-d', help='input domain or subdomain name', metavar='(sub)domain-name',
                        dest='domain', action='store')
    parser.add_argument('-n', help='input CIDR formaT IP netblocks', metavar='netblocks',
                        dest='netblock', action='store')
    parser.add_argument('-e', help='input email address', metavar='email-address',
                        dest='email', action='store')
    parser.add_argument('-c', help='input company name', metavar='company-name',
                        dest='company', action='store')
    parser.add_argument('-u', help='input username', metavar='username',
                        dest='username', action='store')
    args = parser.parse_args()
    return args

def do_args_check(args):
    # check workspace
    if args.workspace:
        workspace = args.workspace
    # check domain or subdomain format
    if args.domain:
        autodomain(workspace, args.domain)
        autohost(workspace, args.domain)
    if args.netblock:
        autonetblock(workspace, args.netblock)
    if args.email:
        autoemail(workspace, args.email)
    if args.company:
        autocompany(workspace, args.company)
    if args.username:
        autousername(workspace, args.username)
    autoresport(workspace)

if __name__ == "__main__":
    init_keys('keys.conf')
    args = do_args_parse()
    do_args_check(args)
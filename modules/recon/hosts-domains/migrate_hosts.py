from recon.core.module import BaseModule
import os
import re
from tld import get_fld


class Module(BaseModule):

    meta = {
        'name': 'Hosts to Domains Data Migrator',
        'author': 'Tim Tomes (@LaNMaSteR53)',
        'description': 'Adds a new domain for all the hostnames stored in the \'hosts\' table.',
        'comments': (
            'This modules considers that everything after the first element could contain other hosts besides the current. Therefore, hosts > 2 domains deep will create domains > 2 elements in length.',
        ),
        'query': 'SELECT DISTINCT host FROM hosts WHERE host IS NOT NULL',
    }

    def module_run(self, hosts):
        # ip address regex
        regex = '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'
        # only migrate hosts that aren't ip addresses
        hosts = [x for x in hosts if not re.match(regex, x[0])]
        domains = []
        for host in hosts:
            domains.append(get_fld(host, fix_protocol=True,fail_silently=True))
        domains= set(domains)
        for domain in domains:
            self.add_domains(domain=domain)

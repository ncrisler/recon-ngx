from recon.core.module import BaseModule
from recon.mixins.resolver import ResolverMixin
from recon.mixins.threads import ThreadingMixin
import dns.resolver
import os

class Module(BaseModule, ResolverMixin, ThreadingMixin):

    meta = {
        'name': 'DNS Public Suffix Brute Forcer',
        'author': 'Marcus Watson (@BranMacMuffin)',
        'description': 'Multi-thread Brute forces TLDs and SLDs using DNS. Updates the \'domains\' table with the results.',
        'comments': (
            'TLDs and SLDs: https://publicsuffix.org/list/public_suffix_list.dat',
        ),
        'query': 'SELECT DISTINCT domain FROM domains WHERE domain IS NOT NULL',
        'options': (
            ('suffixes', os.path.join(BaseModule.data_path, 'suffixes.txt'), True, 'path to public suffix wordlist'),
        ),
    }

    def module_run(self, domains):
        resolver = self.get_resolver()
        with open(self.options['suffixes']) as fp:
            words = [line.strip().lower() for line in fp if len(line)>0 and line[0] is not '#']
        for domain in domains:
            self.heading(domain, level=0)
            domain_root = domain.split('.')[0]
            self.thread(words, domain_root, resolver)
            
    def module_thread(self, word, domain_root, resolver):
        max_attempts = 3
        attempt = 0
        while attempt < max_attempts:
            domain = '%s.%s' % (domain_root, word)
            try:
                answers = resolver.query(domain, 'SOA')
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
                self.verbose('%s => No record found.' % (domain))
            except dns.resolver.Timeout:
                self.verbose('%s => Request timed out.' % (domain))
                attempt += 1
                continue
            else:
                # process answers
                for answer in answers.response.answer:                                        
                    if answer.rdtype == 6:
                        soa = answer.name.to_text()[:-1]
                        self.alert('%s => (SOA) %s' % (domain, soa))
                        # use "host" rather than "soa" as sometimes the SOA record has a CNAME
                        self.add_domains(domain)
            # break out of the loop
            attempt = max_attempts

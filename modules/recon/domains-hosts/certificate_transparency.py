from recon.core.module import BaseModule
import json
import time
import random

class Module(BaseModule):

    meta = {
        'name': 'Certificiate Transparency Search',
        'author': 'Rich Warren (richard.warren@nccgroup.trust)',
        'description': ('Searches certificate transparency data from crt.sh, '
                        'adding newly identified hosts to the hosts table.'),
        'query': 'SELECT DISTINCT domain FROM domains WHERE domain IS NOT NULL',
    }

    def module_run(self, domains):
        for domain in domains:
            self.heading(domain, level=0)
            ua = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, '
                  'like Gecko) Chrome/60.0.3112.113 Safari/537.36	')
            resp = self.request('https://crt.sh/?output=json&q=%25.{0}'.format(domain), timeout=50,
                                headers={'User-Agent': ua})
            count = 0
            while resp.status_code != 200 and count < 10:
                #self.output('Invalid response for \'%s\'' % domain)
                resp = self.request('https://crt.sh/?output=json&q=%25.{0}'.format(domain), timeout=50,
                                    headers={'User-Agent': ua})
                count += 1
                time.sleep(random.randint(25, 55))
            fixed_raw = '[%s]' % resp.raw.replace('}{', '},{')
            for cert in json.loads(fixed_raw):
                self.add_hosts(cert.get('name_value'))

from recon.core.module import BaseModule
from datetime import datetime
import re

class Module(BaseModule):

    meta = {
        'name': 'XSSposed Domain Lookup',
        'author': 'Tim Tomes (@LaNMaSteR53)',
        'description': 'Checks XSSposed.com for XSS records associated with a domain.',
        'query': 'SELECT DISTINCT domain FROM domains WHERE domain IS NOT NULL',
    }
   
    def module_run(self, domains):
        for domain in domains:
            self.heading(domain, level=0)
            url = 'https://www.openbugbounty.org/api/1/search/?domain={0}'
            resp = self.request(url.format(domain))
            vulnsdomain = resp.xml.findall('item')
            for vuln in vulnsdomain:
                data = {}
                data['host'] = vuln.find('host').text
                data['reference'] = vuln.find('url').text
                data['publish_date'] = datetime.strptime(vuln.find('reporteddate').text, '%a, %d %b %Y %H:%M:%S +0000')
                data['category'] = vuln.find('type').text
                data['status'] = 'unfixed' if vuln.find('fixed').text == '0' else 'fixed'
                resp_vuln = self.request(data['reference'])
                data['example'] = re.search('href="([^"]*%s[^"]*)"' % (data['host']), resp_vuln.text).group(1)
                self.add_vulnerabilities(**data)

            url = 'https://www.openbugbounty.org/api/1/search/?domain=%.{0}'
            resp = self.request(url.format(domain))
            vulnssubdomains = resp.xml.findall('item')
            for vuln in vulnssubdomains:
                data = {}
                data['host'] = vuln.find('host').text
                data['reference'] = vuln.find('url').text
                data['publish_date'] = datetime.strptime(vuln.find('reporteddate').text, '%a, %d %b %Y %H:%M:%S +0000')
                data['category'] = vuln.find('type').text
                data['status'] = 'unfixed' if vuln.find('fixed').text == '0' else 'fixed'
                resp_vuln = self.request(data['reference'])
                data['example'] = re.search('href="([^"]*%s[^"]*)"' % (data['host']), resp_vuln.text).group(1)
                self.add_vulnerabilities(**data)

            if not vulnsdomain and not vulnssubdomains:
                self.output('No vulnerabilites found for {0}.'.format(domain))

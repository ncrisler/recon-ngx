from recon.core.module import BaseModule
import time
import urllib

class Module(BaseModule):

    meta = {
        'name': 'Have I been pwned? Breach Search',
        'author': 'Tim Tomes (@LaNMaSteR53) & Tyler Halfpop (@tylerhalfpop)',
        'description': ('Leverages the haveibeenpwned.com API to determine if email addresses are associated with'
                        ' breached credentials. Adds compromised email addresses to the \'credentials\' table.'),
        'comments': (
            'The API is rate limited to 1 request per 1.5 seconds.',
        ),
        'query': 'SELECT DISTINCT email FROM contacts WHERE email IS NOT NULL',
    }

    def module_run(self, accounts):
        # retrieve status
        base_url = 'https://haveibeenpwned.com/api/v2/{}/{}'
        endpoint = 'breachedaccount'
        for account in accounts:
            resp = self.request(base_url.format(endpoint, urllib.quote(account)))
            rcode = resp.status_code
            if rcode == 404:
                self.verbose('{} => Not Found.'.format(account))
            elif rcode == 400:
                self.error('{} => Bad Request.'.format(account))
                continue
            else:
                for breach in resp.json:
                    self.alert(('{} => Breach found! Seen in the {} breach that '
                                'occurred on {}.').format(account, breach['Title'], breach['BreachDate']))
                if 'Title' in breach and 'BreachDate' in breach:
                    leakinfo = breach['Title'] + ' # ' + breach['BreachDate']
                    self.add_credentials(account, leak=leakinfo)
            time.sleep(1.6)

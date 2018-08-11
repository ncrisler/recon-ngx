from recon.core.module import BaseModule
from recon.mixins.threads import ThreadingMixin
from lxml.html import fromstring
import time

class Module(BaseModule, ThreadingMixin):

    meta = {
        'name': 'NameChk.com Username Validator',
        'author': 'Tim Tomes (@LaNMaSteR53) and thrapt (thrapt@gmail.com)',
        'description': 'Leverages NameChk.com to validate the existance of usernames on specific web sites and updates the \'profiles\' table with the results.',
        'comments': (
            'Note: The global timeout option may need to be increased to support slower sites.',
        ),
        'query': 'SELECT DISTINCT username FROM profiles WHERE username IS NOT NULL',
    }

    def module_run(self, usernames):
        # retrieve list of sites
        self.verbose('Retrieving site data...')
        url = 'https://namechk.com/'
        resp = self.request(url)
        tree = fromstring(resp.text)
        # extract sites info from the page
        services = tree.xpath('//div[@class="box service"]/@data-name')
        for username in usernames:
            payload= {'q': username}
            resp = self.request(url, method='POST', payload=payload)
            token = resp.json['valid'].encode('unicode-escape').decode('string_escape')
            # required header for site requests
            headers = {'X-Requested-With': 'XMLHttpRequest', 'Accept': 'application/json'}
            self.heading(username, level=0)
            # validate memberships
            self.thread(services, token, headers)

    def module_thread(self, service, token, headers):
        url = 'https://namechk.com/services/check'
        payload = {'token': token,
                   'fat': 'xwSgxU58x1nAwVbP6+mYSFLsa8zkcl2q6NcKwc8uFm+TvFbN8LaOzmLOBDKza0ShvREINUhbwwljVe30LbKcQw==',
                   'service': service}
        fails = 1
        retries = 5
        while True:
            # build and send the request
            resp = self.request(url, method='POST', headers=headers, payload=payload)
            # retry a max # of times for server 500 error
            if 'error' in resp.json:
                if fails < retries:
                    fails += 1
                    time.sleep(3)
                    continue
            else:
                username = resp.json['username']
                available = resp.json['available']
                #status = resp.json['status']
                #reason = resp.json['failed_reason']
                profile = resp.json['callback_url']
                if available:
                    print('a'*100)
                    # update profiles table
                    self.add_profiles(username=username, resource=service, url=profile, category='social')
                    self.query('DELETE FROM profiles WHERE username = ? and url IS NULL', (username,))
            break

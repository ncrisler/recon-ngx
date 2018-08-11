from recon.core.module import BaseModule
import json

class Module(BaseModule):

    meta = {
        'name': 'ipstack.com',
        'author': 'Siarhei Harbachou (Tech.Insiders) and Gerrit Helm (G) and Tim Tomes (@LaNMaSteR53)',
        'description': 'Leverages the ipstack.com  API to geolocate a host by IP address. Updates the \'hosts\' table with the results.',
        'comments': (
            'Allows up to 10,000 queries per hour by default. Once this limit is reached, all requests will result in HTTP 403, forbidden, until the quota i$
        ),
        'query': 'SELECT DISTINCT ip_address FROM hosts WHERE ip_address IS NOT NULL',
        'options': (
            ('serverurl', 'http://api.ipstack.com', True, 'overwrite server url (e.g. for local installations)'),
            ('key', 'your_access_key', True, 'ipstack.com access key'),
         ),
    }

    def module_run(self, hosts):
        for host in hosts:
            url = '%s/%s?access_key=%s' % (self.options['serverurl'], host, self.options['key'])
            resp = self.request(url)

            if resp.json:
                jsonobj = resp.json
            else:
                self.error('Invalid JSON response for \'%s\'.\n%s' % (host, resp.text))
                continue
            print('response returned:')
            print (jsonobj)
            region = ', '.join([str(jsonobj[x]).title() for x in ['city', 'region_name'] if jsonobj[x]]) or None
            country = jsonobj['country_name'].title()
            latitude = str(jsonobj['latitude'])
            longitude = str(jsonobj['longitude'])
            self.output('%s - %s,%s - %s' % (host, latitude, longitude, ', '.join([x for x in [region, country] if x])))
            self.query('UPDATE hosts SET region=?, country=?, latitude=?, longitude=? WHERE ip_address=?', (region, country, latitude, longitude, host))

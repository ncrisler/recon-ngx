# recon-ngx

recon-ng for myself

Original link: https://bitbucket.org/LaNMaSteR53/recon-ng

# Installation

```
pip install -r REQUIREMENTS
```

# Usage

```
./autorecon.py -h
usage: autorecon.py [-h] -w workspace [-d subdomain-name] [-n netblocks]
                    [-e email-address] [-c company-name] [-u username]

Contact: Victor <victor_xxx@yeah.net>

optional arguments:
  -h, --help           show this help message and exit
  -w workspace         load/create a workspac
  -d (sub)domain-name  input domain or subdomain nam
  -n netblocks         input CIDR formaT IP netblocks
  -e email-address     input email address
  -c company-name      input company name
  -u username          input username
```

# API keys config (Optional)
```
cat keys.conf
# optional api keys
bing_api=
builtwith_api=
censysio_id=
censysio_secret=
flickr_api=
fullcontact_api=
github_api=
google_api=
google_cse=
hashes_api=
ipinfodb_api=
shodan_api=
```

# Key features
 
  - Automatically  run recon-ng modules
  - Automatically read API keys from config file
  - multiple input support: domain name, CIDR format netblocks and IP address, email address, company name, user name
  - Automatically export results in three formats: JSON, HJTML, CSV

# Todo

 - batch input support
 - more modules
 - optimize the program logic


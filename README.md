# Get newly registered domains

Automatic script to get new registered domains from whoisds.com public database.

## Requirements

* You need to create an account on: http://whois.domaintools.com/
* Install python requirements:

```sh
pip install -r requirements.txt
```

## Usage

* Open get-domains.conf and set all parameters. 
* if you want to run a simple query:
```
python get-domains.py -c get-domains.conf
```

* if you want to send a notification email if domains match keywords: 
```
python get-domains.py -c get-domains.conf --email my.email@work.com
```

## Crontab

You can create a crontab script to run it every day and get email notifications:
```
# Edit your crontab entry
crontab -e
# Add these lines to run the script at 8pm every day:
PYTHONIOENCODING=utf8
0 20 * * * /usr/bin/python /path/get-domains.py -c path/get-domains.conf --email my.email@work.com >> path/cron.log 2>&1
```

## License

GNU GPLv3

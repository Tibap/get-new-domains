#!/usr/bin/env python
# @author Dimitri Kirchner @ vancity
# Credits for the idea goes to: https://kaijento.github.io/2017/05/04/web-scraping-requests-eventtarget-viewstate/

import requests
import sys, os
from datetime import date
import zipfile
from time import sleep
from base64 import b64encode
from configparser import ConfigParser
from argparse import ArgumentParser

def get_config(config):
    """
    Parses config file and returns exchange data, whois data and misc data: (host, mailbox, user and password), (user, password), (storage_path, keywords)
    """
    try:
        c = ConfigParser()
        c.read(config)
    except OSError as e:
        print("Cannot read config file {}: {}".format(config, e.errno))
        sys.exit(-1)
        
    exchange_host = c.get('exchange', 'host')
    mailbox = c.get('exchange', 'mailbox')
    mail_user = c.get('exchange', 'user')
    mail_password = c.get('exchange', 'password')
    
    whois_user = c.get('whoisds', 'username')
    whois_password = c.get('whoisds', 'password')
    
    storage_path = c.get('misc', 'storage_path')
    keywords = c.get('misc', 'keywords').split(',')
    
    return (exchange_host, mailbox, mail_user, mail_password), (whois_user, whois_password), (storage_path, keywords)


def send_email(content, exchange_host, mailbox, mail_user, mail_password, dest_address):  
    """
    Sends an email to dest_address containing the list of potential malicious new domains.
    """
    from exchangelib import DELEGATE, Account, Configuration, Credentials, Message, Mailbox
    
    message = "Found the following potential malicious new domains: {}".format(content)

    creds = Credentials(username=mail_user, password=mail_password)
    serverconfig = Configuration(server=exchange_host, credentials=creds)
    account = Account(
        primary_smtp_address=mailbox,
        credentials=creds,
        autodiscover=False,
        config=serverconfig,
        access_type=DELEGATE
    )
    
    if account:
        print("Authenticated as {} to O365 succeeded.".format(mail_user))
    else:
        print("Authentication to O365 mailbox as {} has failed.".format(mail_user))
        sys.exit(-1)

    m = Message (
        account=account,
        subject='New domain alert',
        body=message,
        to_recipients=[
            Mailbox(email_address=dest_address),
        ]
    )
    m.send()
    
    print("Email has been sent to {}.".format(dest_address))

def main():
    parser = ArgumentParser(description = "Get newly registered domains to catch phishing attacks.")
    parser.add_argument('-c', '--config',
        dest = 'config_file',
        help = 'Configuration file',
        required = True,
        metavar = 'CONFIG')
    parser.add_argument('--email',
        dest = 'email_notification',
        help = 'Email to send the notification to. If not set, no notification will be sent.')
    
    args = parser.parse_args()
           
    if not os.path.isfile(args.config_file):
        print("[-]Configuration file {} is not readable.".format(args.config_file))
        sys.exit(-1);
    
    login_url = "https://whoisds.com/verifylogin/index"
    
    (exchange_host, mailbox, mail_user, mail_password), (whois_user, whois_password), (storage_path, keywords) = get_config(args.config_file)

    # Check keywords and storage_path parameters
    if not keywords:
        print ("[-]Keywords list is empty: {}".format(keywords))
        sys.exit(-1)
    if not os.path.exists(storage_path):
        print ("[-]Storage path does not exist: {}".format(storage_path))
        sys.exit(-1)
    # Other parameters will be trigger authentication errors
        
    postdata = {
        'username': whois_user,
        'password': whois_password
    }

    # Url has the form: https://whoisds.com//whois-database/newly-registered-domains/base64( date(YYYY-MM-DD).zip )/nrd
    # From the support team, the archive is uploaded at 9 am ist, which is 7:30 pm PST
    # However from experience, archive is empty for about 30-60 minutes
    day_to_extract = date.today().strftime("%Y-%m-%d")
    
    # If you want to take data from the day before
    #from datetime import timedelta
    #day_to_extract = (date.today() - timedelta(days=1)).strftime("%Y-%m-%d")
    print("Getting new domains from day: {}\nSearching for keywords: {}".format(day_to_extract, keywords))
    if args.email_notification:
        print("If any keywords match, an email will be sent to: {}".format(args.email_notification))

    temp = b64encode("{}.zip".format(day_to_extract).encode('ascii')).decode('utf-8')
    url = "https://whoisds.com/whois-database/newly-registered-domains/{}/nrd".format(temp)
    print ("Complete URL is: {}".format(url))

    # Store results in found_results
    found_results = []
    while True:
        with requests.Session() as s:
            s.headers['user-agent'] = 'Mozilla/5.0'
            r = s.post(login_url, postdata)
            if r.status_code != 200:
                print("Error: {}".format(r.content))
                sys.exit(-1)

            print ("Authentication has succeed")
    
            r = s.get(url)
            if r.status_code == 200:
                if r.content:
                    zip_file = os.path.join(storage_path, "{}-newly-domains.zip".format(day_to_extract))
                    print ("Writing data in {}".format(zip_file))
                    with open(zip_file, "wb") as f:
                        f.write( r.content )

                    # Decompressing ZIP file
                    with zipfile.ZipFile(zip_file, 'r') as zip_ref:
                        zip_ref.extractall( os.path.join(storage_path, "{}-newly-domains".format(day_to_extract)) )

                    # Parse file in the folder which is named domain-names.txt
                    domain_names_path = os.path.join(storage_path, "{}-newly-domains".format(day_to_extract), "domain-names.txt")
                    print("Reading domain list from {}".format(domain_names_path))
                    with open (domain_names_path, 'rt') as f:
                        domains_list = f.read().split()

                    # We can do more efficient than that but i don't think we are really time/perf contrained here
                    for keyword in keywords:
                        print("Searching for keyword: '{}'".format(keyword))
                        for domain in domains_list:
                            if keyword in domain:
                                print(" !!! Found potential phishing domain: {}".format(domain))
                                found_results.append(domain)

                    print("Job finished.")
                    break
                else:
                    print("Content is None, file may not exist?")
                    # The file is uploaded at 7:30 pm PST but may be empty. Let's sleep 10 minutes and retry.
                    sleep(10*60)
            else:
                print ("Status code != 200: {}".format(r.content))
                break
            
    # Send email if parameter has been set
    if found_results and args.email_notification:
        send_email(found_results, exchange_host, mailbox, mail_user, mail_password, args.email_notification)

if __name__ == "__main__":
    main()

import os
import sys
import dns.resolver
import socket
import json

from validate_email import validate_email
from email.mime.text import MIMEText
from smtplib import SMTP_SSL, SMTP  # this invokes the secure SMTP protocol (port 465, uses SSL)

if os.path.isfile('config.json'):
    with open('config.json', 'r') as f:
        config = json.load(f)

    smtp_server = config['SMTP_SERVER']
    smtp_receiver = config['SMTP_RECEIVER']
    smtp_sender = config['SMTP_SENDER']


def check_email(check_domain):
    output_type = True
    valid_format = validate_email(smtp_receiver)
    if valid_format is False:
        print("Please use a valid syntax on the email.")
        sys.exit(1)

    maildomain = smtp_receiver.split('@')[1]
    try:
        dns.resolver.query(maildomain, dns.rdatatype.NS)
        records = dns.resolver.query(maildomain, 'MX')
        mxrecord = records[0].exchange
        mxrecord = str(mxrecord)

        # Get local server hostname
        host = socket.gethostname()

        # SMTP lib setup (use debug level for full output)
        server = SMTP()
        server.set_debuglevel(0)

        # SMTP Conversation
        server.connect(mxrecord)
        server.ehlo(host)
        server.mail(smtp_sender)
        response_code, message = server.rcpt(str(smtp_receiver))
        server.quit()

        if response_code != 250:
            print("Please enter a valid email address.")
            sys.exit(1)

    except dns.resolver.NXDOMAIN:
        print("This receiver email does not exist, Please change it to send the email")
        sys.exit(1)
    except dns.resolver.Timeout:
        print("Resolver timed out")
        sys.exit(1)
    except dns.exception.DNSException:
        print("Unhandled Exception")
        sys.exit(1)
    except socket.error as e:
        print("SMTP Error:", e)
        output_type = False

    return output_type


def send_mail(subject, content, transfertime):
    content = "Dear Registrar," \
              " \n\n" \
              + content + \
              "\n" \
              + transfertime + \
              "\nYou can mail us if you have any questions. " \
              "You can reach us between 09:00 and 17:00 on Mondays till Fridays.\n" \
              "\nKind Regards, " \
              "\n\nSIDN"
    text_subtype = 'plain'

    try:
        msg = MIMEText(content, text_subtype)
        msg['Subject'] = subject
        msg['To'] = smtp_receiver

        conn = SMTP_SSL(smtp_server)
        conn.set_debuglevel(False)
        conn.login(smtp_sender, config['SMTP_PASSWORD'])
        try:
            conn.sendmail(smtp_sender, smtp_receiver, msg.as_string())
        finally:
            conn.quit()

    except:
        sys.exit("Mail failed, %s" % "Check your SMTP settings in the config.json")  # give an error messages

    return

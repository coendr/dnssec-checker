# import required libraries
import os
import dns.name
import dns.query
import dns.dnssec
import dns.message
import dns.resolver
import dns.rdatatype
import json
import sys

# Import custom libraries
from settings import sleep, args, str_to_bool, log, convert_date
from db import check_db, dn_db, key_db, rrsig_db
from email_notification import check_email, send_mail


# Set global result variables
result_zsk = 0
result_ds = 0
stop_zsk = False
stop_ds = False

# Set the Argument values in a variable to be used
domain = args.domain
zsk = args.zsk
ds = args.ds
repeat_query = args.continuetry
send_email = args.mail
ttl = 300
stop_rrsig = False

# Check if the config exists in the filesystem
if os.path.isfile('config.json'):
    # Open the JSON file in read mode if it exists
    with open('config.json', 'r') as f:
        config = json.load(f)

    # Check if some system arguments are not used and replaces them with the config version
    if domain is None:
        domain = config['DOMAIN_NAME']
    if zsk is None:
        if config['ZSK'] != "":
            zsk = config['ZSK']
        else:
            stop_zsk = True
    if ds is None:
        if config['DS'] != "":
            ds = config['DS']
        else:
            stop_ds = True
    if send_email is False:
        send_email = str_to_bool(config['USE_EMAIL'])
    if repeat_query is False:
        repeat_query = str_to_bool(config['CONTINUE_AFTER_ONE_TRY'])

# Connect to Database
check_db()


def check_domain():
    # User input fields for searching Domain, ZSK and registrar address
    check_domain.domain = domain
    if domain is not None:
        check_domain.domain = check_domain.domain.lower()
        # Check if the domain exists
        # If not rerun this command
        try:
            # get nameservers for target domain
            check_domain.response = dns.resolver.query(check_domain.domain, dns.rdatatype.NS)
            check_domain.nsname, check_domain.nsip = get_authoritative_nameserver(domain, log)
            check_domain.zsk = zsk
            check_domain.ds = ds

        except dns.resolver.NXDOMAIN:
            print("This domain name does not exist")
            sys.exit(0)
        except dns.resolver.Timeout:
            print("Resolver timed out")
            sys.exit(1)
        except dns.exception.DNSException:
            print("Unhandled Exception")
            sys.exit(1)

    else:
        print("No domain has been filled in")
        sys.exit(0)

    if send_email is True:
        # Check if email works otherwise fall back to printing in console method
        return check_email(check_domain)
    else:
        return send_email


def get_authoritative_nameserver(domain, log=lambda msg: None):
    n = dns.name.from_text(domain)

    depth = 2
    default = dns.resolver.get_default_resolver()
    nameserver = default.nameservers[0]

    last = False
    while not last:
        s = n.split(depth)

        last = s[0].to_unicode() == u'@'
        sub = s[1]

        log('Looking up %s on %s' % (sub, nameserver))
        query = dns.message.make_query(sub, dns.rdatatype.NS)
        response = dns.query.udp(query, nameserver)

        rcode = response.rcode()
        if rcode != dns.rcode.NOERROR:
            if rcode == dns.rcode.NXDOMAIN:
                raise Exception('%s does not exist.' % sub)
            else:
                raise Exception('Error %s' % dns.rcode.to_text(rcode))

        rrset = None
        if len(response.authority) > 0:
            rrset = response.authority[0]
        else:
            rrset = response.answer[0]

        rr = rrset[0]
        if rr.rdtype == dns.rdatatype.SOA:
            log('Same server is authoritative for %s' % sub)
        else:
            authority = rr.target
            log('%s is authoritative for %s' % (authority, sub))
            nameserver = default.query(authority).rrset[0].to_text()

        depth += 1
    return rr.target, nameserver


def check_resolver(domain):
    # We'll use the first nameserver
    resolver_response = dns.resolver.query(str(check_domain.nsname), dns.rdatatype.A)
    nsaddr = resolver_response.rrset[0].to_text()

    # get DNSKEY for zone
    request = dns.message.make_query(domain,
                                     dns.rdatatype.DNSKEY,
                                     want_dnssec=True)

    # send the query
    response = dns.query.udp(request, nsaddr)

    if response.rcode() != 0:
        # HANDLE QUERY FAILED (SERVER ERROR OR NO DNSKEY RECORD)
        # answer should contain two RRSET: DNSKEY and RRSIG(DNSKEY)

        answer = response.answer
        if len(answer) != 2:
            # SOMETHING WENT WRONG
            # the DNSKEY should be self signed, validate it
            name = dns.name.from_text(check_domain.domain)
            try:
                dns.dnssec.validate(answer[0], answer[1], {name: answer[0]})
            except dns.dnssec.ValidationFailure:
                print(dns.dnssec.ValidationFailure)
                return None
    else:
        # If DNSSEC is enabled on the domain and will search for the ZSK and RRSIG_DNSKEY with find_record()
        # Otherwise the result will return none
        print("\n")
        if len(response.answer) == 2:
            return response

        else:
            return None


def find_record(response, type="", find_string=""):
    # Find a specific record in the response based on the required find_string
    count = 0
    dnskeys = response.answer
    find_string = ''.join(find_string.split())
    ttl = 0

    type_format = {'ZSK': "DNSKEY 256", 'RRSIG_DNSKEY': 'RRSIG DNSKEY', 'RRSIG_DS': 'RRSIG DS', "DS": "DS"}
    zone_format = {'ZSK': "child", "DS": "Parent", 'NS': "Parent", 'RRSIG_DNSKEY': 'Child'}

    if type == 'RRSIG_DNSKEY':
        print("\n" + "The TTL's of the " + type, "in current", zone_format[type], "zones:")
    else:
        print("\n" + type, "in current", zone_format[type], "zone:")

    # Split all the DNSKEY records into an array
    # Find the ZSK string in the array
    # Returns the key in a print
    for key in dnskeys:
        keys = str(key).split("\n")
        for single_key in keys:
            if type_format[type] in single_key:
                splitted = single_key.split()
                domain_id = dn_db(splitted)
                if type == 'RRSIG_DNSKEY' or type == 'RRSIG_DS':
                    rrsig_db(domain_id, splitted)
                    count = int(splitted[1])
                else:
                    print(single_key)
                    key_db(domain_id, splitted)
                    single_key = splitted[7:]
                    single_key = ''.join(single_key)
                    if find_string == single_key:
                        count += 1

    return int(count)


# Check for the query response
def getzsk(domain, find_zsk):
    response = check_resolver(domain)
    if response is not None:
        found_zsk = find_record(response, "ZSK", find_zsk)
        return found_zsk
    else:
        return None


def getrrsig(domain):
    response = check_resolver(domain)
    if response is not None:
        found_ttl = find_record(response, "RRSIG_DNSKEY")
        return found_ttl
    else:
        return 300


def getds(domain, find_ds):
    request = dns.message.make_query(domain, dns.rdatatype.DS, want_dnssec=True)
    request.flags |= dns.flags.AD
    request.find_rrset(request.additional, dns.name.root, dns.rdataclass.IN,
                       dns.rdatatype.ANY, create=True, force_unique=True)
    response = dns.query.udp(request, "8.8.8.8")

    if len(response.answer) == 2:
        return find_record(response, "DS", find_ds)
    else:
        return 0


# Loop as long as the one or both stops are false
while stop_zsk is False or stop_ds is False:

    # Run the check_domain function if the variable is not set
    send_email = check_domain()

    # Put the response in the getter and find the ZSK
    if stop_zsk is False:
        result_zsk = getzsk(check_domain.domain, check_domain.zsk)

    # Put the response in the getter and find the ds
    if stop_ds is False:
        result_ds = getds(check_domain.domain, check_domain.ds)
    # Check if ZSK check has return nothing (NO DNSSEC)
    if result_zsk is None:
        # DNSSEC is not enabled on the domain
        # Sends a message to the user and ends the script
        print(check_domain.domain, "does not have DNSSEC enabled")
        stop_zsk = True
        stop_ds = True
        break

    # Get the RRSIG TTL of domain only once
    if stop_rrsig is False:
        check_domain.ttl = getrrsig(check_domain.domain)
        if check_domain.ttl <= 3600:
            print(check_domain.ttl, " -> ", check_domain.ttl / 60, "minutes")
            ttl_conv = str(int(check_domain.ttl / 60)) + " minutes"
        else:
            print(check_domain.ttl, " -> ", int(check_domain.ttl) / 3600, " hours")
            ttl_conv = str(int(check_domain.ttl / 3600)) + ' hours'
        stop_rrsig = True

    if result_zsk > 0:
        # Gaining ZSK is available in the zone , and sends the email (if possible) to the registrar and
        print("\nYour ZSK has appeared in the child zone for domain: " + check_domain.domain)
        if stop_zsk is False:
            print(check_domain.domain, "is ready for transfer with DNSSEC")
            if send_email is not False:
                print('start sending ZSK email...')
                subject = "Child zone updated for " + check_domain.domain
                content = "Your ZSK record has appeared in the child zone for domain: " + check_domain.domain
                tranfertime = "The domain can be tranfered at: " + convert_date(check_domain.ttl) + "."
                send_mail(subject, content, tranfertime)
                print('ZSK email send')
                # Stop the DS search after sending the email
                stop_zsk = True

    # Check if DS record has been found
    if result_ds > 0:
        # Gaining DS is  available in the parent zone , and sends the email (if possible) to the registrar
        print("\nYour DS record has appeared in the parent zone for domain: " + check_domain.domain)
        if stop_ds is False:
            print("Loosing ZSK in your child zone can be removed")
            if send_email is not False:
                print('start sending DS email...')
                subject = "Parent zone updated for " + check_domain.domain
                content = "Your DS record has appeared in the parent zone for domain: " + check_domain.domain
                tranfertime = "The NS record can be updated in the parent zone at: " + convert_date(check_domain.ttl) + "."
                send_mail(subject, content, tranfertime)
                print('DS email send')
                # Stop the DS search after sending the email
                stop_ds = True

    # Set the stop variables to true if repeat is false
    if repeat_query is False:
        stop_zsk = True
        stop_ds = True

    # Check if one or both stops are not true to make the script pause for a set time
    if stop_ds is False or stop_zsk is False:
        # Gaining ZSK and/ or DS is not available in the zone yet, try again automatically in TTL minutes
        print("\n \nSleeping search for", ttl_conv, "on", check_domain.domain)
        sleep(check_domain.ttl)



import sqlite3
from settings import current_time
import sys


def connect_database():
    # Connect to the database and return the connection
    conn = sqlite3.connect("dnssec_checker.db")
    c = conn.cursor()
    return conn, c


def create_table_key():
    # Creates table key
    conn, c = connect_database()
    c.execute('''
         CREATE TABLE IF NOT EXISTS key(id INTEGER PRIMARY KEY autoincrement, domain_id INT, ttl INT, type TEXT,
          flagfield INT, algorithm INT, key TEXT unique, first_seen TIMESTAMP, FOREIGN KEY(domain_id) 
          REFERENCES domainname(id))''')
    conn.commit()
    conn.close()


def create_table_domainname():
    # Creates table domainname
    conn, c = connect_database()
    c.execute('''CREATE TABLE IF NOT EXISTS domainname(id INTEGER PRIMARY KEY autoincrement, domain_name TEXT)''')
    conn.commit()
    conn.close()


def create_table_rrsig():
    # Creates table rrsig
    conn, c = connect_database()
    c.execute('''
        CREATE TABLE IF NOT EXISTS rrsig(id INTEGER PRIMARY KEY autoincrement, domain_id INT , ttl INT, type TEXT ,
        algorithm INT, expiration_date INT, inception_date INT, key_tag INT, pub_sig TEXT unique, FOREIGN KEY(domain_id) 
        REFERENCES domainname(id))''')
    conn.commit()
    conn.close()


def check_db():
    # Checks if database is available and gets the version
    conn, c = connect_database()
    # Requests the version of the database
    c.execute("SELECT sqlite_version()")
    version = c.fetchone()[0]
    conn.commit()

    # Checks if version is received
    if version:
        print("Database connection established")
        check_tables()

    else:
        print("An error has occurred with opening the database.")
        sys.exit(1)

    conn.close()


def dn_db(data):
    conn, c = connect_database()

    # Checks if value is already in database)
    data[0] = data[0][:-1]
    c.execute("SELECT count(*), id FROM domainname WHERE domain_name=(?)", (data[0],))
    conn.commit()

    # Fills in the domain name information in the database from main.py
    count_domain = c.fetchone()
    if int(count_domain[0]) == 0:
        c.execute("INSERT INTO domainname (domain_name) VALUES (?)", (data[0],))
        conn.commit()

    c.execute("SELECT id FROM domainname WHERE domain_name=(?)", (data[0],))
    conn.commit()
    count_domain = c.fetchone()
    conn.close()
    return count_domain[0]


def key_db(domain_id, data):
    # Checks if the information is DNSKEY or DS
    if data[3] == "DNSKEY" or data[3] == "DS":
        conn, c = connect_database()

        # Checks if value is already in database)
        c.execute("SELECT count(*) FROM key WHERE key=(?)", (''.join(data[7:]),))
        conn.commit()

        # Fills in the information in the database from main.py
        count_key = c.fetchone()
        if int(count_key[0]) == 0:
            zsk = ''.join(data[7:])
            c.execute("INSERT INTO key (domain_id, ttl, type, flagfield, algorithm, key, first_seen) "
                      "VALUES (?,?,?,?,?,?,?)",
                      (domain_id, data[1], data[3], data[4], data[5], zsk, current_time()))
            conn.commit()
        conn.close()


def rrsig_db(domain_id, data):
    conn, c = connect_database()

    # Checks if value is already in database)
    c.execute("SELECT count(*) FROM rrsig WHERE pub_sig=(?)", (''.join(data[12:]),))
    conn.commit()

    # fills in the information into the database form main.py
    count_rrsig = c.fetchone()
    if int(count_rrsig[0]) == 0:
        rrsig = ''.join(data[12:])
        c.execute("INSERT INTO rrsig (domain_id, ttl, type, algorithm, expiration_date, "
                  "inception_date, key_tag, pub_sig) "
                  "VALUES (?,?,?,?,?,?,?,?)",
                  (domain_id, data[1], data[3], data[5], data[8], data[9], data[10], rrsig))
        conn.commit()
    conn.close()


def check_tables():
    # Create tables if tables are not already made.
    create_table_key()
    create_table_domainname()
    create_table_rrsig()

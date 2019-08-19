import sys
import time
import argparse

from datetime import datetime, timedelta


# String to Boolean conversion
def str_to_bool(s):
    if s == 'True':
        return True
    elif s == 'False':
        return False
    else:
        raise ValueError  # evil ValueError that doesn't tell you what the wrong value was


# Sleep timer that counts down in the output
def sleep(t):
    while t >= 0:
        mins, secs = divmod(t, 60)
        hours, mins = divmod(mins, 60)
        if t >= 3600:
            timeformat = '{:02d}:{:02d}:{:02d}'.format(hours, mins, secs)
        elif t >= 60:
            timeformat = '{:02d}:{:02d}'.format(mins, secs)
        else:
            timeformat = '{:02d}'.format(secs)
        sys.stdout.write('\r' + "Retry searching in: " + timeformat)
        time.sleep(1)
        t -= 1

# Displays the current time
def current_time():
    timestamp = datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S')
    return timestamp


def log(msg):
    print(msg)


def convert_date(t):
    now = datetime.now()
    now = now + timedelta(seconds=t + 7200)
    ts = now.strftime("%d-%m-%Y %H:%M ")
    return ts


# Create new argument parser
parser = argparse.ArgumentParser()

# Add several optional arguments the user can use in the script
parser.add_argument('-v', '--version', action='version', version='DNS Zone Checker V1.0')
parser.add_argument('-r', '--repeat', dest="continuetry", default=False,
                    action='store_true', help="Repeat Querying after one try")
parser.add_argument('-e', '--email', dest="mail", default=False,
                    action='store_true', help="Send email after done querying (Must have config.json file enabled)")
parser.add_argument('-dm', '--domain', default=None, dest='domain', help='Search the given domain in resolver')
parser.add_argument('-zsk', default=None,
                    dest='zsk', help='Search the given ZSK key in the domain current child zone RRSET')
parser.add_argument('-ds', default=None,
                    dest='ds', help='Search the DS in the domain current Parent Zone RRSET')

# Put the parsed arguments in a variable to be used in the whole script
args = parser.parse_args()

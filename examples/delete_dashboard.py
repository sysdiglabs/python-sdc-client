#!/usr/bin/env python
#
# This example shows how to delete a dashboard
#

import getopt
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(sys.argv[0])), '..'))
from sdcclient import SdcClient

#
# Parse arguments
#
def usage():
    print 'usage: %s [-p|--pattern <name>] <sysdig-token>' % sys.argv[0]
    print '-p|--pattern: Delete all dashboards containing the provided pattern'
    print 'You can find your token at https://app.sysdigcloud.com/#/settings/user'
    sys.exit(1)

try:
    opts, args = getopt.getopt(sys.argv[1:],"p:",["pattern="])
except getopt.GetoptError:
    usage()

pattern = "API Test"
for opt, arg in opts:
    if opt in ("-p", "--pattern"):
        pattern = arg

if len(args) != 1:
    usage()

sdc_token = args[0]

#
# Instantiate the SDC client
#
sdclient = SdcClient(sdc_token)

#
# List the dashboards
#
res = sdclient.get_dashboards()
if not res[0]:
    print res[1]
    sys.exit(1)

#
# Delete all the dashboards containing pattern
#
for dashboard in res[1]['dashboards']:
    if pattern in dashboard['name']:
        print "Deleting " + dashboard['name']
        res = sdclient.delete_dashboard(dashboard)
        if not res[0]:
            print res[1]
            sys.exit(1)

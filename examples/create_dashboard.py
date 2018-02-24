#!/usr/bin/env python
#
# This example shows two easy ways to create a dasboard: using a view as a
# templeate, and copying another dashboard.
# In both cases, a filter is used to define what entities the new dashboard
# will monitor.
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
    print 'usage: %s [-d|--dashboard <name>] <sysdig-token>' % sys.argv[0]
    print '-d|--dashboard: Set name of dashboard to create'
    print 'You can find your token at https://app.sysdigcloud.com/#/settings/user'
    sys.exit(1)

try:
    opts, args = getopt.getopt(sys.argv[1:],"d:",["dashboard="])
except getopt.GetoptError:
    usage()

# Name for the dashboard to create
dashboardName = "API test - cassandra in prod"
for opt, arg in opts:
    if opt in ("-d", "--dashboard"):
        dashboardName = arg

if len(args) != 1:
    usage()

sdc_token = args[0]

#
# Instantiate the SDC client
#
sdclient = SdcClient(sdc_token)

#
# Create the new dashboard, applying to cassandra in production
#

# Name of the view to copy
viewName = "Overview by Process"
# Filter to apply to the new dashboard.
# Remember that you can use combinations of any segmentation criteria you find
# in Sysdig Cloud Explore page.
# You can also refer to AWS tags by using "cloudProvider.tag.*" metadata or
# agent tags by using "agent.tag.*" metadata
dashboardFilter = "kubernetes.namespace.name = prod and proc.name = cassandra"

print 'Creating dashboard from view'
res = sdclient.create_dashboard_from_view(dashboardName, viewName, dashboardFilter)
#
# Check the result
#
if res[0]:
    print 'Dashboard created successfully'
else:
    print res[1]
    sys.exit(1)

#
# Make a Copy the just created dasboard, this time applying it to cassandra in
# the dev namespace
#

# Name of the dashboard to copy
dashboardCopy = "Copy Of {}".format(dashboardName)
# Filter to apply to the new dashboard. Same as above.
dashboardFilter = "kubernetes.namespace.name = dev and proc.name = cassandra"

print 'Creating dashboard from dashboard'
res = sdclient.create_dashboard_from_dashboard(dashboardCopy, dashboardName, dashboardFilter)

#
# Check the result
#
if res[0]:
    print 'Dashboard copied successfully'
else:
    print res[1]
    sys.exit(1)

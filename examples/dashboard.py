#!/usr/bin/env python
#
# This example shows various functions to create a new dashboard or find an existing on,
# edit the content, and then delete it.
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
    print('usage: %s [-d|--dashboard <name>] <sysdig-token>' % sys.argv[0])
    print('-d|--dashboard: Set name of dashboard to create')
    print('You can find your token at https://app.sysdigcloud.com/#/settings/user')
    sys.exit(1)


try:
    opts, args = getopt.getopt(sys.argv[1:], "d:", ["dashboard="])
except getopt.GetoptError:
    usage()

dashboard_name = "My Dashboard"
for opt, arg in opts:
    if opt in ("-d", "--dashboard"):
        dashboard_name = arg

if len(args) != 1:
    usage()

sdc_token = args[0]

#
# Instantiate the SDC client
#
sdclient = SdcClient(sdc_token)


#
# Create an empty dashboard
#
dashboard_configuration = None
ok, res = sdclient.create_dashboard(dashboard_name)

# Check the result
if ok:
    print('Dashboard %d created successfully' % res['dashboard']['id'])
    dashboard_configuration = res['dashboard']
else:
    print(res)
    sys.exit(1)


#
# Find a dashboard by name
#
ok, res = sdclient.find_dashboard_by(dashboard_name)

# Check the result
if ok and len(res) > 0:
    print('Dashboard found')
    dashboard_configuration = res[0]['dashboard']
else:
    print(res)
    sys.exit(1)


#
# Add a time series
#
panel_name = 'CPU Over Time'
panel_type = 'timeSeries'
metrics = [
    {'id': 'kubernetes.pod.name'},
    {'id': 'cpu.used.percent', 'aggregations': {'time': 'avg', 'group': 'avg'}}
]
scope = 'kubernetes.namespace.name = "dev" and kubernetes.replicationController.name = "cassandra"'
ok, res = sdclient.add_dashboard_panel(dashboard_configuration, panel_name, panel_type, metrics, scope=scope)

# Check the result
if ok:
    print('Panel added successfully')
    dashboard_configuration = res['dashboard']
else:
    print(res)
    sys.exit(1)


#
# Add a top bar chart
#
panel_name = 'CPU by host'
panel_type = 'top'
metrics = [
    {'id': 'host.hostName'},
    {'id': 'cpu.used.percent', 'aggregations': {'time': 'avg', 'group': 'avg'}}
]
sort_by = {'metric': 'cpu.used.percent', 'mode': 'desc'}
limit = 10
ok, res = sdclient.add_dashboard_panel(dashboard_configuration, panel_name, panel_type, metrics, sort_by=sort_by, limit=limit)

# Check the result
if ok:
    print('Panel added successfully')
    dashboard_configuration = res['dashboard']
else:
    print(res)
    sys.exit(1)


#
# Add a number panel
#
panel_name = 'CPU'
panel_type = 'number'
metrics = [
    {'id': 'cpu.used.percent', 'aggregations': {'time': 'avg', 'group': 'avg'}}
]
layout = {'col': 6, 'row': 1, 'size_x': 2, 'size_y': 3}
ok, res = sdclient.add_dashboard_panel(dashboard_configuration, panel_name, panel_type, metrics, layout=layout)

# Check the result
if ok:
    print('Panel added successfully')
    dashboard_configuration = res['dashboard']
else:
    print(res)
    sys.exit(1)


#
# Remove a panel
#
ok, res = sdclient.remove_dashboard_panel(dashboard_configuration, 'CPU')

# Check the result
if ok:
    print('Panel removed successfully')
    dashboard_configuration = res['dashboard']
else:
    print(res)
    sys.exit(1)


#
# Delete the dashboard
#
ok, res = sdclient.delete_dashboard(dashboard_configuration)

# Check the result
if ok:
    print('Dashboard deleted successfully')
else:
    print(res)
    sys.exit(1)

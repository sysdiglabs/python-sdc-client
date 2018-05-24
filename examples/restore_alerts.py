#!/usr/bin/env python
#
# Restore Alerts of the format in a JSON dumpfile from the list_alerts.py example.
#

import os
import sys
import json
import datetime
import calendar
sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(sys.argv[0])), '..'))
from sdcclient import SdcClient

#
# Parse arguments
#
if len(sys.argv) != 3:
    print 'usage: %s <sysdig-token> <file-name>' % sys.argv[0]
    print 'You can find your token at https://app.sysdigcloud.com/#/settings/user'
    sys.exit(1)

sdc_token = sys.argv[1]
alerts_dump_file = sys.argv[2]

#
# Instantiate the SDC client
#
sdclient = SdcClient(sdc_token)

#
# If the dump we're restoring from has an Alert with the same name
# as one that's already configured, we'll update the existing Alert
# so it will have the config from the dump. When we do this, however,
# we need to give the ID and Version # of the existing Alert as a
# basis. We save them off here so we can refer to them later.
#
existing_alerts = {}
res = sdclient.get_alerts()
if res[0]:
    for alert in res[1]['alerts']:
        existing_alerts[alert['name']] = { 'id': alert['id'], 'version': alert['version'] }
else:
    print res[1]
    sys.exit(1)

#
# Someone might be restoring Alert configs from another environment,
# in which case the Notification Channel IDs in the saved Alert JSON
# is not expected to match the Notification Channel IDs in the target
# environment. We'll get the list of target IDs so we can drop non-
# matching IDs when we restore.
#
res = sdclient.get_notification_ids()
if res[0]:
    existing_notification_channel_ids = res[1]
else:
    print res[1]
    sys.exit(1)

created_count = 0
updated_count = 0

with open(alerts_dump_file, 'r') as f:
    j = json.load(f)
    for a in j['alerts']:
        if 'notificationChannelIds' in a:
            for channel_id in a['notificationChannelIds']:
                if channel_id not in existing_notification_channel_ids:
                    print 'Notification Channel ID ' + str(channel_id) + ' referenced in Alert "' + a['name'] + '" does not exist.\n  Restoring without this ID.'
                    a['notificationChannelIds'].remove(channel_id)

        # JSON Alerts from the list_alerts.py example are in epoch time, but ones
        # downloaded using the "Export JSON" button of the web interface are ISO
        # timestamps in string form. If we see these fields as strings, assume
        # they came from the web UI and convert them to epoch.
        for timefield in ['createdOn', 'modifiedOn']:
            if isinstance(a.get(timefield), basestring):
                a[timefield] = calendar.timegm(datetime.datetime.strptime(a[timefield], '%Y-%m-%dT%H:%M:%S.%fZ').timetuple())

        if a['name'] in existing_alerts:
            a['id'] = existing_alerts[a['name']]['id']
            a['version'] = existing_alerts[a['name']]['version']
            if a.get('description') is None:
                a['description'] = '(updated via restore_alerts.py)'
            else:
                a['description'] += ' (updated via restore_alerts.py)'
            res = sdclient.update_alert(a)
            updated_count += 1
        else:
            if a.get('description') is None:
                a['description'] = '(created via restore_alerts.py)'
            else:
                a['description'] += ' (created via restore_alerts.py)'
            res = sdclient.create_alert(alert_obj=a)
            created_count += 1
        if not res[0]:
            print res[1]
            sys.exit(1)

print ('All Alerts in ' + alerts_dump_file + ' restored successfully (' +
      str(created_count) + ' created, ' + str(updated_count) + ' updated)')

#!/usr/bin/env python
#
# Search a dashboard by name and saving it in a zip file
#


import sys
import os
import zipfile

from sdcclient import SdMonitorClient


def zipdir(path, ziph):
    # ziph is zipfile handle
    for root, dirs, files in os.walk(path):
        for file in files:
            ziph.write(os.path.join(root, file))


def cleanup_dir(path):
    if not os.path.exists(path):
        return
    if not os.path.isdir(path):
        print('Provided path is not a directory')
        sys.exit(-1)

    for file in os.listdir(path):
        file_path = os.path.join(path, file)
        try:
            if os.path.isfile(file_path):
                os.unlink(file_path)
            else:
                print(('Cannot clean the provided directory due to delete failure on %s' % file_path))
        except Exception as e:
            print(e)
    os.rmdir(path)


#
# Parse arguments
#
if len(sys.argv) != 4:
    print(('usage: %s <sysdig-token> "<dashboard-name>" <output-file-name>' % sys.argv[0]))
    print('You can find your token at https://app.sysdigcloud.com/#/settings/user')
    sys.exit(1)


# Define args
sdc_token = sys.argv[1]
dashboard_name = sys.argv[2]
dashboard_state_file = sys.argv[3]
sysdig_dashboard_dir = 'sysdig-dashboard-dir'

#
# Instantiate the SDC client
#
sdclient = SdMonitorClient(sdc_token)

#
# Find a dashboard by name
#
ok, res = sdclient.find_dashboard_by(dashboard_name)


# Check the result
if ok and len(res) > 0:
    print('Dashboard found, ID: ', res[0]['dashboard']['id'])
    dashboard_id = res[0]['dashboard']['id']
    dashboard_configuration = res[0]['dashboard']
else:
    print(res)
    sys.exit(1)


#
# Get Dashboard by id
#
ok, res = sdclient.get_dashboard(dashboard_id)

# Clean up any state in the tmp directory
cleanup_dir(sysdig_dashboard_dir)


# Creating sysdig dashboard directory to store dashboards
if not os.path.exists(sysdig_dashboard_dir):
    os.makedirs(sysdig_dashboard_dir)


#
# Check for successful retrieval and save it
#
if len(res['dashboard']) > 0:
    print('Downloading Dashboard ID: ', dashboard_id)
    sdclient.save_dashboard_to_file(res['dashboard'], os.path.join(sysdig_dashboard_dir, str(res['dashboard']['id'])))
    print('Dashboard Name: "%s"' % (res['dashboard']['name']), 'ID:', dashboard_id, 'downloaded')


zipf = zipfile.ZipFile(dashboard_state_file, 'w', zipfile.ZIP_DEFLATED)
zipdir(sysdig_dashboard_dir, zipf)
zipf.close()

# Clean up any state in the directory
cleanup_dir(sysdig_dashboard_dir)

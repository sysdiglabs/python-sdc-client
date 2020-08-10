#!/usr/bin/env python
#
# List all the access keys in a Sysdig Monitor environment. The token you provide must
# have Admin rights.
#

import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.realpath(sys.argv[0])), '..'))
from sdcclient import SdcClient

#
# Parse arguments
#
if len(sys.argv) != 2:
    print('usage: %s <sysdig-token>' % sys.argv[0])
    print('You can find your token at https://app.sysdigcloud.com/#/settings/user')
    print('For this script to work, the user for the token must have Admin rights')
    sys.exit(1)

sdc_token = sys.argv[1]

#
# Instantiate the SDC client
#
sdclient = SdcClient(sdc_token, 'https://app.sysdigcloud.com')

#
# Get the configuration
#
ok, res = sdclient.list_access_keys()
if ok:
    print('Access Keys\n===========')
    for access_key in res['customerAccessKeys']:
        print(access_key['accessKey'])
else:
    print(res)
    sys.exit(1)

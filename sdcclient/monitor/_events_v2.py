import json
from datetime import datetime

from sdcclient._common import _SdcCommon


class EventsClientV2(_SdcCommon):
    def __init__(self, token="", sdc_url='https://app.sysdigcloud.com', ssl_verify=True, custom_headers=None):
        super().__init__(token, sdc_url, ssl_verify, custom_headers)
        self.product = "SDC"

    def get_events(self, name=None, category=None, direction='before', status=None, limit=100, pivot=None, from_s=None,
                   to_s=None):
        '''**Description**
            Returns the list of Sysdig Monitor events.

        **Arguments**
            - **name**: filter events by name. Default: None.
            - **category**: filter events by category. Default: ['alert', 'custom', 'docker', 'containerd', 'kubernetes'].
            - **direction**: orders the list of events. Valid values: "before", "after". Default: "before".
            - **status**: status of the event as list. Default: ['triggered', 'resolved', 'acknowledged', 'unacknowledged']
            - **limit**: max number of events to retrieve. Default: 100.
            - **pivot**: event id to use as pivot. Default: None.
            - **from_s**: the unix timestamp in milliseconds or datetime object for the beginning of the events. Default: None.
            - **to_s**: the unix timestamp in milliseconds or datetime object for the end of the events. Default: None.

        **Success Return Value**
            A dictionary containing the list of events.

        **Example**
            `examples/list_events.py <https://github.com/draios/python-sdc-client/blob/master/examples/list_events.py>`_
        '''
        valid_categories = ['alert', 'custom', 'docker', 'containerd', 'kubernetes']

        if category is None:
            category = valid_categories

        for c in category:
            if c not in valid_categories:
                return False, "Invalid category '{}'".format(c)

        valid_status = ["triggered", "resolved", "acknowledged", "unacknowledged"]
        if status is None:
            status = valid_status

        for s in status:
            if s not in valid_status:
                return False, "Invalid status '{}'".format(s)

        if direction not in ["before", "after"]:
            return False, "Invalid direction '{}', must be either 'before' or 'after'".format(direction)

        if from_s is not None and isinstance(from_s, datetime):
            from_s = int(from_s.timestamp() * 1000)
        if to_s is not None and isinstance(to_s, datetime):
            to_s = int(to_s.timestamp() * 1000)

        if to_s is None and from_s is not None or from_s is None and to_s is not None:
            return False, "only one of 'from_s' or 'to_s' has been specified, both are required when filtering by time"

        if to_s is not None and from_s is not None:
            if int(to_s) < int(from_s):
                return False, "'from_s' must be lower than 'to_s'"

        options = {
            'alertStatus': status,
            'category': ','.join(category),
            'dir': direction,
            'feed': 'true',
            'include_pivot': 'true',
            'include_total': 'true',
            'limit': str(limit),
            'pivot': pivot,
            'filter': name,
            'from': from_s,
            'to': to_s,
        }
        params = {k: v for k, v in options.items() if v is not None}
        res = self.http.get(self.url + '/api/v2/events/', headers=self.hdrs, params=params, verify=self.ssl_verify)
        return self._request_result(res)

    def get_event(self, id):
        """
        Retrieve an event using the ID
        Args:
            id(str): ID of the event to retrieve

        Returns:
            A tuple where the first parameter indicates if the call was successful,
            and the second parameter holds either the error as string, or the event matching this ID.

        Examples:
            >>> from sdcclient.monitor import EventsClientV2
            >>> client = EventsClientV2(token=SECURE_TOKEN)
            >>> ok, res = client.get_event(id='2343214984')
            >>> if ok:
            >>>     print(res["event"])
        """

        url = f'{self.url}/api/v2/events/{id}'
        res = self.http.get(url, headers=self.hdrs, verify=self.ssl_verify)
        return self._request_result(res)

    def delete_event(self, event):
        '''**Description**
            Deletes an event.

        **Arguments**
            - **event**: the event object as returned by :func:`~SdcClient.get_events`.

        **Success Return Value**
            `None`.

        **Example**
            `examples/delete_event.py <https://github.com/draios/python-sdc-client/blob/master/examples/delete_event.py>`_
        '''
        if 'id' not in event:
            return [False, "Invalid event format"]

        res = self.http.delete(self.url + '/api/v2/events/' + str(event['id']), headers=self.hdrs,
                               verify=self.ssl_verify)
        if not self._checkResponse(res):
            return [False, self.lasterr]
        return [True, None]

    def post_event(self, name, description=None, severity=None, event_filter=None, tags=None):
        '''**Description**
            Send an event to Sysdig Monitor. The events you post are available in the Events tab in the Sysdig Monitor UI and can be overlied to charts.

        **Arguments**
            - **name**: the name of the new event.
            - **description**: a longer description offering detailed information about the event.
            - **severity**: syslog style from 0 (high) to 7 (low).
            - **event_filter**: metadata, in Sysdig Monitor format, of nodes to associate with the event, e.g. ``host.hostName = 'ip-10-1-1-1' and container.name = 'foo'``.
            - **tags**: a list of key-value dictionaries that can be used to tag the event. Can be used for filtering/segmenting purposes in Sysdig Monitor.

        **Success Return Value**
            A dictionary describing the new event.

        **Examples**
            - `examples/post_event_simple.py <https://github.com/draios/python-sdc-client/blob/master/examples/post_event_simple.py>`_
            - `examples/post_event.py <https://github.com/draios/python-sdc-client/blob/master/examples/post_event.py>`_
        '''
        options = {
            'name': name,
            'description': description,
            'severity': severity,
            'scope': event_filter,
            'tags': tags
        }
        edata = {
            'event': {k: v for k, v in options.items() if v is not None}
        }
        res = self.http.post(self.url + '/api/v2/events/', headers=self.hdrs, data=json.dumps(edata),
                             verify=self.ssl_verify)
        return self._request_result(res)

import json

from sdcclient._common import _SdcCommon


class EventsClientV1(_SdcCommon):
    def __init__(self, token="", sdc_url='https://app.sysdigcloud.com', ssl_verify=True, custom_headers=None):
        super().__init__(token, sdc_url, ssl_verify, custom_headers)
        self.product = "SDC"

    def get_events(self, from_s=None, to_s=None, last_s=None):
        '''**Description**
            Returns the list of Sysdig Monitor events.

        **Arguments**
            - **name**: filter events by name. Default: None.
            - **category**: filter events by category. Default: ['alert', 'custom', 'docker', 'containerd', 'kubernetes'].
            - **direction**: orders the list of events. Valid values: "before", "after". Default: "before".
            - **status**: status of the event as list. Default: ['triggered', 'resolved', 'acknowledged', 'unacknowledged']
            - **limit**: max number of events to retrieve. Default: 100.
            - **pivot**: event id to use as pivot. Default: None.

        **Success Return Value**
            A dictionary containing the list of events.

        **Example**
            `examples/list_events.py <https://github.com/draios/python-sdc-client/blob/master/examples/list_events.py>`_
        '''

        options = {
            "from": from_s,
            "to": to_s,
            "last": last_s,
        }
        params = {k: v for k, v in options.items() if v is not None}
        res = self.http.get(self.url + '/api/events/', headers=self.hdrs, params=params, verify=self.ssl_verify)
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
            >>> from sdcclient.monitor import EventsClientV1
            >>> client = EventsClientV1(token=SECURE_TOKEN)
            >>> ok, res = client.get_event(id='2343214984')
            >>> if ok:
            >>>     print(res["event"])
        """
        url = f'{self.url}/api/events/{id}'
        res = self.http.get(url, headers=self.hdrs, verify=self.ssl_verify)
        return self._request_result(res)

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
            'filter': event_filter,
            'tags': tags
        }
        edata = {
            'event': {k: v for k, v in options.items() if v is not None}
        }
        res = self.http.post(self.url + '/api/events/', headers=self.hdrs, data=json.dumps(edata),
                             verify=self.ssl_verify)
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

        res = self.http.delete(self.url + '/api/events/' + str(event['id']), headers=self.hdrs, verify=self.ssl_verify)
        if not self._checkResponse(res):
            return [False, self.lasterr]
        return [True, None]

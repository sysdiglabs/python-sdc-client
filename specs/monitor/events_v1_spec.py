import os
import time

from expects import expect, have_key, contain, have_keys, be_empty, equal
from mamba import it, before, description

from sdcclient.monitor import EventsClientV1
from specs import be_successful_api_call

with description("Events v1", "integration") as self:
    with before.all:
        self.client = EventsClientV1(sdc_url=os.getenv("SDC_MONITOR_URL", "https://app.sysdigcloud.com"),
                                     token=os.getenv("SDC_MONITOR_TOKEN"))
        self.event_name = "event_v1_test_ci"

    with it("is able to create a custom event"):
        call = self.client.post_event(name=self.event_name,
                                      description="This event was created in a CI pipeline for the Python SDK library")
        expect(call).to(be_successful_api_call)

    with it("is able to retrieve an event by ID"):
        ok, res = self.client.post_event(name=self.event_name,
                                         description="This event was created in a CI pipeline for the Python SDK library")
        expect((ok, res)).to(be_successful_api_call)

        event = res["event"]
        event_id = event["id"]

        ok, res = self.client.get_event(id=event_id)
        expect((ok, res)).to(be_successful_api_call)

        expect(res["event"]).to(equal(event))

    with it("is able to list the events happened without any filter"):
        time.sleep(3)  # Wait for the event to appear in the feed
        ok, res = self.client.get_events()
        expect((ok, res)).to(be_successful_api_call)
        expect(res).to(have_key("events"))

    with it("is able to list the events created by the tests"):
        time.sleep(3)  # Wait for the event to appear in the feed
        ok, res = self.client.get_events(last_s=60)
        expect((ok, res)).to(be_successful_api_call)
        expect(res).to(have_key("events", contain(have_keys(name=self.event_name))))

    with it("is able to remove the event from the feed"):
        time.sleep(3)
        _, res = self.client.get_events(last_s=60)

        events = [event for event in res["events"] if event["name"] == self.event_name]
        expect(events).to_not(be_empty)

        call = self.client.delete_event(events[0])
        expect(call).to(be_successful_api_call)

import os
import time
from datetime import datetime, timedelta
from time import sleep

from expects import expect, have_key, contain, have_keys, be_empty, equal, be_false, be_above_or_equal, have_len
from mamba import it, before, context, description

from sdcclient.monitor import EventsClientV2
from specs import be_successful_api_call

with description("Events v2", "integration") as self:
    with before.all:
        self.client = EventsClientV2(sdc_url=os.getenv("SDC_MONITOR_URL", "https://app.sysdigcloud.com"),
                                     token=os.getenv("SDC_MONITOR_TOKEN"))
        self.event_name = "event_v2_test_ci"

    with it("is able to create a custom event"):
        call = self.client.post_event(name=self.event_name,
                                      description="This event was created in a CI pipeline for the Python SDK library")
        expect(call).to(be_successful_api_call)

    with it("is able to create a custom event with a scope"):
        call = self.client.post_event(name=self.event_name,
                                      description="This event was created in a CI pipeline for the Python SDK library",
                                      event_filter="host.hostName='ci'")
        expect(call).to(be_successful_api_call)
        sleep(2)  # sleep to guarantee the event is created

        ok, res = self.client.get_events()
        expect((ok, res)).to(be_successful_api_call)
        expect(res).to(have_key("events"))
        expect(res["events"]).to(contain(have_key("scope", equal("host.hostName = 'ci'"))))

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
        ok, res = self.client.get_events(category=["custom"])
        expect((ok, res)).to(be_successful_api_call)
        expect(res).to(have_key("events", contain(have_keys(name=self.event_name))))

    with it("fails to retrieve the events with an incorrect category"):
        ok, res = self.client.get_events(category=['incorrect_category'])

        expect(ok).to(be_false)
        expect(res).to(equal("Invalid category 'incorrect_category'"))

    with it("is able to retrieve events that match a status"):
        ok, res = self.client.get_events(status=['triggered'])
        expect((ok, res)).to(be_successful_api_call)
        expect(res).to(have_key("events", contain(have_keys(name=self.event_name))))

    with it("fails to retrieve the events with an incorrect status"):
        ok, res = self.client.get_events(status=['incorrect_status'])

        expect(ok).to(be_false)
        expect(res).to(equal("Invalid status 'incorrect_status'"))

    with it("retrieves the events correctly specifying direction 'before'"):
        ok, res = self.client.get_events(direction="before")

        expect((ok, res)).to(be_successful_api_call)
        expect(res).to(have_keys('events', 'total', 'matched'))

    with it("retrieves the events correctly specifying direction 'after'"):
        ok, res = self.client.get_events(direction="after")

        expect((ok, res)).to(be_successful_api_call)
        expect(res).to(have_keys('events', 'total', 'matched'))

    with it("fails to retrieve the events with an incorrect direction"):
        ok, res = self.client.get_events(direction="incorrect_direction")

        expect(ok).to(be_false)
        expect(res).to(equal("Invalid direction 'incorrect_direction', must be either 'before' or 'after'"))

    with it("is able to retrieve events by name"):
        ok, res = self.client.get_events(name=self.event_name)

        expect((ok, res)).to(be_successful_api_call)
        expect(res).to(have_key("events", contain(have_key("name", equal(self.event_name)))))

    with it("retrieves an empty list when the name provided is not found"):
        ok, res = self.client.get_events(name="RandomUnexistingEvent")

        expect((ok, res)).to(be_successful_api_call)
        expect(res).to(have_key("events", be_empty))

    with it("is able to retrieve the last event only"):
        ok, res = self.client.get_events(limit=1)
        expect((ok, res)).to(be_successful_api_call)
        expect(res).to(have_key("events", have_len(1)))

    with it("is able to retrieve the events from the last day"):
        to_s = datetime.now()
        from_s = to_s - timedelta(weeks=2)
        ok, res = self.client.get_events(from_s=from_s, to_s=to_s)

        expect((ok, res)).to(be_successful_api_call)
        expect(res).to(have_key("events", have_len(be_above_or_equal(1))))

    with context("but the from and to parameters are incorrectly specified"):
        with it("returns an error if any of the parameters is specified but not the other"):
            t = datetime.now() - timedelta(weeks=2)
            ok1, res1 = self.client.get_events(from_s=t)
            ok2, res2 = self.client.get_events(to_s=t)

            expect((ok1, res1)).not_to(be_successful_api_call)
            expect((ok2, res2)).not_to(be_successful_api_call)
            expect(res1).to(equal("only one of 'from_s' or 'to_s' has been specified, "
                                  "both are required when filtering by time"))
            expect(res2).to(equal("only one of 'from_s' or 'to_s' has been specified, "
                                  "both are required when filtering by time"))

        with it("returns an error if they are specified in the wrong order"):
            to_s = datetime.now()
            from_s = to_s - timedelta(weeks=2)
            ok, res = self.client.get_events(from_s=to_s, to_s=from_s)

            expect((ok, res)).not_to(be_successful_api_call)
            expect(res).to(equal("'from_s' must be lower than 'to_s'"))

    with it("is able to remove the event from the feed"):
        time.sleep(3)  # Wait for the event to appear in the feed
        _, res = self.client.get_events(category=["custom"])

        events = [event for event in res["events"] if event["name"] == self.event_name]
        expect(events).to_not(be_empty)

        call = self.client.delete_event(events[0])
        expect(call).to(be_successful_api_call)

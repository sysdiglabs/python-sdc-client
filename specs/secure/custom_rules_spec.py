import os

from expects import equal, expect, start_with, contain
from mamba import before, context, description, it

from sdcclient import SdSecureClient
from specs import be_successful_api_call

with description("Custom Rules") as self:
    with before.each:
        self.client = SdSecureClient(sdc_url=os.getenv("SDC_SECURE_URL", "https://secure.sysdig.com"),
                                     token=os.getenv("SDC_SECURE_TOKEN"))

    with context("when the custom rules file exists"):
        with it("can be retrieved"):
            ok, res = self.client.get_user_falco_rules()

            expect((ok, res)).to(be_successful_api_call)
            expect(res).to(start_with("####################\n# Your custom rules!\n####################\n"))

    with it("can push custom rules"):
        _, previous_rules = self.client.get_user_falco_rules()
        empty_rules = self.empty_falco_rules()
        custom_rules = self.user_falco_rules()

        ok, res = self.client.set_user_falco_rules(custom_rules)
        expect((ok, res)).to(be_successful_api_call)
        expect(res).to(equal(custom_rules))

        ok, res = self.client.set_user_falco_rules(empty_rules)
        expect((ok, res)).to(be_successful_api_call)
        expect(res).to(equal(empty_rules))

        ok, res = self.client.set_user_falco_rules(self.rules_without_header())
        expect((ok, res)).to(be_successful_api_call)
        # The endpoint automatically fills the header for the user.
        expect(res).to(start_with("####################\n# Your custom rules!\n####################\n\n"))
        expect(res).to(contain(self.rules_without_header()))

        ok, res = self.client.set_user_falco_rules(previous_rules)
        expect((ok, res)).to(be_successful_api_call)
        expect(res).to(equal(previous_rules))


    def user_falco_rules(self):
        with open("fixtures/custom_rules.yaml", "r") as f:
            return f.read()


    def empty_falco_rules(self):
        return """####################
# Your custom rules!
####################

# Add new rules, like this one
# - rule: A shell is run in a container
#   desc: An event will trigger every time you run a shell in a container
#   condition: evt.type = execve and evt.dir=< and container.id != host and proc.name = bash
#   output: "Suspect shell run in container (user=%user.name %container.info shell=%proc.name parent=%proc.pname cmdline=%proc.cmdline)"
#   priority: ERROR
#   tags: [shell]

# Or override any rule, macro, or list from the Default Rules
"""


    def rules_without_header(self):
        return """\
---
- rule: "Testing rule"
  desc: "Description"
  condition: "always_true"
  output: "Sample output"
  priority: "WARNING"
  tags: []
  source: "syscall"
"""

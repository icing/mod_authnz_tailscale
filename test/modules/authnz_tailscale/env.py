import inspect
import logging
import os

from pyhttpd.env import HttpdTestEnv, HttpdTestSetup

log = logging.getLogger(__name__)


class AuthTailscaleTestSetup(HttpdTestSetup):

    def __init__(self, env: 'HttpdTestEnv'):
        super().__init__(env=env)
        self.add_source_dir(os.path.dirname(inspect.getfile(AuthTailscaleTestSetup)))
        self.add_modules(["authnz_tailscale", "cgid"])


class AuthTailscaleTestEnv(HttpdTestEnv):

    def __init__(self, pytestconfig=None):
        super().__init__(pytestconfig=pytestconfig)
        self.add_httpd_log_modules(["authnz_tailscale"])

    def setup_httpd(self, setup: HttpdTestSetup = None):
        super().setup_httpd(setup=AuthTailscaleTestSetup(env=self))

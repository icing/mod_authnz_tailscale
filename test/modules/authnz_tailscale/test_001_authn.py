import pytest

from pyhttpd.conf import HttpdConf
from .faker import TailscaleFaker


class TestTailscale:

    UDS_PATH = None
    Faker = None

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        TestTailscale.UDS_PATH = f"{env.gen_dir}/tailscale.sock"
        faker = TailscaleFaker(env=env, path=TestTailscale.UDS_PATH)
        TestTailscale.Faker = faker
        faker.start()
        HttpdConf(env).install()
        assert env.apache_restart() == 0
        yield
        faker.stop()

    # nothing configured, continues to work
    def test_authnz_tailscale_001_01(self, env):
        conf = HttpdConf(env)
        conf.add_vhost_cgi()
        conf.install()
        assert env.apache_restart() == 0
        url = env.mkurl("https", "cgi", "/hello.py")
        r = env.curl_get(url)
        assert r.response["status"] == 200
        assert r.json['REMOTE_USER'] == ""

    # configure tailscale authentication, require a valid user
    # without setting whois data in Faker, this will fail
    def test_authnz_tailscale_001_02(self, env):
        conf = HttpdConf(env, extras={
            "base": {
                f"AuthTailscaleURL {TestTailscale.UDS_PATH}",
            },
            f"cgi.{env.http_tld}": [
                "<Location />",
                "  AuthType tailscale",
                "  Require valid-user",
                "</Location>",
            ]
        })
        conf.add_vhost_cgi()
        conf.install()
        assert env.apache_restart() == 0
        url = env.mkurl("https", "cgi", "/")
        r = env.curl_get(url)
        assert r.response["status"] == 401

    # configure tailscale authentication, require a valid user
    # set Faker whois data, must work
    def test_authnz_tailscale_001_03(self, env):
        conf = HttpdConf(env, extras={
            "base": {
                f"AuthTailscaleURL {TestTailscale.UDS_PATH}",
            },
            f"cgi.{env.http_tld}": [
                "<Location />",
                "  AuthType tailscale",
                "  Require valid-user",
                "</Location>",
            ]
        })
        conf.add_vhost_cgi()
        conf.install()
        assert env.apache_restart() == 0
        TestTailscale.Faker.set_whois({
            "UserProfile": {
                "LoginName": "ts_user_1",
            }
        })
        url = env.mkurl("https", "cgi", "/hello.py")
        r = env.curl_get(url)
        assert r.response["status"] == 200
        assert r.json['REMOTE_USER'] == "ts_user_1"

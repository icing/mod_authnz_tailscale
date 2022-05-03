import pytest

from pyhttpd.conf import HttpdConf
from .faker import TailscaleFaker


class TestTSAuthzUser:

    UDS_PATH = None
    Faker = None

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        TestTSAuthzUser.UDS_PATH = f"{env.gen_dir}/tailscale.sock"
        faker = TailscaleFaker(env=env, path=TestTSAuthzUser.UDS_PATH)
        TestTSAuthzUser.Faker = faker
        faker.start()
        HttpdConf(env).install()
        assert env.apache_restart() == 0
        yield
        faker.stop()

    # no whois data set, require tailscale-user will fail
    def test_authnz_tailscale_002_01(self, env):
        conf = HttpdConf(env, extras={
            "base": {
                f"AuthTailscaleURL {TestTSAuthzUser.UDS_PATH}",
            },
            f"cgi.{env.http_tld}": [
                "<Location />",
                "  Require tailscale-user ts_user_1",
                "</Location>",
            ]
        })
        conf.add_vhost_cgi()
        conf.install()
        assert env.apache_restart() == 0
        url = env.mkurl("https", "cgi", "/")
        r = env.curl_get(url)
        assert r.response["status"] == 403

    # whois data set, require tailscale-user must succeed,
    # but with 'AuthType tailscale' REMOTE_USER is not set
    def test_authnz_tailscale_002_02(self, env):
        conf = HttpdConf(env, extras={
            "base": {
                f"AuthTailscaleURL {TestTSAuthzUser.UDS_PATH}",
            },
            f"cgi.{env.http_tld}": [
                "<Location />",
                "  Require tailscale-user ts_user_1",
                "</Location>",
            ]
        })
        conf.add_vhost_cgi()
        conf.install()
        assert env.apache_restart() == 0
        TestTSAuthzUser.Faker.set_whois({
            "Node": {
                "Name": "client.test.tailnet",
                "ComputedName": "client",
            },
            "UserProfile": {
                "LoginName": "ts_user_1",
            }
        })
        url = env.mkurl("https", "cgi", "/hello.py")
        r = env.curl_get(url)
        assert r.response["status"] == 200
        assert r.json['REMOTE_USER'] == ""

    # whois data set, require tailscale-user must fail for other user
    def test_authnz_tailscale_002_03(self, env):
        conf = HttpdConf(env, extras={
            "base": {
                f"AuthTailscaleURL {TestTSAuthzUser.UDS_PATH}",
            },
            f"cgi.{env.http_tld}": [
                "<Location />",
                "  Require tailscale-user ts_user_1",
                "</Location>",
            ]
        })
        conf.add_vhost_cgi()
        conf.install()
        assert env.apache_restart() == 0
        TestTSAuthzUser.Faker.set_whois({
            "Node": {
                "Name": "client2.test.tailnet",
                "ComputedName": "client2",
            },
            "UserProfile": {
                "LoginName": "ts_user_2",
            }
        })
        url = env.mkurl("https", "cgi", "/hello.py")
        r = env.curl_get(url)
        assert r.response["status"] == 403

    # whois data set, require tailscale-user must succeed if one user matches
    # all on one line
    def test_authnz_tailscale_002_04(self, env):
        conf = HttpdConf(env, extras={
            "base": {
                f"AuthTailscaleURL {TestTSAuthzUser.UDS_PATH}",
            },
            f"cgi.{env.http_tld}": [
                "<Location />",
                "  Require tailscale-user ts_user_1 ts_user_2 ts_user_3",
                "</Location>",
            ]
        })
        conf.add_vhost_cgi()
        conf.install()
        assert env.apache_restart() == 0
        TestTSAuthzUser.Faker.set_whois({
            "Node": {
                "Name": "client2.test.tailnet",
                "ComputedName": "client2",
            },
            "UserProfile": {
                "LoginName": "ts_user_2",
            }
        })
        url = env.mkurl("https", "cgi", "/hello.py")
        r = env.curl_get(url)
        assert r.response["status"] == 200

    # whois data set, require tailscale-user must succeed if one user matches
    # several lines
    def test_authnz_tailscale_002_05(self, env):
        conf = HttpdConf(env, extras={
            "base": {
                f"AuthTailscaleURL {TestTSAuthzUser.UDS_PATH}",
            },
            f"cgi.{env.http_tld}": [
                "<Location />",
                "  Require tailscale-user ts_user_1",
                "  Require tailscale-user ts_user_2",
                "  Require tailscale-user ts_user_3",
                "</Location>",
            ]
        })
        conf.add_vhost_cgi()
        conf.install()
        assert env.apache_restart() == 0
        TestTSAuthzUser.Faker.set_whois({
            "Node": {
                "Name": "client2.test.tailnet",
                "ComputedName": "client2",
            },
            "UserProfile": {
                "LoginName": "ts_user_2",
            }
        })
        url = env.mkurl("https", "cgi", "/hello.py")
        r = env.curl_get(url)
        assert r.response["status"] == 200

    # whois data set, wildcard match all users
    def test_authnz_tailscale_002_06(self, env):
        conf = HttpdConf(env, extras={
            "base": {
                f"AuthTailscaleURL {TestTSAuthzUser.UDS_PATH}",
            },
            f"cgi.{env.http_tld}": [
                "<Location />",
                "  Require tailscale-user *",
                "</Location>",
            ]
        })
        conf.add_vhost_cgi()
        conf.install()
        assert env.apache_restart() == 0
        TestTSAuthzUser.Faker.set_whois({
            "Node": {
                "Name": "client2.test.tailnet",
                "ComputedName": "client2",
            },
            "UserProfile": {
                "LoginName": "ts_user_2",
            }
        })
        url = env.mkurl("https", "cgi", "/hello.py")
        r = env.curl_get(url)
        assert r.response["status"] == 200

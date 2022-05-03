import pytest

from pyhttpd.conf import HttpdConf
from .faker import TailscaleFaker


class TestTSAuthzNode:

    UDS_PATH = None
    Faker = None

    @pytest.fixture(autouse=True, scope='class')
    def _class_scope(self, env):
        TestTSAuthzNode.UDS_PATH = f"{env.gen_dir}/tailscale.sock"
        faker = TailscaleFaker(env=env, path=TestTSAuthzNode.UDS_PATH)
        TestTSAuthzNode.Faker = faker
        faker.start()
        HttpdConf(env).install()
        assert env.apache_restart() == 0
        yield
        faker.stop()

    # no whois data set, require tailscale-user will fail
    def test_authnz_tailscale_003_01(self, env):
        conf = HttpdConf(env, extras={
            "base": {
                f"AuthTailscaleURL {TestTSAuthzNode.UDS_PATH}",
            },
            f"cgi.{env.http_tld}": [
                "<Location />",
                "  Require tailscale-node client.test.tailnet",
                "</Location>",
            ]
        })
        conf.add_vhost_cgi()
        conf.install()
        assert env.apache_restart() == 0
        url = env.mkurl("https", "cgi", "/")
        r = env.curl_get(url)
        assert r.response["status"] == 403

    # whois data set, require tailscale-node must succeed,
    def test_authnz_tailscale_003_02(self, env):
        conf = HttpdConf(env, extras={
            "base": {
                f"AuthTailscaleURL {TestTSAuthzNode.UDS_PATH}",
            },
            f"cgi.{env.http_tld}": [
                "<Location />",
                "  Require tailscale-node client.test.tailnet",
                "</Location>",
            ]
        })
        conf.add_vhost_cgi()
        conf.install()
        assert env.apache_restart() == 0
        TestTSAuthzNode.Faker.set_whois({
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

    # whois data set, require tailscale-node must fail for other node
    def test_authnz_tailscale_003_03(self, env):
        conf = HttpdConf(env, extras={
            "base": {
                f"AuthTailscaleURL {TestTSAuthzNode.UDS_PATH}",
            },
            f"cgi.{env.http_tld}": [
                "<Location />",
                "  Require tailscale-node client.test.tailnet",
                "</Location>",
            ]
        })
        conf.add_vhost_cgi()
        conf.install()
        assert env.apache_restart() == 0
        TestTSAuthzNode.Faker.set_whois({
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

    # whois data set, require tailscale-node must succeed if one node matches
    # all on one line
    def test_authnz_tailscale_003_04(self, env):
        conf = HttpdConf(env, extras={
            "base": {
                f"AuthTailscaleURL {TestTSAuthzNode.UDS_PATH}",
            },
            f"cgi.{env.http_tld}": [
                "<Location />",
                "  Require tailscale-node client.test.tailnet client2.test.tailnet",
                "</Location>",
            ]
        })
        conf.add_vhost_cgi()
        conf.install()
        assert env.apache_restart() == 0
        TestTSAuthzNode.Faker.set_whois({
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

    # whois data set, require tailscale-node must succeed if one user matches
    # several lines
    def test_authnz_tailscale_003_05(self, env):
        conf = HttpdConf(env, extras={
            "base": {
                f"AuthTailscaleURL {TestTSAuthzNode.UDS_PATH}",
            },
            f"cgi.{env.http_tld}": [
                "<Location />",
                "  Require tailscale-node client.test.tailnet",
                "  Require tailscale-node client2.test.tailnet",
                "  Require tailscale-node client3.test.tailnet",
                "</Location>",
            ]
        })
        conf.add_vhost_cgi()
        conf.install()
        assert env.apache_restart() == 0
        TestTSAuthzNode.Faker.set_whois({
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
    def test_authnz_tailscale_003_06(self, env):
        conf = HttpdConf(env, extras={
            "base": {
                f"AuthTailscaleURL {TestTSAuthzNode.UDS_PATH}",
            },
            f"cgi.{env.http_tld}": [
                "<Location />",
                "  Require tailscale-node *",
                "</Location>",
            ]
        })
        conf.add_vhost_cgi()
        conf.install()
        assert env.apache_restart() == 0
        TestTSAuthzNode.Faker.set_whois({
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

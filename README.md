# mod\_authnz\_tailscale

Apache httpd authentication/authorization for tailscale access.

## What it does

When you run Apache httpd on a machine in a tailscale VPN (some words about what that is [below](#about_tailscale)), you can manage access to sites or specific
resources based on where connections come from. For example, if you installed tailscale with login `your-id@github`:

```
<VirtualHost *:443>
  <Location />
    Require tailscale-user your-id@github
  </Location>
  ...
</VirtualHost>
```

means that only tailscale connections from one of your machines/phones you added have access here.

This is very convenient since there is no need for additional logins. No connection coming from someone/somewhere else 
will have access here.

## Status

Experimental. Available only on Linux machines (or where tailscale provides a unix domain socket). Requires `libcurl` and `libjansson` to build. Should work with any recent Apache httpd 2.4.x.


## Authorizations

The module adds three authorization directives right now:

1. `tailscale-user`: checks the `LoginName` of the `UserProfile` given by the tailscale demon for the client's address and port.
2. `tailscale-node`: checks the full node name of the tailscale node behind the client's address and port.
2. `tailscale-tailnet`: checks the node name suffix of the tailscale node behind the client's address and port.

### on a standard tailscale vpn

On a default installation of tailscale, all machines that you add to your tailscale VPN have the same user profile, e.g. `LoginName`. This is what you used to sign up to tailscale, like `john.doe@example.com`. If you used an email on a "shared" identity provider like `github`, this is `your-id@github`.

The directive to check for nodes that belong to your login name would then be:

```
Require tailscale-user your-id@github
```

This identity is also used to give your tailscale nodes, e.g. the machines you add, a unique name. This could be something like `machine-name.your-id.github.beta.tailscale.net.`. If you want to allow a specific node access to a Apache `Location`, you would configure:

```
Require tailscale-node machine-name.your-id.github.beta.tailscale.net.
```

If you want to give access to all machines your tailscale VPN runs on, do:

```
Require tailscale-tailnet your-id.github.beta.tailscale.net.
```

this common suffix among all your nodes is what tailscale calls your `tailnet`.

### Non standard configs

All this above holds true until you start digging deeper into your tailscale configuration and add `tags`
and other means like tailscale authentication keys to your tailnet. Then you will have nodes in your tailnet
that have other `LoginName` values. 

For example, you add a raspberry to your tailnet using a special auth key and that raspberry will not carry
your github id. While in your tailnet, it is not really "you" that it makes connections for.

The need for this is more clear when you consider tailnets for an organization. People add their laptops using
the company mail id, but the central servers clearly do not belong to a particular person. Also, when Joe leaves
the company, you do not want your central mail server to go down with him.



## Configuration

Normally nothing. Just load the module into the server and add `Require` directives where appropriate. Should you
be on a platform where the tailscale unix domain socket is not found, you can configure

```
AuthTailscaleURL file://localhost/var/lib/anotherpath/tailscale.socket
```

This configuration is recommended to be done globally.

Tailscale information is cached per connection for a short while. This is to prevent lookups for 
each request. The default timeout for such information is 1 second. You can change that by configuring

```
AuthTailscaleCacheTimeout 30s
```


## Authentication

The keen reader will have notices that the examples above are all about *Authorization*. If you have 
a web application running in/behind your Apache, you might want to know *which* user has been allowed access. Configure

```
<VirtualHost *:443>
  <Location />
    AuthType tailscale
    Require valid-user
  </Location>
  ...
</VirtualHost>
```

and the tailscale user will be available just like with other authentication mechanisms. For example, a CGI
process will find `REMOTE_USER` in its environment.

## How it works

On each machine, there is a `tailscale` demon running which does the routing and encryption. When it accepts network packets, it knows who encrypted them or it does not allow them in. Simplified, a packet from address `a.b.c.d` has to use a specific key and that key belongs to user `XYZ`. Only if `XYZ` is granted access into you tailscale network, will this data ever appear.

The tailscale demon has a local HTTP API, accessible on Linux via a unix domain socket, where one may ask which user is behind a remote address and port. `mod_authnz_tailscale` uses this feature to find the tailscale login behind an incoming HTTP request.


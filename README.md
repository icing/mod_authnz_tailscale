# mod\_authnz\_tailscale

Apache httpd authentication/authorization for tailscale access.

## What it does

When you run Apache httpd on a machine in a tailscale VPN (some words about what that is [below](#about_tailscale)), you can manage access to sites or specific
resources based on where connections come from. For example, if you installed tailscale with login `myself@github`:

```
<VirtualHost *:443>
  <Location />
    Require tailscale-user myself@github
  </Location>
  ...
</VirtualHost>
```

means that only tailscale connections from one of your machines/phones have access here.

This is very convenient since there is no need for additional logins. If you invite a friend into your
tailscale network, she will not have access here, since her tailscale login will be different. But you
can give her access simply by adding her login name. 

## How it works

On each machine, there is a `tailscale` demon running which does the routing and encryption. When it accepts network packets, it knows who encrypted them or it does not allow them in. Simplified, a packet from address `a.b.c.d` has to use a specific key and that key belongs to user `XYZ`. Only if `XYZ` is granted access into you tailscale network, will this data ever appear.

The tailscale demon has a local HTTP API, accessible on Linux via a unix domain socket, where one may ask which user is behind a remote address and port. `mod_authnz_tailscale` uses this feature to find the tailscale login behind an incoming HTTP request.

## Status

Experimental. Available only on Linux machines (or where tailscale provides a unix domain socket). Does no caching right now, so not suitable for high traffic. Tailscale groups and tags are on the todo list.

Requires `libcurl` and `libjansson` to build. Should work with any, not antique Apache httpd 2.4.x.

## Configuration

Normally nothing. Just load the module into the server and add `Require` directives where appropriate. Should you
be on a platform where the tailscale unix domain socket is not found, you can configure

```
AuthTailscaleURL file://localhost/var/lib/anotherpath/tailscale.socket
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


## About tailscale

[tailscale](https://tailscale.com) is, in their words, "a zero config VPN". If you think that does
not sound *that* exciting, you might want to read on a little bit.

It is not about hiding your IP address to the rest of the world, just so you can watch cat pictures in peace. No. It is really about given you a *private* network *across* the internet. Allowing all your computers and phones to talk to each other, *in private*, wherever they are. 

Example: let your phone talk to your computer at home, without configuring your router. The banger is: it is a real network, so your home computer can also talk to your phone as well. Add another machine and all three can talk to each other. It is like your own world-wide internet, using the internet, but just for you. Without the bad guys.

All traffic is encrypted securely and does **not** run over central tailscale servers. Unless you are really in a ditch somewhere and their magic peer-to-peer connections do not work. They have good documentation what they do and when they use what mode of operation.

Setting up your own network means installing the software and using a common login on your machines, like your github account. Tailscale then joins all installations with the same base login into a single network. There are other ways to connection machines, permanent or temporary, but then you leave the "zero config" behind.




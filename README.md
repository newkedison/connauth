Authenticate incoming connections and forward to another destination

### Why?

To make our backend services(like SSH) more secrecy,
besides using the tools supply by services themself(like public key authentication of SSH),
we usually put a firewall(iptables, ufw, etc.) in front of our services, only allowed IPs can connect to our services,
this make them more safely even if some CVEs was found but not fixed yet.

One of disadvantages of firewall was hard to update rules. So here comes [port knocking](https://en.wikipedia.org/wiki/Port_knocking).
It can update rules of iptables automatically if you connect to some ports in a special order.

There were new disadvantages of port knocking, like:
* it needs to run as root for changing configs of iptables
* it can be sniff by others
* most implementations of port knocking allow port to be access(maybe a short time) from all sources

Inspired by [giuliocomi/knockandgo](https://github.com/giuliocomi/knockandgo), I wrote this tool
for connections authentication and forward.

### Features

* no need to run as root/administrator
* support authenticating connections by IP or token(see
 [server config file](https://github.com/newkedison/connauth/blob/master/cmd/authserver/config.yaml.template) for more detail)
    * port-special IP whitelist for allowing IPs access this port
    * global IP whitelist/blacklist for allowing/denying IPs access all ports
    * other IPs need to auth by token, there were also port-special token and global token
* can set timeout for an authentication, clients need to re-auth again before create new connection when auth expired
* use encryption for keeping away of sniff and [replay attack](https://en.wikipedia.org/wiki/Replay_attack)
* cross platform, can run as service on windows(thanks to [kardianos/service](https://github.com/kardianos/service))

##### difference of [giuliocomi/knockandgo](https://github.com/giuliocomi/knockandgo)
* use a fixed port instead of random port, so the client not need to change port everytime
* not use PEM certificate for simply
* designed to run as service/daemon instead of one-time use

### Usage

##### build
build cmd/authserver and cmd/authclient by go, or just download the latest release binary file of your platform.

##### server side
1. copy authserver(or authserver.exe on windows) to your server
2. copy cmd/authserver/config.yaml.template to the same directory of authserver on your server,
rename it to server_config.yaml
3. modify the content of server_config.yaml to fit your need, it was easy, the comments and example will help you
4. run ./authserver on your server
##### client side
1. copy authclient(or authclient.exe on windows) to your client
2. copy cmd/authclient/config.yaml.template to the same directory of authclient on your client,
rename it to client_config.yaml
3. modify the content of client_config.yaml to fit your need
4. run ./authclient on your client
5. connect to your service as you do before(maybe you need to change port)

### Example

suppose you have a server(IP: 1.1.1.1) and running ssh service on port 22

* make sure UDP port 33333 and TCP port 2222 of server can be access from all sources
* copy `authserver` to `$HOME/connauth/` on server
* copy the content below to `$HOME/connauth/server_config.yaml` on the server:
````
authaddr: "0.0.0.0:33333"
authkey: "a safe key"
forwardconfigs:
  - bindport: 2222
    forwardaddr: "127.0.0.1:22"
    allowtokens:
      - "admin"
````
* `cd` to `$HOME/connauth` on your server and run
````
./authserver
````
* copy `authclient` to `$HOME/connauth` on client
* copy the content below to `$HOME/connauth/client_config.yaml` on the client:
````
servers:
  - addr: "1.1.1.1:33333"
    key: "a safe key"
    authconfigs:
    - token: "admin"
      port: 2222
````
* `cd` to `$HOME/connauth` on your client and run
````
./authclient
````
* run `ssh -p 2222 1.1.1.1` to connect to your ssh service on server

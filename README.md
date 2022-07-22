[![HitCount](https://hits.dwyl.com/makiisthenes/Proxy5Server.svg?style=flat-square&show=unique)](http://hits.dwyl.com/makiisthenes/Proxy5Server)
![Forks](https://img.shields.io/github/forks/makiisthenes/Proxy5Server)
![Stars](https://img.shields.io/github/stars/makiisthenes/Proxy5Server)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-0077B5?style=for-the-badge&logo=linkedin&logoColor=white&style=flat-square)]([https://www.linkedin.com/in/isaac-kogan-5a45b9193/](https://www.linkedin.com/in/michael-p-88b015200/) )


## Python Socks5 Proxy Server
### Allows users to run a Proxy5 server on thier own local computer, implemented using sockets.

----

#### Installation
Running the following to install: 
```python
pip install makiproxy5
```

----
#### Usage
```python
if __name__ == "__main__":
	ps = ProxyServer(host=None, port=10696, username=None, password=None, max_clients=3, secure=True)
	ps.run()
```

- ***host*** : This is the current local IP of the devices, this will be automatically so can be left blank.
- ***port*** : State the local port you want to clients to use when connecting to the proxy server.
- ***username*** : Set allowed username that can access the proxy server during authentication.
- ***password*** : Corresponding password required for username during authentication.
- ***max_client*** : Allow a maximum of x concurrent connections to the proxy server. 
- ***secure*** : Disables no authentication method, so all users must provide username/pass to connect.

----

#### Example
Example usage for initializing proxy server.
```python
ProxyServer(username="maki", password="password", port=10696, secure=True).run()
```

----

#### Client Connection Options:
There are many ways to use this server, I will mention a few for aid.

- **On Firefox (PC)**:
	Using extension Proxy Toggle, 
	https://addons.mozilla.org/en-GB/firefox/addon/proxy-toggle/
	Any extension where Proxy5 is accepted and allows the username/password authentication method.


- **On iOS (Mobile)**:
	Using this app, although cost £2-3 its the best option I have found.
	https://apps.apple.com/gb/app/shadowrocket/id932747118
	There may be other options available on Andriod for free.


----

#### Journey and Motivation

I wanted to watch UK TV shows that weren't available while abroad so decided to make a proxy server running on a raspberry pi so that I could watch free of charge and effortlessly.

Of course I could of just bought a monthly subscription to a VPN service or a proxy for a month, but what's the fun in that? I wanted to challenge myself, learn more about things I depend on instead of just using it.

I started my journey by looking at RFC for proxy5 protocol, and inspecting wireshark for proxy server running in practical way, so I could implement it myself.


[![Inspecting using Wireshark.](https://i.imgur.com/iE0Jmkb.png "Inspecting using Wireshark.")](https://i.imgur.com/iE0Jmkb.png "Inspecting using Wireshark.")


----
> Michael Peres 22/07/2022

> #### End

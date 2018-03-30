# Mr. Toot      ༼∵༽ ༼⍨༽ ༼⍢༽ ༼⍤༽

Find proxy credentials of users under same gateway/router.

The idea is to perform arp spoofing and then extract the proxy
credentials from the headers of intercepted packets.

The inital [CONNECT](https://en.wikipedia.org/wiki/HTTP_tunnel#HTTP_CONNECT_method) request to proxy server is sent unsecured and this request has proxy-username and proxy-password in it. Capture those packets, parse them and get the credentials.

## Usage

This package works only on Python3.

Scapy is a dependency. And Scapy requires **sudo** access for sending packets.
When you run sudo, the virtualenv environment variables, aliases, functions, etc are not carried over. **So using virtualenv won't work.**

    git clone https://github.com/narenchoudhary/mr-toot.git
    cd mr-toot
    pip install -r requirements.txt
    sudo python3 -m mrtoot.arp_poison

# IP and DNS Blocklists

## What it is

IP and DNS blocklists are lists of known malicious IP addresses and domain names. This tool uses these lists to identify connections to and from malicious hosts.

## How it's triggered

A blocklist hit is triggered when a host on your network communicates with an IP address or resolves a domain name that is present in one of the configured blocklists.

## How to interpret it

A blocklist hit is a strong indicator that a host on your network is communicating with a known malicious entity. This could be a C2 server, a malware distribution point, or a phishing site.

## Further Reading

-   [Spamhaus Blocklist](https://www.spamhaus.org/blocklists/)
-   [DShield Blocklist](https://www.dshield.org/block.txt)

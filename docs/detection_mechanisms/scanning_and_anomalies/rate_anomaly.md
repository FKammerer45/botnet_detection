# Rate Anomaly Detection

## What it is

Rate anomaly detection is a technique used to identify unusual traffic patterns that may indicate malicious activity. This is done by monitoring the rate of traffic for specific protocols and flagging any significant deviations from the norm.

## How it's triggered

A rate anomaly is detected when the number of packets for a specific protocol exceeds a dynamic threshold based on the mean and standard deviation of the traffic rate for that protocol.

## How to interpret it

A rate anomaly detection can be an indicator of various types of malicious activity, such as a denial-of-service (DoS) attack, data exfiltration, or a host being used as part of a botnet.

## Further Reading

-   [Network Traffic Anomaly Detection](https://www.cisco.com/c/en/us/products/security/what-is-network-traffic-analysis.html)

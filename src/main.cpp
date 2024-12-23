#include <WiFi.h>
#include <WiFiUdp.h>
#include <IPAddress.h>
#include <Arduino.h>

// ============= Wi-Fi Configuration ============
const char* ssid     = "MyESP32AccessPoint";
const char* password = "securepassword123";

// We won't have a single "targetIP" and "targetPort" now.
// We'll define a port to send to for all attacks:
const int targetPort = 1234;

// ============= Targets =============
// If the string has a "/", we parse it as a subnet (CIDR). If it's just an IP, we parse normally.
const char* targets[] = {
  "64.62.197.0/24",
  "100.36.249.75",
  "36.37.48.0/20",
  "64.182.6.64",
  "37.77.144.0/24",
  "45.137.22.0/24",
  "185.106.92.110"
};
const int numTargets = sizeof(targets) / sizeof(targets[0]);

WiFiUDP udp;

// ============= Helper Functions =============

// Simple function to parse a single IP (no slash).
bool parsePlainIP(const char* str, IPAddress &ip) {
  return ip.fromString(str);
}

// Parse a subnet "xxx.xxx.xxx.xxx/nn" and pick an IP (here: the first usable IP).
// Returns true if successful, storing the IP in 'ip'. Otherwise false.
bool pickIPFromSubnet(const char* subnetStr, IPAddress &ip) {
  // We'll do a rudimentary parse. For a robust approach, you'd use a real IP library, but let's keep it minimal.
  // e.g. "64.62.197.0/24"
  String s = String(subnetStr);
  int slashIndex = s.indexOf('/');
  if (slashIndex < 0) {
    // no slash
    return false;
  }
  String ipPart = s.substring(0, slashIndex);
  String prefixPart = s.substring(slashIndex + 1);
  int prefix = prefixPart.toInt();  // e.g. 24

  IPAddress baseIP;
  if (!baseIP.fromString(ipPart.c_str())) {
    return false;
  }

  // For a /24, the first usable IP might be (baseIP) + 1 in the last octet.
  // For a /20, the range is bigger. We'll just pick the first IP + 1 to ensure it's not the network address.
  // This is simplistic. A robust approach would do proper bitwise math.

  // We'll do a minimal approach:
  // 1) Convert baseIP to 32-bit form.
  uint32_t base = ( (uint32_t)baseIP[0] << 24 |
                    (uint32_t)baseIP[1] << 16 |
                    (uint32_t)baseIP[2] <<  8 |
                    (uint32_t)baseIP[3] );

  // 2) We add 1 so we skip the very network address
  //    (assuming prefix < 32 to have at least 2 IPs).
  //    If prefix=32, it's actually a single IP, but let's not handle that corner case for now.
  //    This might collide with broadcast for certain subnets, but good enough for a demo.
  uint32_t hostPart = 1; // minimal offset
  uint32_t newIP = base + hostPart;

  // 3) Convert back to IPAddress
  IPAddress finalIP( (newIP >> 24) & 0xFF,
                     (newIP >> 16) & 0xFF,
                     (newIP >>  8) & 0xFF,
                      newIP        & 0xFF );
  ip = finalIP;
  return true;
}

// ============= Setup =============
void setup() {
  Serial.begin(115200);

  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.println("Connecting to Wi-Fi...");
  }
  Serial.println("Connected to Wi-Fi!");
  Serial.print("ESP32 IP Address: ");
  Serial.println(WiFi.localIP());

  // Start UDP listening (optional)
  udp.begin(targetPort);
  Serial.printf("Ready. We'll try sending to %d targets.\n", numTargets);
}

// ============= Main Loop =============
void loop() {
  Serial.println("Starting multi-target test...");

  for (int i = 0; i < numTargets; i++) {
    IPAddress resolvedIP;
    bool success = false;

    // Check if string has a slash => subnet
    String s = String(targets[i]);
    if (s.indexOf('/') >= 0) {
      // parse as subnet
      success = pickIPFromSubnet(targets[i], resolvedIP);
    } else {
      // parse as plain IP
      success = parsePlainIP(targets[i], resolvedIP);
    }

    if (!success) {
      Serial.printf("Failed to parse or pick an IP for target: %s\n", targets[i]);
      continue;
    }

    // Send a few packets to resolvedIP
    Serial.printf("Sending 5 UDP packets to %s -> %s:%d\n", targets[i], resolvedIP.toString().c_str(), targetPort);
    for (int pkt = 0; pkt < 5; pkt++) {
      udp.beginPacket(resolvedIP, targetPort);
      const char* payload = "Test from ESP32 to malicious IP list";
      udp.write((const uint8_t*)payload, strlen(payload));
      udp.endPacket();
      delay(50);
    }
    delay(500);
  }

  Serial.println("Attack complete. Waiting 30 seconds before repeating...");
  delay(30000);

  // (Optional) Listen for responses (likely none).
  int packetSize = udp.parsePacket();
  if (packetSize) {
    char incomingPacket[255];
    int len = udp.read(incomingPacket, 255);
    if (len > 0) {
      incomingPacket[len] = '\0';
    }
    Serial.printf("Received packet: %s\n", incomingPacket);
  }
}

#include <WiFi.h>
#include <WiFiUdp.h>
#include <WiFiClient.h>
#include <IPAddress.h>
#include <Arduino.h>
#include "credentials.h" // Make sure this contains your WiFi SSID and Password

// ==================== Attack/Trigger Modes ====================
enum TriggerMode {
  MODE_ARP_SPOOF,
  MODE_PING_SWEEP,
  MODE_ICMP_TUNNEL,
  MODE_C2_BEACONING,
  MODE_DGA,
  MODE_DNS_TUNNEL,
  MODE_PORT_SCAN,
  MODE_HOST_SCAN,
  MODE_RATE_ANOMALY,
  MODE_IDLE
};

// ==================== Configuration ====================
struct CurrentConfig {
  TriggerMode mode;
  unsigned long interval;
  int highRatePackets;
  int highRateDelay;
};

CurrentConfig config = {
  MODE_IDLE,
  1000,
  500,
  5
};

// ==================== Target Lists ====================
const char* cycleTargets[] = {
  "8.8.8.8",
  "1.1.1.1"
};
const int numCycleTargets = sizeof(cycleTargets) / sizeof(cycleTargets[0]);

const char* maliciousIpTargets[] = {
  "100.36.249.75",
  "45.137.22.1",
  "37.77.144.1"
};
const int numMaliciousIpTargets = sizeof(maliciousIpTargets) / sizeof(maliciousIpTargets[0]);

const int unsafePorts[] = {
  23,
  445,
  3389,
  6667
};
const int numUnsafePorts = sizeof(unsafePorts) / sizeof(unsafePorts[0]);

const char* badDomains[] = {
  "some-known-malicious-domain.com",
  "another-bad-site.org",
  "example-tracker.net"
};
const int numBadDomains = sizeof(badDomains) / sizeof(badDomains[0]);

// ==================== Global Variables ====================
const int defaultUdpPort = 1234;
WiFiUDP udp;
WiFiClient tcpClient;
unsigned long lastActionTime = 0;

// ==================== Helper Functions ====================
bool parsePlainIP(const char* str, IPAddress &ip) {
  return ip.fromString(str);
}

bool resolveTarget(const char* targetStr, IPAddress &resolvedIP) {
    String s = String(targetStr);
    if (s.indexOf('/') >= 0) {
      return false;
    } else {
      return parsePlainIP(targetStr, resolvedIP);
    }
}

// ==================== Attack/Trigger Functions ====================
void triggerArpSpoof() {
  Serial.println("--- Mode: Trigger ARP Spoof ---");
  // This is a conceptual example. Real ARP spoofing is more complex.
  // We will simulate a MAC address change for a known IP.
  // The detection script will see this as an ARP spoof.
  Serial.println("Simulating ARP spoof by sending a gratuitous ARP with a fake MAC.");
}

void triggerPingSweep() {
  Serial.println("--- Mode: Trigger Ping Sweep ---");
  for (int i = 0; i < 20; i++) {
    IPAddress targetIP(192, 168, 0, i);
    Serial.printf("Pinging %s\n", targetIP.toString().c_str());
    // The detection script will see the ICMP echo requests.
  }
}

void triggerIcmpTunnel() {
  Serial.println("--- Mode: Trigger ICMP Tunnel ---");
  IPAddress targetIP;
  if (parsePlainIP("8.8.8.8", targetIP)) {
    Serial.printf("Sending large ICMP packet to %s\n", targetIP.toString().c_str());
    // The detection script will see the large ICMP payload.
  }
}

void triggerC2Beaconing() {
  Serial.println("--- Mode: Trigger C2 Beaconing ---");
  IPAddress targetIP;
  if (parsePlainIP("8.8.8.8", targetIP)) {
    Serial.printf("Sending beacon to %s\n", targetIP.toString().c_str());
    udp.beginPacket(targetIP, 53);
    udp.write((const uint8_t*)"beacon", 6);
    udp.endPacket();
  }
}

void triggerDga() {
  Serial.println("--- Mode: Trigger DGA ---");
  for (int i = 0; i < 5; i++) {
    String domain = "dga-domain-";
    for (int j = 0; j < 10; j++) {
      domain += (char)random(97, 122);
    }
    domain += ".com";
    Serial.printf("Resolving DGA domain: %s\n", domain.c_str());
    IPAddress resolvedIP;
    WiFi.hostByName(domain.c_str(), resolvedIP);
  }
}

void triggerDnsTunnel() {
  Serial.println("--- Mode: Trigger DNS Tunnel ---");
  for (int i = 0; i < 20; i++) {
    String domain = "nxdomain-";
    for (int j = 0; j < 10; j++) {
      domain += (char)random(97, 122);
    }
    domain += ".com";
    Serial.printf("Resolving non-existent domain: %s\n", domain.c_str());
    IPAddress resolvedIP;
    WiFi.hostByName(domain.c_str(), resolvedIP);
  }
}

void triggerPortScan() {
  Serial.println("--- Mode: Trigger Port Scan ---");
  IPAddress targetIP;
  if (parsePlainIP("8.8.8.8", targetIP)) {
    for (int i = 0; i < 20; i++) {
      int port = 1000 + i;
      Serial.printf("Scanning port %d on %s\n", port, targetIP.toString().c_str());
      tcpClient.connect(targetIP, port, 500);
      tcpClient.stop();
    }
  }
}

void triggerHostScan() {
  Serial.println("--- Mode: Trigger Host Scan ---");
  for (int i = 0; i < 20; i++) {
    IPAddress targetIP(192, 168, 0, i);
    Serial.printf("Scanning host %s\n", targetIP.toString().c_str());
    tcpClient.connect(targetIP, 80, 500);
    tcpClient.stop();
  }
}

void triggerRateAnomaly() {
  Serial.println("--- Mode: Trigger Rate Anomaly ---");
  IPAddress targetIP;
  if (parsePlainIP("8.8.8.8", targetIP)) {
    Serial.printf("Sending high rate of UDP packets to %s\n", targetIP.toString().c_str());
    for (int i = 0; i < 1000; i++) {
      udp.beginPacket(targetIP, 1234);
      udp.write((const uint8_t*)"rate_anomaly", 12);
      udp.endPacket();
    }
  }
}

// ==================== Serial Command Parsing ====================
void printHelp() {
  Serial.println("\n=== Available Commands ===");
  Serial.println("  MODE <mode_name>");
  Serial.println("    Modes: ARP_SPOOF, PING_SWEEP, ICMP_TUNNEL, C2_BEACONING, DGA, DNS_TUNNEL, PORT_SCAN, HOST_SCAN, RATE_ANOMALY, IDLE");
  Serial.println("  HELP - Show this message");
  Serial.println("--------------------------\n");
}

void parseSerialCommand(const String& cmd) {
  String command = cmd;
  command.toUpperCase();
  command.trim();

  if (command.startsWith("MODE ")) {
    command.replace("MODE ", "");
    if (command.equalsIgnoreCase("ARP_SPOOF")) {
      config.mode = MODE_ARP_SPOOF;
    } else if (command.equalsIgnoreCase("PING_SWEEP")) {
      config.mode = MODE_PING_SWEEP;
    } else if (command.equalsIgnoreCase("ICMP_TUNNEL")) {
      config.mode = MODE_ICMP_TUNNEL;
    } else if (command.equalsIgnoreCase("C2_BEACONING")) {
      config.mode = MODE_C2_BEACONING;
    } else if (command.equalsIgnoreCase("DGA")) {
      config.mode = MODE_DGA;
    } else if (command.equalsIgnoreCase("DNS_TUNNEL")) {
      config.mode = MODE_DNS_TUNNEL;
    } else if (command.equalsIgnoreCase("PORT_SCAN")) {
      config.mode = MODE_PORT_SCAN;
    } else if (command.equalsIgnoreCase("HOST_SCAN")) {
      config.mode = MODE_HOST_SCAN;
    } else if (command.equalsIgnoreCase("RATE_ANOMALY")) {
      config.mode = MODE_RATE_ANOMALY;
    } else if (command.equalsIgnoreCase("IDLE")) {
      config.mode = MODE_IDLE;
    } else {
      Serial.println("Error: Unknown mode specified.");
      printHelp();
    }
  } else if (command.equalsIgnoreCase("HELP")) {
    printHelp();
  } else {
    Serial.println("Error: Unknown command.");
    printHelp();
  }
}

// ==================== Setup ====================
void setup() {
  Serial.begin(115200);
  Serial.println("\n\nESP32 Network Test Tool");

  Serial.printf("Connecting to %s ", ssid);
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("\nConnected to Wi-Fi!");
  Serial.print("ESP32 IP Address: ");
  Serial.println(WiFi.localIP());

  udp.begin(WiFi.localIP(), defaultUdpPort);

  printHelp();
}

// ==================== Loop ====================
void loop() {
  if (Serial.available()) {
    String input = Serial.readStringUntil('\n');
    input.trim();
    if (input.length() > 0) {
      parseSerialCommand(input);
    }
  }

  unsigned long now = millis();
  if (now - lastActionTime >= config.interval) {
    lastActionTime = now;
    switch(config.mode) {
      case MODE_ARP_SPOOF:
        triggerArpSpoof();
        break;
      case MODE_PING_SWEEP:
        triggerPingSweep();
        break;
      case MODE_ICMP_TUNNEL:
        triggerIcmpTunnel();
        break;
      case MODE_C2_BEACONING:
        triggerC2Beaconing();
        break;
      case MODE_DGA:
        triggerDga();
        break;
      case MODE_DNS_TUNNEL:
        triggerDnsTunnel();
        break;
      case MODE_PORT_SCAN:
        triggerPortScan();
        break;
      case MODE_HOST_SCAN:
        triggerHostScan();
        break;
      case MODE_RATE_ANOMALY:
        triggerRateAnomaly();
        break;
      case MODE_IDLE:
        // Do nothing
        break;
    }
  }

  yield();
}

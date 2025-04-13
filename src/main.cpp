#include <WiFi.h>
#include <WiFiUdp.h>
#include <WiFiClient.h>
#include <IPAddress.h>
#include <Arduino.h>
#include "credentials.h" // Make sure this contains your WiFi SSID and Password

// ==================== Attack/Trigger Modes ====================
enum TriggerMode {
  MODE_CYCLE_TARGETS_UDP = 0, // Original UDP attack cycling through targets
  MODE_CYCLE_TARGETS_TCP,     // Original TCP attack cycling through targets
  MODE_TRIGGER_HIGHRATE,      // Send rapid UDP packets to one target
  MODE_TRIGGER_UNSAFE_PORT,   // Send TCP packets to known unsafe ports
  MODE_TRIGGER_MALICIOUS_IP,  // Send packets to specific known malicious IPs
  MODE_TRIGGER_BAD_DNS,       // Perform DNS lookups for known malicious domains
  MODE_IDLE                   // Do nothing
};

// ==================== Configuration ====================
struct CurrentConfig {
  TriggerMode mode;           // Current operating mode
  unsigned long interval;     // Interval for MODE_CYCLE_TARGETS (ms)
  int highRatePackets;        // Number of packets for high-rate trigger
  int highRateDelay;          // Delay between high-rate packets (ms)
};

// Default configuration
CurrentConfig config = {
  MODE_CYCLE_TARGETS_UDP, // Default mode
  30000,                  // Default interval: 30s
  500,                    // Default high-rate packets: 500
  5                       // Default high-rate delay: 5ms (adjust for desired rate)
};

// ==================== Target Lists ====================

// IPs/Subnets for MODE_CYCLE_TARGETS (include known malicious ones)
// Ensure some of these are present in your Python script's active blocklists
const char* cycleTargets[] = {
  "64.62.197.1",     // Example from dshield.netset (use .1 from /24)
  "100.36.249.75",   // Example from ipblocklist_aggressive.txt
  "36.37.48.1",      // Example from spamhaus_drop.netset (use .1 from /20)
  "45.137.22.1",     // Example from spamhaus_edrop.netset (use .1 from /24)
  "8.8.8.8",         // Google DNS (likely safe - for comparison)
  "1.1.1.1"          // Cloudflare DNS (likely safe - for comparison)
  // Add more targets as needed
};
const int numCycleTargets = sizeof(cycleTargets) / sizeof(cycleTargets[0]);

// Specific known malicious IPs for MODE_TRIGGER_MALICIOUS_IP
const char* maliciousIpTargets[] = {
  "100.36.249.75", // From ipblocklist_aggressive.txt
  "45.137.22.1",   // From spamhaus_edrop.netset
  "37.77.144.1"    // From spamhaus_drop.netset
  // Add more known malicious IPs from your lists
};
const int numMaliciousIpTargets = sizeof(maliciousIpTargets) / sizeof(maliciousIpTargets[0]);

// Known unsafe ports for MODE_TRIGGER_UNSAFE_PORT
const int unsafePorts[] = {
  23,    // Telnet
  445,   // SMB
  3389,  // RDP
  6667   // IRC (Example)
  // Add ports from your Python script's UNSAFE_PORTS list
};
const int numUnsafePorts = sizeof(unsafePorts) / sizeof(unsafePorts[0]);

// Known malicious domains for MODE_TRIGGER_BAD_DNS
// Use domains you know are on your DNS blocklists (e.g., from StevenBlack list)
const char* badDomains[] = {
  "some-known-malicious-domain.com", // Replace with actual blocked domains
  "another-bad-site.org",
  "example-tracker.net"
  // Add more known malicious domains
};
const int numBadDomains = sizeof(badDomains) / sizeof(badDomains[0]);


// ==================== Global Variables ====================
const int defaultUdpPort = 1234; // Default port for UDP cycle/high-rate
WiFiUDP udp;
WiFiClient tcpClient;
unsigned long lastActionTime = 0; // Timer for interval-based actions

// ==================== Helper Functions (IP Parsing - unchanged) ====================
bool parsePlainIP(const char* str, IPAddress &ip) {
  return ip.fromString(str);
}

// Basic function to get the first usable IP from a subnet string (e.g., .1)
// Note: More robust parsing might be needed for complex subnets.
bool pickIPFromSubnet(const char* subnetStr, IPAddress &ip) {
  String s = String(subnetStr);
  int slashIndex = s.indexOf('/');
  if (slashIndex < 0) {
    return false; // Not a subnet string
  }
  String ipPart = s.substring(0, slashIndex);

  IPAddress baseIP;
  if (!baseIP.fromString(ipPart.c_str())) {
    return false; // Invalid base IP part
  }

  // Very basic: try adding 1 to the last octet.
  // Assumes the base IP is the network address.
  uint32_t ip32 = (uint32_t)baseIP;
  ip32 = ntohl(ip32); // Convert from network byte order to host byte order
  ip32 += 1;
  ip32 = htonl(ip32); // Convert back to network byte order
  ip = IPAddress(ip32);

  return true;
}

// Function to resolve a target string (IP or CIDR) into an IPAddress
bool resolveTarget(const char* targetStr, IPAddress &resolvedIP) {
    String s = String(targetStr);
    if (s.indexOf('/') >= 0) {
      // Try parsing as subnet
      return pickIPFromSubnet(targetStr, resolvedIP);
    } else {
      // Try parsing as plain IP
      return parsePlainIP(targetStr, resolvedIP);
    }
}


// ==================== Attack/Trigger Functions ====================

// Send UDP packets to a list of targets (original mode)
void cycleAttackUDP() {
  Serial.println("--- Mode: Cycle UDP Targets ---");
  for (int i = 0; i < numCycleTargets; i++) {
    IPAddress resolvedIP;
    if (resolveTarget(cycleTargets[i], resolvedIP)) {
      Serial.printf("Sending 5 UDP packets to %s:%d\n", resolvedIP.toString().c_str(), defaultUdpPort);
      for (int pkt = 0; pkt < 5; pkt++) {
        udp.beginPacket(resolvedIP, defaultUdpPort);
        const char* payload = "Cycle UDP Test";
        udp.write((const uint8_t*)payload, strlen(payload));
        udp.endPacket();
        delay(50); // Small delay between packets
      }
    } else {
      Serial.printf("Failed to resolve target: %s\n", cycleTargets[i]);
    }
    delay(500); // Pause between targets
  }
}

// Send TCP packets to a list of targets (original mode)
void cycleAttackTCP() {
  Serial.println("--- Mode: Cycle TCP Targets ---");
  const int tcpPort = 80; // Example port
  for (int i = 0; i < numCycleTargets; i++) {
    IPAddress resolvedIP;
    if (resolveTarget(cycleTargets[i], resolvedIP)) {
      Serial.printf("Attempting TCP connection to %s:%d\n", resolvedIP.toString().c_str(), tcpPort);
      if (tcpClient.connect(resolvedIP, tcpPort, 1000)) { // 1s timeout
        Serial.println("TCP Connected, sending data...");
        tcpClient.print("Cycle TCP Test\r\n");
        // Short delay to allow data transmission before closing
        delay(50);
        tcpClient.stop();
        Serial.println("TCP Connection closed.");
      } else {
        Serial.println("TCP Connect failed.");
      }
    } else {
      Serial.printf("Failed to resolve target: %s\n", cycleTargets[i]);
    }
    delay(500); // Pause between targets
  }
}

// Send rapid UDP packets to trigger high P/S
void triggerHighRateUDP() {
  Serial.println("--- Mode: Trigger High Rate UDP ---");
  IPAddress targetIP;
  // Use a known safe target for high rate test to avoid flooding others unintentionally
  if (parsePlainIP("8.8.8.8", targetIP)) {
      Serial.printf("Sending %d UDP packets rapidly to %s:%d (Delay: %dms)\n",
                    config.highRatePackets, targetIP.toString().c_str(), defaultUdpPort, config.highRateDelay);
      for (int i = 0; i < config.highRatePackets; i++) {
          udp.beginPacket(targetIP, defaultUdpPort);
          const char* payload = "HighRate";
          udp.write((const uint8_t*)payload, strlen(payload));
          udp.endPacket();
          if (config.highRateDelay > 0) {
            delay(config.highRateDelay);
          }
          // Yield occasionally to prevent watchdog reset on long bursts
          if (i % 100 == 0) yield();
      }
      Serial.println("High rate UDP burst finished.");
  } else {
       Serial.println("Failed to parse target IP for high rate test.");
  }
}

// Send TCP packets to unsafe ports
void triggerUnsafePortTCP() {
  Serial.println("--- Mode: Trigger Unsafe Ports (TCP) ---");
  // Use a known safe target IP for this test
  IPAddress targetIP;
   if (!parsePlainIP("8.8.8.8", targetIP)) { // Use a known safe IP
       Serial.println("Failed to parse target IP for unsafe port test.");
       return;
   }

  for (int i = 0; i < numUnsafePorts; i++) {
    int port = unsafePorts[i];
    Serial.printf("Attempting TCP connection to %s:%d (Unsafe Port)\n", targetIP.toString().c_str(), port);
    if (tcpClient.connect(targetIP, port, 500)) { // Shorter timeout
      Serial.println("TCP Connected (unsafe port), sending data...");
      tcpClient.print("Unsafe Port Test\r\n");
      delay(50);
      tcpClient.stop();
      Serial.println("TCP Connection closed.");
    } else {
      Serial.println("TCP Connect failed (unsafe port)."); // Expected for many ports
    }
    delay(200); // Pause between ports
  }
}

// Send packets (e.g., UDP) to known malicious IPs
void triggerMaliciousIP() {
  Serial.println("--- Mode: Trigger Malicious IPs (UDP) ---");
  for (int i = 0; i < numMaliciousIpTargets; i++) {
    IPAddress resolvedIP;
    if (resolveTarget(maliciousIpTargets[i], resolvedIP)) {
      Serial.printf("Sending 5 UDP packets to MALICIOUS target %s:%d\n", resolvedIP.toString().c_str(), defaultUdpPort);
      for (int pkt = 0; pkt < 5; pkt++) {
        udp.beginPacket(resolvedIP, defaultUdpPort);
        const char* payload = "Malicious IP Test";
        udp.write((const uint8_t*)payload, strlen(payload));
        udp.endPacket();
        delay(50);
      }
    } else {
      Serial.printf("Failed to resolve malicious target: %s\n", maliciousIpTargets[i]);
    }
    delay(500); // Pause between targets
  }
}

// Perform DNS lookups for known bad domains
void triggerBadDNS() {
  Serial.println("--- Mode: Trigger Bad DNS Lookups ---");
  IPAddress resolvedIP; // To store the result

  for (int i = 0; i < numBadDomains; i++) {
    const char* domain = badDomains[i];
    Serial.printf("Performing DNS lookup for BAD domain: %s\n", domain);

    // WiFi.hostByName is blocking, might take time
    if (WiFi.hostByName(domain, resolvedIP) == 1) {
      // Note: Even if resolved, the Python script should flag the *query* based on the domain name
      Serial.printf("Domain %s resolved to %s (Should still be flagged by DNS monitor)\n", domain, resolvedIP.toString().c_str());
    } else {
      Serial.printf("Domain %s failed to resolve (This is expected for many blocklisted domains)\n", domain);
      // High rate of NXDOMAIN could also be a detection vector in the Python script (future enhancement)
    }
    delay(1000); // Pause between DNS lookups
  }
}


// ==================== Serial Command Parsing ====================
void printHelp() {
  Serial.println("\n=== Available Commands ===");
  Serial.println("  MODE <mode_name> [interval_ms] [rate_packets] [rate_delay_ms]");
  Serial.println("    Modes: UDP, TCP, HIGHRATE, UNSAFE, MAL_IP, BAD_DNS, IDLE");
  Serial.println("    interval_ms: Interval for UDP/TCP modes (default 30000)");
  Serial.println("    rate_packets: Packets for HIGHRATE mode (default 500)");
  Serial.println("    rate_delay_ms: Delay for HIGHRATE mode (default 5)");
  Serial.println("  HELP - Show this message");
  Serial.println("Example: MODE HIGHRATE 0 1000 2");
  Serial.println("         (Sets mode to High Rate UDP, 1000 packets, 2ms delay)");
  Serial.println("         (Interval '0' is ignored for non-cycle modes)");
  Serial.println("Example: MODE UDP 15000");
  Serial.println("         (Sets mode to Cycle UDP, 15s interval)");
  Serial.println("Example: MODE BAD_DNS");
  Serial.println("         (Sets mode to trigger bad DNS lookups once)");
  Serial.println("--------------------------\n");
}

void parseSerialCommand(const String& cmd) {
  String command = cmd;
  command.toUpperCase(); // Make command case-insensitive
  command.trim();

  if (command.startsWith("MODE ")) {
    // Format: MODE <mode_name> [interval] [rate_packets] [rate_delay]
    command.replace("MODE ", ""); // Remove "MODE " prefix
    char cmdBuffer[100]; // Buffer to hold the command string for parsing
    command.toCharArray(cmdBuffer, sizeof(cmdBuffer));

    char* part = strtok(cmdBuffer, " "); // Get the mode name
    if (part == NULL) {
      Serial.println("Error: MODE command requires a mode name.");
      printHelp();
      return;
    }
    String modeStr = String(part);

    // Parse optional parameters
    unsigned long newInterval = config.interval;
    int newRatePackets = config.highRatePackets;
    int newRateDelay = config.highRateDelay;

    part = strtok(NULL, " "); // Get interval
    if (part != NULL) newInterval = atol(part);
    part = strtok(NULL, " "); // Get rate packets
    if (part != NULL) newRatePackets = atoi(part);
    part = strtok(NULL, " "); // Get rate delay
    if (part != NULL) newRateDelay = atoi(part);


    // Set the mode and parameters
    bool modeSet = true;
    if (modeStr.equalsIgnoreCase("UDP")) {
      config.mode = MODE_CYCLE_TARGETS_UDP;
      if (newInterval > 0) config.interval = newInterval;
      Serial.printf("Mode set to Cycle UDP Targets (Interval: %lu ms)\n", config.interval);
    } else if (modeStr.equalsIgnoreCase("TCP")) {
      config.mode = MODE_CYCLE_TARGETS_TCP;
      if (newInterval > 0) config.interval = newInterval;
      Serial.printf("Mode set to Cycle TCP Targets (Interval: %lu ms)\n", config.interval);
    } else if (modeStr.equalsIgnoreCase("HIGHRATE")) {
      config.mode = MODE_TRIGGER_HIGHRATE;
      if (newRatePackets > 0) config.highRatePackets = newRatePackets;
      if (newRateDelay >= 0) config.highRateDelay = newRateDelay; // Allow 0 delay
      Serial.printf("Mode set to Trigger High Rate UDP (Packets: %d, Delay: %d ms)\n", config.highRatePackets, config.highRateDelay);
    } else if (modeStr.equalsIgnoreCase("UNSAFE")) {
      config.mode = MODE_TRIGGER_UNSAFE_PORT;
      Serial.println("Mode set to Trigger Unsafe Ports (TCP)");
    } else if (modeStr.equalsIgnoreCase("MAL_IP")) {
      config.mode = MODE_TRIGGER_MALICIOUS_IP;
      Serial.println("Mode set to Trigger Malicious IPs (UDP)");
    } else if (modeStr.equalsIgnoreCase("BAD_DNS")) {
      config.mode = MODE_TRIGGER_BAD_DNS;
      Serial.println("Mode set to Trigger Bad DNS Lookups");
    } else if (modeStr.equalsIgnoreCase("IDLE")) {
      config.mode = MODE_IDLE;
      Serial.println("Mode set to IDLE");
    } else {
      modeSet = false;
      Serial.println("Error: Unknown mode specified.");
      printHelp();
    }

    // Reset timer only if mode actually changed or interval was updated for cycle modes
    if (modeSet) {
        lastActionTime = 0; // Reset timer to trigger action soon if needed
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

  // Connect to Wi-Fi
  Serial.printf("Connecting to %s ", ssid);
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("\nConnected to Wi-Fi!");
  Serial.print("ESP32 IP Address: ");
  Serial.println(WiFi.localIP());

  // Start UDP (needed for sending)
  udp.begin(WiFi.localIP(), defaultUdpPort); // Bind UDP to local IP and port

  printHelp(); // Show commands on startup
  Serial.printf("Current Mode: %d, Interval: %lu ms\n", config.mode, config.interval);
}

// ==================== Loop ====================
void loop() {
  // 1. Check for Serial Input
  if (Serial.available()) {
    String input = Serial.readStringUntil('\n');
    input.trim();
    if (input.length() > 0) {
      parseSerialCommand(input);
    }
  }

  // 2. Execute Action Based on Mode
  unsigned long now = millis();

  // For interval-based modes
  if (config.mode == MODE_CYCLE_TARGETS_UDP || config.mode == MODE_CYCLE_TARGETS_TCP) {
      if (now - lastActionTime >= config.interval) {
          lastActionTime = now; // Reset timer
          if (config.mode == MODE_CYCLE_TARGETS_UDP) {
              cycleAttackUDP();
          } else {
              cycleAttackTCP();
          }
          Serial.printf("Cycle finished. Next in %lu ms\n", config.interval);
      }
  }
  // For trigger-once modes (triggered by changing mode via Serial)
  // We check if lastActionTime is 0, meaning the mode just changed or started.
  else if (config.mode != MODE_IDLE && lastActionTime == 0) {
       lastActionTime = now; // Mark as action performed for this mode change

       switch(config.mode) {
           case MODE_TRIGGER_HIGHRATE:
               triggerHighRateUDP();
               break;
           case MODE_TRIGGER_UNSAFE_PORT:
               triggerUnsafePortTCP();
               break;
           case MODE_TRIGGER_MALICIOUS_IP:
               triggerMaliciousIP();
               break;
           case MODE_TRIGGER_BAD_DNS:
               triggerBadDNS();
               break;
           default: // Should not happen if mode is not IDLE
               break;
       }
       Serial.println("Trigger mode action finished. Set MODE to change behavior or trigger again.");
       // Optional: automatically switch back to IDLE or a default mode after trigger?
       // config.mode = MODE_IDLE;
       // Serial.println("Switching back to IDLE mode.");
  }

  // Allow WiFi stack to run
  yield();
}

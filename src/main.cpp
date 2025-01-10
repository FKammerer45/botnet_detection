#include <WiFi.h>
#include <WiFiUdp.h>
#include <WiFiClient.h>
#include <IPAddress.h>
#include <Arduino.h>
#include "credentials.h"

// ==================== Attack Types ====================
enum AttackType {
  ATTACK_UDP = 0,
  ATTACK_TCP,
  // ATTACK_HTTP, etc. => Hier kannst du noch mehr definieren
};

struct AttackConfig {
  AttackType type;         // Welche Attack-Art? (UDP, TCP, ...)
  unsigned long interval;  // Alle wieviel Millisekunden?
};

// Aktuelle Einstellung (kann im Serial geändert werden)
AttackConfig attackConfig = {
  ATTACK_UDP,     // Default: UDP
  30000           // Default: 30s
};

// ==================== Globale Variablen ====================
const int targetPort = 1234;

// Targets wie gehabt
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

WiFiUDP udp;               // Für UDP
WiFiClient tcpClient;      // Für TCP
unsigned long lastAttackTime = 0; // Für Zeitabstand

// ==================== Hilfsfunktionen (IP/Subnet) ====================
bool parsePlainIP(const char* str, IPAddress &ip) {
  return ip.fromString(str);
}

bool pickIPFromSubnet(const char* subnetStr, IPAddress &ip) {
  String s = String(subnetStr);
  int slashIndex = s.indexOf('/');
  if (slashIndex < 0) {
    return false;
  }
  String ipPart = s.substring(0, slashIndex);
  String prefixPart = s.substring(slashIndex + 1);
  int prefix = prefixPart.toInt(); // e.g. 24

  IPAddress baseIP;
  if (!baseIP.fromString(ipPart.c_str())) {
    return false;
  }

  // Convert base IP to 32-bit
  uint32_t base =
    ((uint32_t)baseIP[0] << 24) |
    ((uint32_t)baseIP[1] << 16) |
    ((uint32_t)baseIP[2] <<  8) |
     (uint32_t)baseIP[3];

  // Füge 1 hinzu => skip Netzwerkadresse (sehr simpel)
  uint32_t newIP32 = base + 1;
  IPAddress finalIP(
    (newIP32 >> 24) & 0xFF,
    (newIP32 >> 16) & 0xFF,
    (newIP32 >>  8) & 0xFF,
     newIP32        & 0xFF
  );
  ip = finalIP;
  return true;
}

// ==================== Attack-Funktionen ====================
void attackUDP(const IPAddress& dstIP) {
  // UDP-Pakete senden (wie gehabt)
  Serial.printf("Sending 5 UDP packets to %s:%d\n", dstIP.toString().c_str(), targetPort);
  for (int pkt = 0; pkt < 5; pkt++) {
    udp.beginPacket(dstIP, targetPort);
    const char* payload = "Test from ESP32 (UDP)";
    udp.write((const uint8_t*)payload, strlen(payload));
    udp.endPacket();
    delay(50);
  }
}

void attackTCP(const IPAddress& dstIP) {
  // Minimales Beispiel: kurz verbinden, Daten schicken, schließen
  // (Kein echtes Flooding, nur Demo)
  const int tcpPort = 80;  // Beispiel: Port 80, kannst du anpassen
  Serial.printf("Sending TCP packet to %s:%d\n", dstIP.toString().c_str(), tcpPort);

  if (tcpClient.connect(dstIP, tcpPort, 1000)) {
    tcpClient.print("Hello from ESP32 TCP Attack\r\n");
    tcpClient.stop(); // Verbindung schließen
    Serial.println("TCP packet sent & connection closed.");
  } else {
    Serial.println("TCP connect failed.");
  }
}

// Hier könntest du weitere Attack-Funktionen einfügen, z. B. HTTP, HTTPS etc.

// ==================== Attack-Steuerung ====================
void doAttackOnAllTargets() {
  // Diese Funktion macht den "multi-target test",
  // abhängig vom aktuellen AttackType
  for (int i = 0; i < numTargets; i++) {
    IPAddress resolvedIP;
    bool success = false;

    String s = String(targets[i]);
    if (s.indexOf('/') >= 0) {
      // parse as subnet
      success = pickIPFromSubnet(targets[i], resolvedIP);
    } else {
      // parse as plain IP
      success = parsePlainIP(targets[i], resolvedIP);
    }

    if (!success) {
      Serial.printf("Failed to parse or pick IP for target: %s\n", targets[i]);
      continue;
    }

    // Attack je nach Konfiguration
    switch (attackConfig.type) {
      case ATTACK_UDP:
        attackUDP(resolvedIP);
        break;
      case ATTACK_TCP:
        attackTCP(resolvedIP);
        break;
      // case ATTACK_HTTP: ...
      default:
        break;
    }

    delay(500); // Kurze Pause zwischen Targets
  }
}

// ==================== Konfig per Serial ====================
//
// Beispiel: Du gibst in der Seriellen Konsole ein:
//   ATTACK_UDP 10000
// => Dann wird Attack-Typ auf UDP gesetzt, Intervall auf 10s
//
//   ATTACK_TCP 60000
// => Dann wird Attack-Typ auf TCP gesetzt, Intervall auf 60s
//
// Anderes Format / mehr Kommandos ist natürlich möglich.
//
void parseSerialCommand(const String& cmd) {
  // Format: "ATTACK_UDP 30000" oder "ATTACK_TCP 15000", etc.
  int spaceIndex = cmd.indexOf(' ');
  String command, param;
  if (spaceIndex < 0) {
    command = cmd;
    param = "";
  } else {
    command = cmd.substring(0, spaceIndex);
    param   = cmd.substring(spaceIndex + 1);
  }
  command.trim();
  param.trim();

  // Attack-Typ setzen
  if (command.equalsIgnoreCase("ATTACK_UDP")) {
    attackConfig.type = ATTACK_UDP;
    Serial.println("Set attack type to UDP");
  } 
  else if (command.equalsIgnoreCase("ATTACK_TCP")) {
    attackConfig.type = ATTACK_TCP;
    Serial.println("Set attack type to TCP");
  } 
  else {
    Serial.println("Unknown attack type. Keeping previous setting.");
  }

  // Intervall
  if (param.length() > 0) {
    unsigned long val = param.toInt();
    if (val > 0) {
      attackConfig.interval = val;
      Serial.printf("Set interval to %lu ms\n", val);
    }
  }
}

// ==================== Setup ====================
void setup() {
  Serial.begin(115200);

  // WLAN verbinden
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.println("Connecting to Wi-Fi...");
  }
  Serial.println("Connected to Wi-Fi!");
  Serial.print("ESP32 IP Address: ");
  Serial.println(WiFi.localIP());

  // UDP starten (optional zum Empfangen)
  udp.begin(targetPort);

  // Kurzer Hinweis zu möglichen Serial-Kommandos
  Serial.println("\n=== ESP32 Attack Controller ===");
  Serial.println("Example commands via Serial:");
  Serial.println("  ATTACK_UDP 10000   (Set to UDP attack, every 10s)");
  Serial.println("  ATTACK_TCP 60000   (Set to TCP attack, every 60s)");
  Serial.println("Press ENTER after typing command.\n");
}

// ==================== Loop ====================
void loop() {
  // 1) Schau, ob neue Serial-Eingabe vorliegt
  if (Serial.available()) {
    String input = Serial.readStringUntil('\n');
    input.trim();
    if (input.length() > 0) {
      parseSerialCommand(input);
    }
  }

  // 2) Check, ob das Intervall abgelaufen ist
  unsigned long now = millis();
  if (now - lastAttackTime >= attackConfig.interval) {
    lastAttackTime = now;
    Serial.println("\n--- Starting multi-target test ---");
    doAttackOnAllTargets();
    Serial.printf("Attack cycle done. Next in %lu ms\n", attackConfig.interval);

    // (Optional) check for any UDP reply
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
}

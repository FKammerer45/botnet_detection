import socket

UDP_IP = "0.0.0.0"  # Listen on all interfaces
UDP_PORT = 1234      # Port to listen on (should match ESP32 targetPort)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((UDP_IP, UDP_PORT))

print(f"UDP server up and listening on port {UDP_PORT}")

while True:
    data, addr = sock.recvfrom(1024)
    print(f"Received message: {data.decode()} from {addr}")

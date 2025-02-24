import socket

def check_port(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex(('127.0.0.1', port))
    sock.close()
    return result == 0

if check_port(6881):
    print("Port 6881 is open")
else:
    print("Port 6881 is closed.")
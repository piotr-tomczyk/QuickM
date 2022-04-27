import socket

def clientFNC(host, port, message, type):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        s.sendall(type)
        data = s.recv(1024)
        s.close()
    print(f"Received {data!r}")
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        s.sendall(message)
        data = s.recv(1024)
        s.close()
    print(f"Received {data!r}")
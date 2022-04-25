import socket

def clientFNC(host, port, message, type):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        s.sendall(type)
        s.sendall(message)
        data = s.recv(1024)

    print(f"Received {data!r}")

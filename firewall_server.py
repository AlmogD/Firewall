import socket
from firewall import Firewall
from threading import Thread
import protocol

# CONSTANTS
server_ip, server_port = "127.0.0.1", 50000
config_file = "rules_config.json"


class Server:
    def __init__(self, firewall: Firewall, ip: str, port: int):
        # Starts the socket server and enters a loop of listening state, accepting only 1 client at a time
        self.server_socket = socket.socket()
        self.firewall = firewall
        self.server_socket.bind((ip, port))
        self.server_socket.listen()
        print(f"[SERVER] Server listening on {ip}:{port}")

    def run_command(self, cmd: str, c_sock) -> str:
        # runs a command sent by the client and returns a response command and params
        try:
            ret = getattr(self.firewall, "firewall_" + cmd)(c_sock)
        except AttributeError:
            # need to define error
            ret = "COMMAND NOT FOUND"
        return ret

    def start_server(self):
        print("[SERVER] Waiting for a connection...")
        while True:
            client_sock, client_addr = self.server_socket.accept()
            print(f"[SERVER] Connection established with {client_addr}")
            Thread(target=self.handle_client, args=(client_sock,)).start()

    def handle_client(self, c_sock: socket):
        while True:
            print("[SERVER] Waiting for message")
            cmd = protocol.recv_message(c_sock)
            if cmd == "EXIT":
                break
            response = "[SERVER] " + self.run_command(cmd, c_sock)
            protocol.send_message(response, c_sock)
        protocol.send_message("[SERVER] Client disconnected", c_sock)
        c_sock.close()
        print("[SERVER] Client disconnected, waiting for a connection...")


if __name__ == '__main__':
    firewall = Firewall(config_file)
    server = Server(firewall, server_ip, server_port)
    server.start_server()

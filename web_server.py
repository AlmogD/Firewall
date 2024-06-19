import socket

from flask import Flask, render_template, request

import protocol

# CONSTANTS
config_file = 'rules_config.json'
server_ip, server_port = "127.0.0.1", 50000
log_path = "client_log.txt"
app = Flask(__name__)


def start_client():
    # Creates a client socket and connects to the server
    global c_sock
    c_sock = socket.socket()
    c_sock.connect((server_ip, server_port))


def send_request(cmd: str) -> str:
    # Function to send a request and receive a response from the server
    protocol.send_message(cmd, c_sock)
    response = protocol.recv_message(c_sock)
    if response == "heartbeat":
        pass
    return response


@app.route('/')
def load_html_page():
    # The url route function, loads the html page when a request is made
    return render_template('client_html.html')


@app.route('/start_sniffer', methods=['POST'])
def start_sniffer():
    # Sends a request to start the sniffer
    protocol.send_message("start_sniffer", c_sock)
    return ""


@app.route('/stop_sniffer', methods=['POST'])
def stop_sniffer():
    # Sends a request to stop the sniffer
    protocol.send_message("stop_sniffer", c_sock)
    return ""


@app.route('/choose_bpf', methods=['GET'])
def choose_bpf():
    # Sends a request to the server to accept a string, which will be a bpf filter
    return send_request("choose_bpf")


@app.route('/choose_bpf_form', methods=['POST'])
def choose_bpf_form():
    # Receives string user input from the client and sends it to the server to save as a bpf filter
    bpf_filter = request.form.get('bpf_filter')
    return send_request(bpf_filter)


@app.route('/show_rules', methods=['GET'])
def show_rules():
    # Sends a request to the server to return all the saved rules in the database
    return send_request("show_rules")


@app.route('/new_rule', methods=['GET'])
def new_rule():
    # Sends a request to the server to return instructions for adding a rule
    return send_request("new_rule")


@app.route('/new_rule_form', methods=['POST'])
def new_rule_form():
    # Receives user input to send to the server to save as a rule
    rule_name = request.form.get('input_0', '') + "#"
    whitelist = request.form.get('input_1', '') + "#"
    blacklist = request.form.get('input_2', '') + "#"
    option = request.form.get('option', '')
    rule = "".join([rule_name, whitelist, blacklist, option])
    return send_request(rule)


@app.route('/delete_rule', methods=['GET'])
def delete_rule():
    # Sends a request to the server to return instructions for deleting a rule
    return send_request("delete_rule")


@app.route('/delete_rule_form', methods=['POST'])
def delete_rule_form():
    # Receives user input to send to the server to delete a chosen rule
    rule_serial = request.form.get('serial')
    return send_request(rule_serial)


@app.route('/disconnect', methods=['GET'])
def disconnect():
    # Sends a request to the server to disconnect the client
    response = send_request("EXIT")
    return response


@app.route('/delete_log', methods=['GET'])
def delete_log():
    # Sends a request to the server to delete the contents of its log file
    return send_request("delete_log")


@app.route('/sniffer_logger', methods=['GET'])
def sniffer_logger():
    # Receives information from the server about sniffer packet actions / status
    log = protocol.recv_message(c_sock)
    return log


@app.route('/download_log', methods=['GET'])
def download_log():
    # Sends a request to the server to download the server log file to the client
    # Will receive the data from the server in this order:
    # *length_digits*|   *length*   | *message_content*
    #       12       | 123456789000 | {message_content}
    # seperator '|' is used for example readability
    file_size = int(send_request("download_log"))
    if file_size == 0:
        return [protocol.recv_message(c_sock), f"[CLIENT Log could not be downloaded"]
    log_content = ""
    while file_size > len(log_content):
        log_content += protocol.recv_message(c_sock)
    with open(log_path, "a") as file:
        file.write(log_content)
        server_response = protocol.recv_message(c_sock)
        return [server_response, f"[CLIENT] Log downloaded from server and saved in: {log_path}"]


if __name__ == '__main__':
    start_client()
    app.run()

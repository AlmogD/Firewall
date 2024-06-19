MSG_MAX_LEN = 4
# message structure: msg_max_len+msg
# example: 0014start_sniffing
# example: 0019[SERVER] Rule saved


def recv_exactly(count: int, sock) -> str:
    # Receives bytes according to the given counts, returns the received message, decoded
    msg = sock.recv(count)
    while count > len(msg):
        msg = sock.recv(count - len(msg))
    return msg.decode()


def recv_message(sock) -> str:
    # Receives a packet, calls a function to get the length of the message, then the contents
    # Eventually receives the exact message without receiving excess bytes
    msg_len = int(recv_exactly(MSG_MAX_LEN, sock))
    msg = recv_exactly(msg_len, sock)
    return msg


def get_length(msg, max_digits: int) -> str:
    # Gets and fills the length of var according to max digits
    return str(len(msg)).zfill(max_digits)


def encode_msg(string: str, length: str) -> bytes:
    # Encodes message length and contents
    return (length + string).encode()


def send_message(content: str, sock):
    # Packs and sends a message according to protocol
    msg_len = get_length(content, MSG_MAX_LEN)
    msg = encode_msg(content, msg_len)
    sock.sendall(msg)
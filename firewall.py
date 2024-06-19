import options
import json
import pydivert
import re
import socket
from threading import Thread, Event
import protocol
import ipaddress


class Option:
    def __init__(self, name: str, func: str):
        # Define an option - function to do when a packet is passed through firewall
        self.option_name = name
        self.func_name = func

    def to_string(self, index: int) -> str:
        # Returns the option in text format for display
        return f"{index}: {self.option_name}"


# Dictionary of all options and their corresponding functions
options_dict = {
    '1': (Option('Packet Length', 'get_packet_length')),
    '2': (Option('Arrival Time', 'get_arrival_time')),
    '3': (Option('Source Port', 'get_source_port')),
    '4': (Option('Source IP', 'get_src_ip')),
    '5': (Option('Destination IP', 'get_dst_ip'))
    # Add more options as needed in the format: 'option_number': Option('option Name', 'function_name')
}


class Rule:
    def __init__(self, name: str, whitelist: list, blacklist: list, option: Option, serial: int):
        # Define a rule - has a whitelist, blacklist, and an assigned option(function) to whitelisted packets
        self.serial = serial
        self.name = name
        self.whitelist = whitelist
        self.blacklist = blacklist
        self.option = option

    def to_dict(self) -> dict:
        # Re-formats the rule data into a dictionary structure
        return {
            'serial': self.serial,
            'name': self.name,
            'whitelist': self.whitelist,
            'blacklist': self.blacklist,
            'option': {
                'name': self.option.option_name,
                'func': self.option.func_name
            }
        }

    def to_string(self) -> str:
        # reformat the rule to a visual string for visualisation
        return f"Rule name: {self.name}, Serial:{self.serial}"


def from_dict(rule_dict: dict) -> Rule:
    # Loads a rule from the json configuration file and formats the information accordingly, then returns it
    serial = rule_dict['serial']
    name = rule_dict['name']
    whitelist = rule_dict['whitelist']
    blacklist = rule_dict['blacklist']
    option = Option(rule_dict['option']['name'], rule_dict['option']['func'])
    return Rule(name, whitelist, blacklist, option, serial)


def check_domain_ip(domain: str) -> list:
    # returns all ip addresses connected to a domain name via DNS lookup, or an empty list if it is not a real domain
    try:
        ip_addresses = socket.gethostbyname_ex(domain)[2]
        return ip_addresses
    except socket.gaierror:
        return []


def is_valid_domain(domain: str) -> bool:
    # Check if the given string 'domain' can be a valid domain name
    # Check if the given string contains atleast one period and does not start or end with a period
    if "." in domain and not domain.startswith(".") and not domain.endswith("."):
        # Check if the domain name contains only alphanumeric characters(A-Z,a-z,0-9), hyphens(-), and periods(.)
        if re.match(r"^[A-Za-z0-9.-]+$", domain):
            return True
    return False


def validate_ip_addresses(ip_lst: list) -> (list, list):
    # check if a list contains an ip address that is not a valid IPv4 address, or a domain name
    # returns a list of all invalid ips or none if there are none.
    invalid_ips, valid_ips = [], []
    for ip in ip_lst:
        if ip:
            # checks if address is not empty.
            try:
                ipaddress.IPv4Address(ip)
                valid_ips.append(ip)
            except ipaddress.AddressValueError:
                if is_valid_domain(ip):
                    domain_ips = check_domain_ip(ip)
                    valid_ips.extend(domain_ips) if domain_ips else invalid_ips.append(ip)
                else:
                    invalid_ips.append(ip)
    return valid_ips, invalid_ips


def load_rules(config_file: str) -> list:
    # loads all rules from the database {config_file} and returns a list of all rules
    try:
        with open(config_file, 'r') as file:
            rules_data = json.load(file)
            return [from_dict(rule) for rule in rules_data]
    except FileNotFoundError:
        pass
    except json.JSONDecodeError:
        print(f"Error: The file {config_file} contains invalid JSON.")
    return []


def save_rules(rules: list, config_file: str):
    # saves a rule to the configuration file, in a dictionary format.
    # "indent 4" is used for better json file readability
    with open(config_file, 'w') as file:
        json.dump([rule.to_dict() for rule in rules], file, indent=4)


def rule_instructions() -> str:
    # returns the instructions and number of options for adding a new rule to the firewall
    instructions = "Enter rule name: #Enter whitelisted IPs separated by comma: #Enter blacklisted IPs separated by comma: #Enter Option: #"
    for i, option in enumerate(options_dict.values()):
        instructions += option.to_string(i + 1) + "#"
    return instructions[:-1]


class Firewall:
    def __init__(self, config_file: str):
        # Constructor of the firewall, with its defined attributes
        self.config_file = config_file  # database of the server rules
        self.log_file = 'log.txt'  # log file to write information to
        self.rules = load_rules(self.config_file)  # active list of all the rules
        self.bpf_filter = "true"  # bpf filter for the sniffer
        self.stop_event = Event()  # used to sync the sniffer thread with client input (run/stop running)
        self.sniffer_thread = Thread()  # element to serve as the thread for the sniffer to avoid collision between functions

    def firewall_new_rule(self, sock: socket) -> str:
        # Receives a request from the client to add a rule to the firewall.
        # Sends instructions and receives user input to create the rule, then runs a few verifications about the
        # given ip addresses. saves the data provided as a rule in the configuration file and active rules list
        protocol.send_message(rule_instructions(), sock)
        try:
            rule_name, whitelist, blacklist, option = protocol.recv_message(sock).split("#")
            whitelist, blacklist = whitelist.split(","), blacklist.split(",")
        except ValueError:
            return "Error adding rule, received bad input"
        whitelist, invalid_whitelist = validate_ip_addresses(whitelist)
        blacklist, invalid_blacklist = validate_ip_addresses(blacklist)
        invalid_ips = invalid_whitelist + invalid_blacklist
        if invalid_ips:
            return f"Error adding rule, invalid ip addresses provided: {invalid_ips}"
        rule = Rule(rule_name, whitelist, blacklist, options_dict[option], len(self.rules))
        self.rules.append(rule)
        save_rules(self.rules, self.config_file)
        return "Rule successfully added"

    def firewall_show_rules(self, _) -> str:
        # Receives a request from the client to return all rules saved in the database, if there are any rules saved
        # it will return a string of all the saved rules
        if not self.rules:
            return "No rules available"
        else:
            response = f"Rule names and serials: #"
            for rule in self.rules:
                response += rule.to_string() + "#"
            return response[:-1]

    def update_serials(self):
        # Update the serial numbers of all rules to ensure they are sorted in a consecutive sequence
        for index, rule in enumerate(self.rules):
            rule.serial = index
        save_rules(self.rules, self.config_file)

    def firewall_delete_rule(self, sock: socket) -> str:
        # Receives a request from the client to delete one of the saved rules, if there are any rules saved in the
        # database, {rules_config.json}, it will return an instruction and the serial numbers of all the rules.
        # Will wait for user input, which will be a serial number of their choice to delete, after deletion,
        # the database will update and a request to sort the rules will be made by the firewall,
        # success status will be returned to the client
        if len(self.rules) == 0:
            return "No rules to delete"
        msg = "Please choose a serial number:" + "#" + str(len(self.rules))
        protocol.send_message(msg, sock)
        serial = int(protocol.recv_message(sock))
        del self.rules[serial]
        save_rules(self.rules, self.config_file)
        self.update_serials()
        return f"Rule {serial} has been deleted"

    def firewall_choose_bpf(self, sock: socket) -> str:
        # Updates the BPF filter for the packet sniffer
        protocol.send_message("bpf", sock)
        bpf = protocol.recv_message(sock)
        try:
            with pydivert.WinDivert(bpf):
                self.bpf_filter = bpf
                return "BPF filter updated"
        except WindowsError:
            return "Invalid BPF filter input, BPF filter did not update"

    def firewall_download_log(self, sock: socket) -> str:
        # Receives a request from the client to download the contents of the server log file to the client,
        # By first sending the length of the content to the client, then sends the content in increments of chunks,
        # A chunk's size will be set with this formula: 10^n - 1
        # n is the max length of messages the protocol can send
        # Will act accordingly if the log file is empty
        try:
            with open(self.log_file, "r") as file:
                file_size = len(file.read())
                protocol.send_message(str(file_size), sock)
                if file_size > 0:
                    file.seek(0)
                    counter = 0
                    chunk_size = 10*protocol.MSG_MAX_LEN - 1
                    while file_size - counter > chunk_size:
                        chunk = file.read(chunk_size)
                        counter += chunk_size
                        protocol.send_message(chunk, sock)
                    protocol.send_message(file.read(file_size - counter), sock)
                    return "Log file contents transferred successfully"
                return "Log file is empty"
        except FileNotFoundError:
            return "Log file doesnt exist"

    def firewall_delete_log(self, _) -> str:
        # Deletes the contents of the current server log file
        try:
            with open(self.log_file, "w"):
                return "Log file contents successfully deleted"
        except FileNotFoundError:
            return "Log file doesnt exist"

    def blacklist_packet_handler(self, packet: pydivert.Packet):
        # Handler for blacklisted packets, will only be used if blocking a packet is not the goal.
        with open(self.log_file, 'a') as log_file:
            log_file.write(f"Blacklisted IP Packet: {packet.src_addr}\n")

    def neutral_packet_handler(self, packet: pydivert.Packet):
        # Handler for neutral packets (not whitelisted nor blacklisted)
        with open(self.log_file, 'a') as log_file:
            log_file.write(f"Non-Whitelisted IP Packet: {packet.src_addr}\n")

    def whitelist_packet_handler(self, packet: pydivert.Packet, rule: Rule, sock: socket):
        # Handler for whitelisted packets
        ret = getattr(options, rule.option.func_name)(packet)
        response = f"[SNIFFER] Whitelisted packet: {rule.to_string()} Option info:{rule.option.option_name}: {ret}"
        protocol.send_message(response, sock)

    def sniffer_stopper(self, _) -> bool:
        # Determines whether the packet sniffer should stop based on the status of stop_event.
        return self.stop_event.is_set()

    def sniffer(self, sock: socket):
        # Sniffer function, contains packet_handler as a closure function to retain the sock parameter received.
        # The sock parameter might be used in some situations where the sniffer would want to send the client an alert
        # about an event, for example when a whitelisted packet is received, or when malicious activities are detected
        with pydivert.WinDivert(self.bpf_filter, layer=0) as w:
            # sniffs packets and examinates them
            for packet in w:
                try:
                    if self.stop_event.is_set():
                        break
                    for rule in self.rules:
                        if str(packet.src_addr) in rule.blacklist or str(packet.dst_addr) in rule.blacklist:
                            # Checks if a rule is blacklisted
                            self.blacklist_packet_handler(packet)
                            break
                        elif str(packet.src_addr) in rule.whitelist or str(packet.dst_addr) in rule.whitelist:
                            # Checks if a rule is whitelisted
                            self.whitelist_packet_handler(packet, rule, sock)
                            w.send(packet)
                            break
                    else:
                        # Will log all non blacklisted/whitelisted packets
                        w.send(packet)
                except Exception as e:
                    print(f"[SERVER] Packet Error: {e}")

    def firewall_start_sniffer(self, sock: socket) -> str:
        # Clears the stop_event value, incase it has been set. then creates and start a thread for packet sniffer
        self.stop_event.clear()
        self.sniffer_thread = Thread(target=self.sniffer, args=(sock,))
        self.sniffer_thread.start()
        return "Sniffer started"

    def firewall_stop_sniffer(self, _) -> str:
        # Stop the sniffer by setting stop_event, to indicate the sniffer should be stopped,
        # Then the program waits for the thread to finish and stop before returning status to client
        try:
            if self.sniffer_thread.is_alive():
                self.stop_event.set()
                self.sniffer_thread.join()
                return "Sniffer stopped"
        except Exception as e:
            print(e)
            pass
        return "Sniffer is not running"

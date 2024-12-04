'''
--------------------------------------------------------------------------------
Class:          ECE 5590 Computer Netwroks
Author:         Lino Mercado-Esquivias

Description:    My terminal-based version of wireshark.
--------------------------------------------------------------------------------
'''

# modules
import re
import os
import glob
import signal
import platform
import subprocess
from colors import *
from typing import List
from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
from textual import events
from textual.widgets import DataTable
from textual.app import App, ComposeResult

# global variables
global_packets = []

def main():
    # clear terminal
    clear_terminal = set_clear_command()
    os.system(clear_terminal)

    # poll git
    current_directory = os.getcwd()
    if current_directory.endswith("ECE5590_Final_Project"):
        git_details =poll_git()
        version = git_details[0]
        date_modified = git_details[1]
    else:
        print("Could not poll git details. Please change directory to the appropriate git directory.")
        version = "unknown"
        date_modified = "unknown"
    # main menu
    while True:
        print(f"Welcome to Wirefish {version} ({date_modified} realease). Select an option from below.")
        print("1.    Capture mode")
        print("2.    Trigger mode")
        print("q     Exit program")
        user_response = input("Please enter your selection: ").strip()
        if user_response == '1':
            os.system(clear_terminal)
            while True:
                app = capture_mode()
                row = app.run()
                if not row:
                    row = 0
                os.system(clear_terminal)
                print_packet_info(global_packets[row])
                input()
        elif user_response == '2':
            os.system(clear_terminal)
            trigger_mode() 
            os.system(clear_terminal)
        elif user_response == 'q':
            os.system(clear_terminal)
            print("Wirefish program ended.")
            exit(0)
        else:
            os.system(clear_terminal)

# set command to clear the terminal depending on the operating system
def set_clear_command():
    if platform.system() == "Windows":
        return "cls"
    else:
        return "clear"

# poll git details
def poll_git() -> List:
    date_created = "2024-11-07"
    try:
        command = ["git", "log", "-1", "--format=%ad", "--date=short"]
        date_modified = subprocess.check_output(command, text=True).strip()
    except subprocess.CalledProcessError:
        date_modified = "unknown"
    try:
        command = ["git", "describe", "--tags"]
        version = subprocess.check_output(command, text=True).strip()
    except subprocess.CalledProcessError:
        version = "unknown"
    return version, date_modified, date_created

def extract_packet_info(packet, start_time=None):
    # calculate elapsed time
    if start_time is None:
        elapsed_time = 0.0
    else:
        elapsed_time = packet.time - start_time

    # extract required fields
    time_str = f"{elapsed_time:.6f}"
    src_ip = packet[0][1].src if packet.haslayer("IP") else "N/A"
    dst_ip = packet[0][1].dst if packet.haslayer("IP") else "N/A"
    protocol = packet[0][1].proto if packet.haslayer("IP") else "N/A"
    length = len(packet)
    info = packet.summary()

    return time_str, src_ip, dst_ip, protocol, length, info

# capture packets and display them
class capture_mode(App):
    def __init__(self):
        super().__init__()
        self.packets = []  # To store captured packets
        self.viewing_details = False

    def compose(self) -> ComposeResult:
        # create table
        table = DataTable()
        table.add_columns("Elapsed Time", "Source", "Destination", "Protocol", "Length", "Info")
        table.cursor_type = "row"   
        table.frozen_rows = 1       
        yield table

    def on_mount(self) -> None:
        self.capture_packets()
    
    # def on_unmount(self) -> None:
    #     print("Exiting table")

    def capture_packets(self) -> None:
        global global_packets
        if global_packets == []:
            global_packets = sniff(count=25)
        # packets = sniff(count=25)  
        start_time = global_packets[0].time if global_packets else 0
        table = self.query_one(DataTable)

        for packet in global_packets:
            packet_info = extract_packet_info(packet, start_time)
            table.add_row(*map(str, packet_info))  
    
    def on_key(self, event: events.Key) -> None:
        table = self.query_one(DataTable)
        # check if enter key was pressed
        if event.key == "enter":
            # get selected row index
            selected_row = table.cursor_row
            self.exit(selected_row)


def print_packet_info(packet):
    # Layer 3 - Network Layer (IP)
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        print("Layer 3 - IP Header:")
        print(f"  Source IP: {ip_layer.src}")
        print(f"  Destination IP: {ip_layer.dst}")
        print(f"  Protocol: {ip_layer.proto}")
        print()

    # Layer 4 - Transport Layer (TCP or UDP)
    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        print("Layer 4 - TCP Header:")
        print(f"  Source Port: {tcp_layer.sport}")
        print(f"  Destination Port: {tcp_layer.dport}")
        print(f"  Flags: {tcp_layer.flags}")
        print()
    elif packet.haslayer(UDP):
        udp_layer = packet[UDP]
        print("Layer 4 - UDP Header:")
        print(f"  Source Port: {udp_layer.sport}")
        print(f"  Destination Port: {udp_layer.dport}")
        print()
    
    # Layer 5 - Application Layer (For example, HTTP or DNS)
    if packet.haslayer(TCP):
        # Check if HTTP is present in the payload (port 80)
        if packet[TCP].dport == 80 or packet[TCP].sport == 80:
            print("Layer 5 - Application Layer (HTTP):")
            print(f"  Payload: {packet[TCP].payload}")
            print()

# silently listen and alert user of trigger
def trigger_mode():
    pass

# handle kill signal by exiting gracefully
def kill_signal_handler(signal_number, frame):
    clear_terminal = set_clear_command()
    os.system(clear_terminal)
    print("Wirefish program ended.")
    exit(0)

signal.signal(signal.SIGINT, kill_signal_handler)

if __name__ == "__main__":
    main()
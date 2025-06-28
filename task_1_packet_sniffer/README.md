# Python Packet Sniffer

## What it Does

This is a very basic Python script that listens to your network connection and prints out information about the data packets it sees. It shows things like:

*   Where the data came from (Source IP address and Port)
*   Where it's going (Destination IP address and Port)
*   What type of data it is (Protocol like TCP, UDP, ICMP)

It uses a Python library called `scapy` to do the network listening.

## Setup

1.  **Install Python:** Make sure you have Python 3 installed on your computer.
2.  **Install Scapy:** Open your terminal or command prompt and type:
    ```bash
    pip install scapy
    ```
3.  **Platform Needs:**
    *   **Linux/Mac:** You need to run the script with `sudo` because listening to network traffic requires special permissions.
    *   **Windows:** You need to install **Npcap** ([download here](https://npcap.com/)). Make sure you run the script by opening your Command Prompt **as Administrator**.

## How to Run

1.  Save the script as `packet_sniffer.py`.
2.  Open your terminal or command prompt.
3.  Navigate to the directory where you saved the file.
4.  Run the script:
    *   **On Linux/Mac:**
        ```bash
        sudo python3 packet_sniffer.py
        ```
    *   **On Windows (as Administrator):**
        ```cmd
        python packet_sniffer.py
        ```
5.  The script will start printing packet information.
6.  Press `Ctrl + C` to stop the script.

## Understanding the Output

Each line shows one packet:

```
[Timestamp] SourceIP:SourcePort -> DestinationIP:DestinationPort Protocol: ProtocolName
```

*   `[Timestamp]`: When the packet was seen.
*   `SourceIP:SourcePort`: The computer and application sending the data.
*   `DestinationIP:DestinationPort`: The computer and application receiving the data.
*   `ProtocolName`: The type of network conversation (e.g., TCP for web browsing, UDP for streaming/DNS).

(A `*` for the port means the protocol doesn't use ports, like ICMP which is used for ping.)

See the `sample_output.txt` file for an example.

## Troubleshooting (Windows)

If you get an "Interface not found" error on Windows:

*   Make sure Npcap is installed correctly.
*   Make sure you are running the Command Prompt as Administrator.
*   Try restarting your computer after installing Npcap.


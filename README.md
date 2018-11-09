# pcap-analyser

A)Wireshark Programming: Extract all the information from network bytes received based on TCP header and data part. Compute throughput, loss rate and average RTT for the pcap captured.

B)Congestion control: Estimation of initial congestion window size and look at it's variation. Extract retransmissions and segregate them in two parts: Due to triple duplicate acks and timeout.

C)HTTP Analysis: Reassemble each unique HTTP Request/Response and identify which HTTP protocol is being used for each PCAP collected file. Perform comparitive analysis on the basis of load speed and bytes sent out to network.

Analyzed a Wireshark/TCPdump trace to characterize the TCP flows in the trace and also figured out the HTTP Versions, congestion window sizes and packet losses

Part A

Run the program - python analysis_pcap_tcp_A.py

Part B

Run the program - python analysis_pcap_tcp_B.py

Part C

Command to run tcpdump:

sudo tcpdump -i en0 -n port 1080 -w http_1080.pcap

sudo tcpdump -i en0 -n port 1081 -w tcp_1081.pcap

sudo tcpdump -i en0 -n port 1082 -w tcp_1082.pcap


Run the program - python analysis_pcap_http.py

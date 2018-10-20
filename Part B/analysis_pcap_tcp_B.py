import struct
import dpkt

def getField(buffer,f,position,field_size):
    if(len(buffer)>position):
        return str(struct.unpack(f,buffer[position:position+field_size])[0])
    else:
        pass

#check if a connection is established
def syn_ack_acknowledge(p):
    if p.syn == "1" and p.ack == "1":
        return True
    return False

#check if it is the requested tcp connection
def req_tcp_connection(p,source_ip,destination_ip):
    if p.source_ip == source_ip and p.destination_ip == destination_ip:
        return True
    return False

#check if it is the requested source and destination ports
def req_source_dest_ports(p1,p2):
    if p1.source_port == p2.destination_port and p2.source_port == p1.destination_port:
        return True
    if p1.source_port == p2.source_port and p2.destination_port == p1.destination_port:
        return True
    return False

class TCP_Packet:
    valid = True
    timestamp = 0
    source_ip = destination_ip = source_port = destination_port = sequence_number = ack_number = syn = ack = header_size = window_size = size = mss = ""
    
    def parse(P,timestamp,buffer):
        try:
            #parse source and destination address from ip header
            x,y = 26,30
            while x<29:
                P.source_ip = P.source_ip + getField(buffer,">B",x,1) + "."
                P.destination_ip = P.destination_ip + getField(buffer,">B",y,1) + "."
                x=x+1
                y=y+1
            P.source_ip = P.source_ip +getField(buffer,">B",x,1)
            P.destination_ip =P.destination_ip + getField(buffer,">B",y,1)
            
            #prase remaining data from the tcp packet
            #parse source and destination ports
            P.source_port = getField(buffer,">H",34,2)
            P.destination_port = getField(buffer,">H",36,2)
            
            #parse sequence and acknowledgement numbers
            P.sequence_number = getField(buffer,">I",38,4)
            P.ack_number = getField(buffer,">I",42,4)
            
            #parse header size and ack and syn
            P.header_size = getField(buffer,">B",46,1)
            P.ack = "{0:16b}".format(int(getField(buffer,">H",46,2)))[11]
            P.syn = "{0:16b}".format(int(getField(buffer,">H",46,2)))[14]
            
            #parse window size, max segment size, size and timestamp
            P.window_size = getField(buffer,">H",48,2)
            P.mss = getField(buffer,">H",56, 2)
            P.size = len(buffer)
            P.timestamp = timestamp
        except:
            P.valid = False

class Connection:
    packets=[]
    source_port= destination_port= ""
    def __init__(P,source,destination):
        P.source_port=source
        P.destination_port=destination

def Loss(connection):
    loss = triple_acknowledgement_loss = 0
    sequence_dict = {}
    ack_dict = {}

    for p in connection.packets:
        if req_tcp_connection(p,"130.245.145.12","128.208.2.198"):
            sequence_dict[p.sequence_number] = sequence_dict.get(p.sequence_number,0) + 1
        
        if req_tcp_connection(p,"128.208.2.198","130.245.145.12"):
            ack_dict[p.ack_number] = ack_dict.get(p.ack_number,0) + 1

    for key,value in sequence_dict.items():
        if (key in ack_dict) and (ack_dict[key] > 2):
            triple_acknowledgement_loss += sequence_dict[key]-1
        elif key in sequence_dict:
            loss += sequence_dict[key]-1

    print ("Triple Acknowledgement Loss = %s "%str(triple_acknowledgement_loss))
    print ("Timeout Loss = %s"%str(loss))


def congestionWindow(connection):
    congestion_windows = []
    first_packet = True
    first_packet_timestamp = last_packet_timestamp = 0
    seq_number = 0
    i = 0
    count = 0
    c = 0
    for p in connection.packets:
        c += 1
        if i > 11:
            break
        if req_tcp_connection(p,"130.245.145.12","128.208.2.198"):
            count = count + 1
            if first_packet:
                first_packet_timestamp = p.timestamp
                first_packet = False
                seq_number = int(p.sequence_number)
            elif (p.timestamp-first_packet_timestamp)>(0.073):
                if i!=0:
                    print ("Congestion Window = %s "%(count*1460))
                count = 0
                first_packet = True
                i += 1
    print("\n")

if __name__=='__main__':
    packets = []
    connections = []
    tcp_connection_count = 0
    for timestamp,buffer in dpkt.pcap.Reader(open('assignment2.pcap', 'rb')):
        p = TCP_Packet()
        p.parse(timestamp,buffer)
        if p.valid:
            packets.append(p)
            if syn_ack_acknowledge(p):
                tcp_connection_count += 1
                connection = Connection(p.source_port, p.destination_port)
                connection.packets = []
                connections.append(connection)

    for p in packets:
        for connection in range(0,len(connections),1):
            if req_source_dest_ports(p,connections[connection]):
                connections[connection].packets.append(p)

    k=1
    print ("\nTcp connection count = %s \n"%tcp_connection_count)
    for connection in connections:
        print ("\nConnection %s" %k)
        print ("--------------------------------------------------------------")
        Loss(connection)
        congestionWindow(connection)
        k = k + 1

from collections import defaultdict
import struct
import dpkt

def getField(buffer,f,position,field_size):
    if(len(buffer)>position):
        return str(struct.unpack(f,buffer[position:position+field_size])[0])
    else:
        pass

#check if a connection is established
def http_acknowledge(p):
    if p.syn == "1" and p.ack == "1":
        return True
    return False

class Packet:
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
            if(P.size > 66):
                #print (P.size)
                P.request = str(getField(buffer,">s",66,1))+str(getField(buffer,">s",67,1)) + str(getField(buffer,">s",68,1))
                #print (P.request)
                P.response = str(getField(buffer,">s",66,1))+str(getField(buffer,">s",67,1)) + str(getField(buffer,">s",68,1))+str(getField(buffer,">s",69,1))
                #print (P.response)
            
        except:
            P.valid = False

if __name__=='__main__':
    files = ['http_1080.pcap','tcp_1081.pcap','tcp_1082.pcap']
    print("\n\n")
    for f in files:
        print ("File - %s" %f)
        print ("--------------------------------------------------------------")
        packets = []
        connections = []
        tcp_connection_count = packet_count = total_payload = 0

        for timestamp,buffer in dpkt.pcap.Reader(open(f,'rb')):
            p = Packet()
            p.parse(timestamp,buffer)
            if p.valid:
                packets.append(p)
                packet_count += 1
                total_payload += p.size
                if http_acknowledge(p):
                    tcp_connection_count += 1
                    #print ("MSS : %s" %p.mss)

        print ("Tcp connection count = %s"%tcp_connection_count)
        print ("Time Taken = %s"%str(packets[len(packets)-1].timestamp-packets[0].timestamp))
        print ("Packet Count = %s"%str(packet_count))
        print ("Raw data size = %s \n"%str(total_payload))
    
        req_dictionary = defaultdict(list)
        response_dictionary = defaultdict(list)
 
        for packet in packets:
            if(packet.size > 66):
                str1 = "b'G'b'E'b'T'"
                str2 = "b'H'b'T'b'T'b'P'"
                i=0
                if packet.request == str1:
                    x = packet.source_ip
                    if packet.source_port not in req_dictionary:
                        req_dictionary[packet.source_port].append((packet.source_ip,packet.destination_ip,packet.sequence_number,packet.ack_number))
                if packet.response == str2 and packet.destination_ip == x:
                    dict = []
                    dict += ((packet.source_ip,packet.destination_ip,packet.sequence_number,packet.ack_number))
                response_dictionary[packet.destination_port].append(dict)
                    
        req_set = set(req_dictionary)
        resp_set = set(response_dictionary)

        for key in req_set.intersection(resp_set):
            print ("HTTP REQUEST %s " %str(req_dictionary[key]))
            print ("Response: ")
            for value in response_dictionary[key]:
                print (value)
            print ("\n")

        print ("\n")

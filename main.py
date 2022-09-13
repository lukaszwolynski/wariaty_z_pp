import socket
import textwrap
import struct
import binascii
import sys

# Format MAC Address
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr

#DONE
# Unpack IPv4 Packets Recieved
#https://en.wikipedia.org/wiki/IPv4#Packet_structure
def ipv4_Packet(data):
    version = 4 
    ihl = 20 #(version_header_len & 15) * 4 # this always return 20
    ttl, proto, source_ip, dest_ip = struct.unpack('! 8x B B 2x 4s 4s', data[:20])  # 8x means we dont need it (version, ihl, dscp) 
    #B      B     4s         4s
    return version, ihl, ttl, proto, ipv4(source_ip), ipv4(dest_ip), data[ihl:]

# Returns Formatted IP Address
def ipv4(addr):
    return '.'.join(map(str, addr))

#DONE
def udp_seg(data):
    #https://www.tutorialspoint.com/data_communication_computer_network/images/UDP_Header.jpg
    src_port, dest_port, length   = struct.unpack('! H H H', data[:6]) #deleted 2x from here
    return src_port, dest_port, length, data[6:]

#DONE
def icmp_packet(data):
    # https://www.tutorialspoint.com/what-is-icmp-protocol
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]


def printPackets(data, raw_data):
    # PROTOCOL NUMBERS: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xml

    version, header_length, ttl, protocol, src, target, data = ipv4_Packet(data)

    # ICMP
    if protocol == 1:
        type, code, checksum, data = icmp_packet(data)
        printType("ICMP")
        print (f"ICMP type: {type}")
        print (f"ICMP code: {code}")
        print (f"ICMP checksum: {checksum}")

    #list of ICMP types: https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml

    # TCP
    # https://www.gatevidyalay.com/wp-content/uploads/2018/09/TCP-Header-Format.png
    elif protocol == 6:
        printType("TCP")
        print(f'Version: {version}\t Header Length: {header_length}\t TTL: {ttl}')
        print(f'protocol: TCP \t Source: {src} \t Target: {target}')
        src_port, dest_port, sequence, acknowledgment, useless_and_flags = struct.unpack( '! H H L L H', raw_data[:14]) 

        useless_and_flags = bin(useless_and_flags) 
        flags = useless_and_flags[-6:]
        flag_urg = flags[0]
        flag_ack = flags[1]
        flag_psh = flags[2]
        flag_rst = flags[3]
        flag_syn = flags[4]
        flag_fin = flags[5]
        data = raw_data[14:] 
        print(f"Source Port: {src_port} \t Destination Port: {dest_port}")
        print(f"Sequence: {sequence} \t Acknowledgment: {acknowledgment}")
        
        printType("Flags", 4)
        print(f"URG {flag_urg} \t ACK {flag_ack} \t PSH {flag_psh}")
        print(f"RST {flag_rst} \t SYN {flag_syn} \t FIN {flag_fin}")

    # UDP
    elif protocol == 17:
        printType("UDP")
        print(f'Version: {version} \t Header Length: {header_length} \t TTL: {ttl}')
        print(f'protocol: UDP \t Source: {src} \t Target: {target}')
       
        src_port, dest_port, length, data = udp_seg(data)
        print(f'Source Port: {src_port} \t Destination Port: {dest_port} \t Length: {length}')


#https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/dd197515(v=ws.10)?redirectedfrom=MSDN

#DONE
def printType(type, lenght=10):
    print("*" * lenght + " " + type  + " " + "*" * lenght )

# Unpack Ethernet Frame
#DONE
def ethernet_frame(data):
    #struct.unpack - https://docs.python.org/3/library/struct.html
    # https://upload.wikimedia.org/wikipedia/commons/thumb/1/13/Ethernet_Type_II_Frame_format.svg/700px-Ethernet_Type_II_Frame_format.svg.png

    proto = ""
    IpHeader = struct.unpack("!6s6sH",data[0:14])  # example return (b'\x06y\xfaUG.', b'\x06k\xd5;\xc7,', 2048)
    dstMac = binascii.hexlify(IpHeader[0]) # binary -> hex
    srcMac = binascii.hexlify(IpHeader[1]) # binary -> hex 
    protoType = IpHeader[2]  #2048
    nextProto = hex(protoType) # int to hex
    
    #https://en.wikipedia.org/wiki/EtherType#Values
    if (nextProto == '0x800'): 
        proto = 'IPV4'

    return dstMac, srcMac, proto, data[14:]

def main():
    packet = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(3)) # ntohs(3) means "capture all packets"
    while True:
        bytes, address = packet.recvfrom(65536) # max buffsize
        dest_mac, src_mac, eth_proto, data = ethernet_frame(bytes)

        printPackets(data, bytes)
        #example of  dest_mac, src_mac, eth_proto - b'066bd53bc72c' b'0679fa55472e' IPV4
        #b' - bytes string

main()
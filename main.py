import pyshark
import subprocess
import re
from elevate import elevate

class Firewall:

    def __init__(self):
        self.port = -1
        self.dport = -1
        self.protocol = ''
        self.src_ip = ''
        self.dst_ip = ''

    def getProtocol(self,packet):
        try:
            return packet.ip.proto.int_value
        except:
            return -1
    
    def getProtocolName(self,value):
        table = {
            1 : 'icmp',
            6 : 'tcp',
            17: 'udp'
        }
        try:
            return table[value].lower()
        except:
            return 'None'

    def getProtocolProperties(self,packet,proto):
        if proto == 'icmp':
            return packet.icmp
        elif proto == 'tcp':
            return packet.tcp
        elif proto == 'udp':
            return packet.udp
        else:
            return None

    def getPort(self,head):
        try:
            a = int(head.port)
            b = int(head.srcport)
            c = int(head.dstport)

            if a == b:
                return a,c
            elif a == c:
                return c,b
            return a,b
            
        except:
            return -1,-1
    
    def getIP(self,packet):
        try:
            return packet.ip.src,packet.ip.dst
        except:
            return 'None','None'

    def checkPacket(self,packet):
        self.src_ip,self.dst_ip = self.getIP(packet)
        val = self.getProtocol(packet)
        self.protocol = self.getProtocolName(val)
        if self.protocol == 'None':
            return 
        proto = self.getProtocolProperties(packet,self.protocol)
        self.port,self.dport = self.getPort(proto)
        

def handlePacket(packet):
    
    firewall = Firewall()
    firewall.checkPacket(packet)

    global j

    k = 0

    ty = 'in'
    
    if firewall.src_ip == '192.168.0.104':
        ty = 'out'
        

    for i in rules:    
        if ((firewall.protocol == i['protocol'] and firewall.protocol != 'None') \
        or (firewall.src_ip == i['srcip'] and firewall.src_ip != 'None')\
        or (firewall.dst_ip == i['dstip'] and firewall.dst_ip != 'None')) and i['type'] == ty:
            

            print('Packet with ip',firewall.src_ip,'is blocked')
            
            string = 'netsh advfirewall firewall add rule name=\"block ' + str(j) + '\" dir=' + str(ty)
            
            if firewall.protocol == i['protocol'] and firewall.protocol != 'None':
                string += ' protocol=' + firewall.protocol
            
            if firewall.src_ip == i['srcip'] and firewall.src_ip != 'None':
                string += ' remoteip=' + firewall.src_ip
            
            if firewall.dst_ip == i['dstip'] and firewall.dst_ip != 'None':
                string += ' localip=' + firewall.dst_ip
            
            if firewall.port == i['hostport'] and i['hostport'] != -1:
                string += ' localport=' + firewall.port
            
            if firewall.dport == i['otherport'] and i['otherport'] != -1:
                string += ' remoteport=' + firewall.dport
            
            string += ' action=block'
            
            if count[k] == 0 and string != 'netsh advfirewall firewall add rule name=\"block ' + str(j) + '\"':
                subprocess.getoutput(string)
                print('\n')
                print('Rule name \" Block',j,'\" is implemented')
                print('\n')
                j = j + 1            
                count[k] = -1
        k = k + 1
        
                        
                
def checkIP(ip):
    regex = '''^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
			25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
			25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
			25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)'''
    
    if re.search(regex, ip) :
        return True
    else:
        return False
    


def main():

    global rules,count,j

    elevate()

    val = int(input('Enter the number of rules(for blocking):'))

    rules = []
    count = []
    j = 0

    try:

        for i in range(val):

            d = {}
            print('\nRule',str(i + 1),':\n')

            d['type'] = str(input('Direction (Incoming/Outgoing):')).lower()
            
            if d['type'] == 'incoming':
                d['type'] = 'in'
            elif d['type'] == 'outgoing':
                d['type'] = 'out'
            else:
                d['type'] = ''

            d['protocol'] = str(input('Protocol(TCP,UDP,ICMP,None):')).lower()
            
            d['srcip'] = input('Source IP(IP,None):')
            
            while(checkIP(d['srcip']) == False and d['srcip'] != 'None'):
                d['srcip'] = input('Source IP(IP,None):')
            
            d['dstip'] = input('Destination IP(IP,None):')

            while(checkIP(d['dstip']) == False and d['dstip'] != 'None'):
                d['dstip'] = input('Destination IP(IP,None):')

            

            if d['protocol'] == 'None':
                d['hostport'] = -1
                d['otherport'] = -1
            else:        
                x = input('Host Port(port_num,None):')
                if(x == 'None'):
                    d['hostport'] = -1
                else:
                    d['hostport'] = int(x)
                
                x = input('Remote Port(port_num,None):')
                if(x == 'None'):
                    d['otherport'] = -1
                else:
                    d['otherport'] = int(x)

            rules.append(d)
            count.append(0)
    except:
        print('Rule entering error')
        print('Program terminated.......')
        

    try:
        capture = pyshark.LiveCapture(interface = 'Wi-Fi')
        capture.apply_on_packets(handlePacket, timeout = 30)
    except:
        pass

    
    print('\n\n')
    for i in range(j):        
        string = 'netsh advfirewall firewall delete rule name=\"block ' + str(i) + '\"'
        subprocess.getoutput(string)
        print('Rule name \" Block',j,'\" is deleted \n\n')

if __name__ == '__main__':
    main()
    print('\n\nDone...')
    input()
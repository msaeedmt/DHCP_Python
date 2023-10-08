import socket
from AllocatedIP import AllocatedIP
import dhcppython
import ipaddress
import json
import random
from time import sleep
import threading
from Utils import *

MAX_BYTES = 1024

serverPort = 4000
clientPort = 4001

DHCPDISCOVER = 1
DHCPOFFER = 2
DHCPREQUEST = 3
DHCPDECLINE = 4
DHCPACK = 5
DHCPNACK = 6


class DHCP_server(object):
    def __init__(self, serverAddress):
        self.serverAddress = serverAddress
        self.allocatedIPs = []
        self.reservedIPs = {}
        self.blockedMacAddresses = []
        self.lease = 0
        self.firstIpAddress = None
        self.lastIPAddress = None
        self.setConfigs()
        self.threads = []
        self.DHCPPackets = {}

        self.makeRandomIP()

    def server(self):
        print("DHCP server is starting...\n")

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('', serverPort))
        dest = ('255.255.255.255', clientPort)

        lock = threading.Lock()
        leasesDecreaseThread = threading.Thread(target=self.countdownLeaseTimes, args=(lock,))
        leasesDecreaseThread.start()

        getInstruction = threading.Thread(target=self.showClients)
        getInstruction.start()

        while 1:
            try:
                data, address = s.recvfrom(MAX_BYTES)
                if int.from_bytes(dhcppython.packet.DHCPPacket.from_bytes(data).options[0].data,
                                  'little') == DHCPDISCOVER:
                    newOffer = threading.Thread(target=self.DHCPOffer, args=(s, dest, data))
                    newOffer.start()
                    self.threads.append(newOffer)
                elif int.from_bytes(dhcppython.packet.DHCPPacket.from_bytes(data).options[0].data,
                                    'little') == DHCPREQUEST:
                    newAck = threading.Thread(target=self.DHCPAck, args=(s, dest, data, lock))
                    newAck.start()
                    self.threads.append(newAck)
            except:
                for thread in self.threads:
                    thread.join()
                getInstruction.join()

    def DHCPOffer(self, s, dest, data):
        discoveryPacket = dhcppython.packet.DHCPPacket.from_bytes(data)
        clientMacAddress = discoveryPacket.chaddr

        newIPAddress = self.selectNewIP(clientMacAddress)

        print("Send DHCP offer.")
        xid = self.generateRandomXid()
        if clientMacAddress in self.blockedMacAddresses:
            declinePacket = self.sendPacket(clientMacAddress,
                                            XID=str(ipaddress.IPv4Address(xid)),
                                            yiaddr=str(newIPAddress), type=DHCPDECLINE,
                                            lease=str(ipaddress.IPv4Address(self.lease)))
            s.sendto(declinePacket, dest)
        else:
            offerPacket = self.sendPacket(clientMacAddress,
                                          XID=str(ipaddress.IPv4Address(xid)),
                                          yiaddr=str(newIPAddress), type=DHCPOFFER,
                                          lease=str(ipaddress.IPv4Address(self.lease)))

            self.DHCPPackets[xid] = str(newIPAddress)

            s.sendto(offerPacket, dest)

    def DHCPAck(self, s, dest, data, lock):
        print("Receive DHCP request.")

        requestPacket = dhcppython.packet.DHCPPacket.from_bytes(data)
        xid = requestPacket.xid
        clientMacAddress = requestPacket.chaddr
        offeredIP = self.DHCPPackets[xid]

        isOfferedIPAllocated = False
        for allocatedIP in self.allocatedIPs:
            if allocatedIP.IP == offeredIP:
                isOfferedIPAllocated = True

        if isOfferedIPAllocated:
            nackPacket = self.sendPacket(clientMacAddress,
                                         XID=str(ipaddress.IPv4Address(xid)),
                                         yiaddr=str(offeredIP), type=DHCPNACK,
                                         lease=str(ipaddress.IPv4Address(self.lease)))
            s.sendto(nackPacket, dest)
        else:
            print("Send DHCP pack.\n")
            ackPacket = self.sendPacket(clientMacAddress,
                                        XID=str(ipaddress.IPv4Address(xid)),
                                        yiaddr=str(offeredIP), type=DHCPACK,
                                        lease=str(ipaddress.IPv4Address(self.lease)))

            s.sendto(ackPacket, dest)

            lock.acquire()
            self.allocatedIPs.append(AllocatedIP(offeredIP, clientMacAddress, self.lease))
            lock.release()

    def countdownLeaseTimes(self, lock):
        while 1:
            sleep(1)
            lock.acquire()
            for allocatedIP in self.allocatedIPs:
                allocatedIP.decreaseRemainingLeaseTime()
                if allocatedIP.remainingLeaseTime == 0:
                    self.allocatedIPs.remove(allocatedIP)
            lock.release()

    def setConfigs(self):
        configFile = open('configs.json', )
        configs = json.load(configFile)

        self.lease = int(configs['lease_time'])
        poolMode = configs['pool_mode']
        if poolMode == 'range':
            self.firstIpAddress = configs['range']['from']
            self.lastIPAddress = configs['range']['to']
        elif poolMode == 'subnet':
            self.firstIpAddress = ipaddress.IPv4Address(configs['subnet']['ip_block']) + 1
            self.lastIPAddress = ipaddress.IPv4Address(
                int(self.firstIpAddress) + int(ipaddress.IPv4Address('255.255.255.255')) - int(
                    ipaddress.IPv4Address(configs['subnet']['subnet_mask'])))

        self.reservedIPs = configs['reservation_list']
        self.blockedMacAddresses = configs['black_list']
        print("Server IP : {}".format(self.serverAddress))
        print("Initial Ip Pool : from {} - to {}".format(self.firstIpAddress,self.lastIPAddress))
        print("Reserved IP list : {}".format(self.reservedIPs))
        print("Blocked IP list : {}".format(self.blockedMacAddresses))

    def makeRandomIP(self):
        randomIp = random.randint(int(ipaddress.IPv4Address(self.firstIpAddress)),
                                  int(ipaddress.IPv4Address(self.lastIPAddress)))

        while str(ipaddress.IPv4Address(randomIp)) in self.reservedIPs.values():
            randomIp = random.randint(int(ipaddress.IPv4Address(self.firstIpAddress)),
                                      int(ipaddress.IPv4Address(self.lastIPAddress)))
        return ipaddress.IPv4Address(randomIp)

    def selectNewIP(self, clientMacAddress):

        for allocatedIP in self.allocatedIPs:
            if allocatedIP.macAddress == clientMacAddress:
                selectedIP = allocatedIP.IP
                self.allocatedIPs.remove(allocatedIP)
                return selectedIP

        if clientMacAddress in self.reservedIPs.keys():
            return self.reservedIPs[clientMacAddress]

        randomIP = self.makeRandomIP()
        isIPNew = False

        while not isIPNew:
            isRepeated = False
            for allocatedIP in self.allocatedIPs:
                if allocatedIP.IP == randomIP:
                    isRepeated = True
                    break

            if not isRepeated:
                isIPNew = True
                break

            randomIP = self.makeRandomIP()

        return randomIP

    def generateRandomXid(self):
        randomXid = random.randint(1, pow(2, 32) - 1)
        while randomXid in self.DHCPPackets.keys():
            randomXid = random.randint(1, (2 ^ 32) - 1)
        return randomXid

    def printAllocatedIPs(self):
        if len(self.allocatedIPs) == 0:
            print("There is No Allocated IP!")
        else:
            for allocatedIP in self.allocatedIPs:
                allocatedIP.printDetails()

    def showClients(self):
        order = input()
        while 1:
            if order == "show":
                self.printAllocatedIPs()
            else:
                print("No instruction found!")
            order = input()

    def sendPacket(self, clientMacAddress, XID, yiaddr, type, lease):

        OP = bytes([0x02])
        HTYPE = bytes([0x01])
        HLEN = bytes([0x06])
        HOPS = bytes([0x00])
        XID = bytes(convertIPToHexArray(XID))
        SECS = bytes([0x00, 0x00])
        FLAGS = bytes([0x80, 0x00])
        CIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        YIADDR = bytes(convertIPToHexArray(yiaddr))
        SIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        GIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        CHADDR = bytes(convertMacAdressToHexArray(clientMacAddress))
        SNAME = bytes(64)
        FILE = bytes(128)
        Magiccookie = bytes([0x63, 0x82, 0x53, 0x63])
        DHCPOptions1 = bytes([53, 1, type])  # DHCP Type
        DHCPOptions2 = bytes([51, 4] + convertIPToHexArray(lease))
        DHCPOptions3 = bytes([54, 4] + convertIPToHexArray(self.serverAddress))
        DHCPOptions4 = bytes([255, 0, 0])

        package = OP + HTYPE + HLEN + HOPS + XID + SECS + FLAGS + CIADDR + YIADDR + SIADDR + GIADDR + CHADDR + SNAME + FILE + Magiccookie + DHCPOptions1 + DHCPOptions2 + DHCPOptions3 + DHCPOptions4

        return package


if __name__ == '__main__':
    serverAddress = '192.168.2.1'
    dhcp_server = DHCP_server(serverAddress)
    dhcp_server.server()

import socket, sys
import dhcppython
import ipaddress
import time
import random
from Utils import *
from termcolor import colored

MAX_BYTES = 1024

serverPort = 4000
clientPort = 4001

DHCPDISCOVER = 1
DHCPOFFER = 2
DHCPREQUEST = 3
DHCPDECLINE = 4
DHCPACK = 5
DHCPNACK = 6


class DHCP_client(object):
    def __init__(self):
        self.backoffCutoff = 120
        self.initialInterval = 10
        self.ackTimeout = 20
        self.IP = '0.0.0.0'
        self.hasIP = False
        self.macAddress = 'DE:AD:BE:EF:C0:DE'

    def client(self):
        print("DHCP client is starting...\n")
        dest = ('<broadcast>', serverPort)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('0.0.0.0', clientPort))

        while not self.hasIP:
            self.sendDHCPPackets(s, dest)

    def sendDHCPPackets(self, s, dest):
        print("Send DHCP discovery.")
        discoverResponse = self.DHCPDiscover(s, dest)

        print("Send DHCP request.")
        requestResponse = self.DHCPRequest(s, dest, discoverResponse)
        print("Received IP from server with address {} and lease {} :".format(ipaddress.IPv4Address(
            int(dhcppython.packet.DHCPPacket.from_bytes(requestResponse).options[2].data.hex(), 16)),
            int(dhcppython.packet.DHCPPacket.from_bytes(requestResponse).options[1].data.hex(), 16),
        ), end=" ")
        print(colored(dhcppython.packet.DHCPPacket.from_bytes(
            requestResponse).yiaddr, 'green') + "\n")

    def DHCPDiscover(self, s, dest):
        discoverTimeout = self.initialInterval
        data = None

        while data is None:
            s.settimeout(discoverTimeout)
            try:
                discoveryPacket = self.sendPacket(self.macAddress, type=DHCPDISCOVER, XID=str(ipaddress.IPv4Address(0)))
                s.sendto(discoveryPacket, dest)

                data, address = s.recvfrom(MAX_BYTES)
                while dhcppython.packet.DHCPPacket.from_bytes(data).chaddr.lower() != self.macAddress.lower():
                    data, address = s.recvfrom(MAX_BYTES)

                if int.from_bytes(dhcppython.packet.DHCPPacket.from_bytes(data).options[0].data,
                                  'little') == DHCPDECLINE:
                    print(colored("Client allocating IP declined!", 'red'))
                    time.sleep(10)
                    data = None
                    raise
                else:
                    print(colored("Receive DHCP offer.", 'green'))
            except:
                pass
            if data is None:
                print(colored("faild with discover time : {}".format(discoverTimeout), 'red'))

            discoverTimeout = self.makeNewDiscoverTimeout(discoverTimeout)

        return data

    def DHCPRequest(self, s, dest, requestResponse):
        xid = dhcppython.packet.DHCPPacket.from_bytes(requestResponse).xid
        data = None
        s.settimeout(self.ackTimeout)

        try:
            requestPacket = self.sendPacket(self.macAddress, str(ipaddress.IPv4Address(xid)), DHCPREQUEST)
            s.sendto(requestPacket, dest)

            data, address = s.recvfrom(MAX_BYTES)

            while dhcppython.packet.DHCPPacket.from_bytes(data).chaddr.lower() != self.macAddress.lower():
                data, address = s.recvfrom(MAX_BYTES)

            if data is not None:
                if not int.from_bytes(dhcppython.packet.DHCPPacket.from_bytes(data).options[0].data,
                                      'little') == DHCPNACK:
                    self.hasIP = True
                    print(colored("Receive DHCP ack.", 'green'))
                else:
                    print(colored("Receive DHCP ack.", 'red'))
                return data
        except:
            print(colored('error occured', 'red'))

        return data

    def makeNewDiscoverTimeout(self, currentTimeout):
        randomNumber = random.random()
        newTimeout = randomNumber * 2 * currentTimeout

        if newTimeout > self.backoffCutoff:
            return self.backoffCutoff

        return newTimeout

    def sendPacket(self, clientMacAddress, XID, type):

        OP = bytes([0x01])
        HTYPE = bytes([0x01])
        HLEN = bytes([0x06])
        HOPS = bytes([0x00])
        XID = bytes(convertIPToHexArray(XID))
        SECS = bytes([0x00, 0x00])
        FLAGS = bytes([0x80, 0x00])
        CIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        YIADDR = bytes(([0x00, 0x00, 0x00, 0x00]))
        SIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        GIADDR = bytes([0x00, 0x00, 0x00, 0x00])
        CHADDR = bytes(convertMacAdressToHexArray(clientMacAddress))
        SNAME = bytes(64)
        FILE = bytes(128)
        Magiccookie = bytes([0x63, 0x82, 0x53, 0x63])
        DHCPOptions1 = bytes([53, 1, type])  # DHCP Type
        DHCPOptions2 = bytes([255, 0, 0])

        package = OP + HTYPE + HLEN + HOPS + XID + SECS + FLAGS + CIADDR + YIADDR + SIADDR + GIADDR + CHADDR + SNAME + FILE + Magiccookie + DHCPOptions1 + DHCPOptions2

        return package


if __name__ == '__main__':
    dhcp_client = DHCP_client()
    dhcp_client.client()

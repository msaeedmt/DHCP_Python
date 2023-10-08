import json


class AllocatedIP:
    def __init__(self, IP, macAddress, lease):
        self.lease = lease
        self.IP = IP
        self.macAddress = macAddress
        self.remainingLeaseTime = self.lease

        # self.setLease()

    def printDetails(self):
        print("IP : {}\nMacAddress : {}\nLease : {}".format(self.IP, self.macAddress, self.remainingLeaseTime))

    def decreaseRemainingLeaseTime(self):
        self.remainingLeaseTime -= 1

    # def setLease(self):
    #     configFile = open('configs.json', )
    #     configs = json.load(configFile)
    #     self.lease = int(configs['lease_time'])

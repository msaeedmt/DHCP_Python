def convertIPToHexArray( IP):
    splitedIP = IP.split('.')
    hexIPParts = []
    for part in splitedIP:
        hexIPParts.append(int(part))

    return hexIPParts


def convertMacAdressToHexArray( macAddress):
    splitedMacAdress = macAddress.split(':')
    hexMacAdressParts = []
    for part in splitedMacAdress:
        hexMacAdressParts.append(int(part, 16))

    while len(hexMacAdressParts) < 16:
        hexMacAdressParts.append(0)

    return hexMacAdressParts
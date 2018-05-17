#!/usr/bin/python2.7

from Tkinter import *
from scapy.all import *
import bs4

filename = open('mac-vendor.txt', 'r')
vendors = filename.read()
filename.close()
del filename
vendors = eval(vendors)

def macSplit(mac):
    return ''.join(mac.split(':')[0:3])
    

class Host(object):

    def __init__(self, mac):
        self.mac = mac

class AccessPoint(Host):

    def __init__(self, mac, density):
        self.mac = mac
        self.density = density
        self.distances = []
        self.name = ''
        self.channel = ''
        self.enc = ''
        self.vendor = 'Unknown'

    def __str__(self):
        return '{} ({}:{}) - enc:{} chan:{} dist:{}'.format(self.name,
                                                            self.mac,
                                                            self.vendor,
                                                            self.enc,
                                                            self.channel,
                                                            str(sum(self.distances)/self.density))

class Probe(Host):

    def __init__(self, mac, density):
        self.mac = mac
        self.density = density
        self.distances = []
        self.parent = 'none'
        self.vendor = 'Unknown'

    def __str__(self):
        return '{} - {}; (parent:{}); dist:{}'.format(self.mac,
                                                      self.vendor,
                                                      self.parent,
                                                      str(sum(self.distances)/self.density))

'''FUNCTIONS'''
# Converts hexadecimal dBm to Decimal for easier understanding
def dBmConverter(dBm):
    # Possible hex characters 
    digits='0123456789abcdef'
    x = []
    # Make sure the input is 2 digits long
    if (len(dBm)==2):
        for i in dBm:
            # Check if input matches with hex characters
            for digit in digits:
                if i==digit:
                    x.append(digits.index(i))
        # Convert to decimal
        a = x[0]*16
        a = a + x[1]
    # If the input is not 2 digits long, return 0
    else:
        a = 255
    return a-255

# the Base GUI
class MainGUI(Frame):
    # the constructor
    def __init__(self, master):
        # background color = #ffffff
        Frame.__init__(self, master)
        master.attributes("-fullscreen", False)
        self.master = master
        self.setupGUI()

    def setupGUI(self):
        # Header
        header = Label(self.master, text="Net Navigator",
                       fg="black", font=("Arial",72))
        header.grid(row=0, column=0, columnspan=3, sticky=E+W+N+S)
        # Spacer
        padding = Label(self.master, text="-"*200, fg="#000000")
        padding.grid(row=1, column=0, columnspan=3, sticky=E+W+N+S)
        # State Display Section
        self.display = Label(self.master, text="", font=("Arial", 18))
        self.display.grid(row=2, column=0, columnspan=3, sticky=E+W+N+S)
        # Spacer
        padding = Label(self.master, text="-"*200, fg="#000000")
        padding.grid(row=3, column=0, columnspan=3, sticky=E+W+N+S)
        # Timeout Section
        timeouttext = Label(window, text="Timeout: ", font=("Arial", 18), width=12)
        timeouttext.grid(row=4, column=1, sticky=W)
        self.e1 = Entry(window, width=30)
        self.e1.grid(row=4, column=1)
        b1 = Button(window, text="Submit", bg="#ffffff", width=16,
                    command=lambda:self.process(self.e1.get()))
        b1.grid(row=4, column=1, sticky=E)
        # Blank Spacer
        padding = Label(self.master, text="", fg="#000000")
        padding.grid(row=5, column=0, columnspan=3, sticky=E+W+N+S)
        
    def process(self, arg):
        if arg == "":
            self.display["text"] = "Please put in a number greater than zero"
            self.e1.delete(0,END)
        self.sniffer(arg)
        try:
            arg = int(arg)
            if arg is abs(arg):
                if arg == 0:
                    self.display["text"] = "Please put in a number greater than zero"
                    self.e1.delete(0,END)
                else:
                    self.sniffer(arg)
                    self.display["text"] = "Success"
                    self.e1.delete(0,END)
                    
            else:
                self.display["text"] = "Please input a non-negative number"
                self.e1.delete(0,END)
        except:
            self.display["text"] = "Please input a number"
            self.e1.delete(0,END)

    def sniffer(self, t):
        a = sniff(iface="wlan0mon", timeout=int(t), prn=classifier)
        self.pagemaker()

    def pagemaker(self):
        # open the devices page, store it, and close it
        filename = open("devices.html", 'r')
        dev = filename.read()
        filename.close()
        # use the bs4 library to store the contents of the webpage in a variable
        #  that can be manipulated
        soup = bs4.BeautifulSoup(dev, "html.parser")
        # clear the current data in the table
        soup.table.tbody.string = ''
        # for each of the hosts, add their data to the webpage
        for i in range(len(probes)):
            # create new row of table
            tr = soup.new_tag('tr')
            # create data entry in row and place it in the row
            #  (count)
            td = soup.new_tag('td')
            td.append(str(i+1))
            tr.append(td)
            # create data entry in row and place it in the row
            #  (mac address)
            td = soup.new_tag('td')
            td.append(probes[probes.keys()[i]].mac)
            tr.append(td)
            # create data entry in row and place it in the row
            #  (vendor)
            td = soup.new_tag('td')
            td.append(probes[probes.keys()[i]].vendor)
            tr.append(td)
            # create data entry in row and place it in the row
            #  (parent)
            td = soup.new_tag('td')
            td.append(probes[probes.keys()[i]].parent)
            tr.append(td)
            # create data entry in row and place it in the row
            #  (density)
            td = soup.new_tag('td')
            td.append(str(probes[probes.keys()[i]].density))
            tr.append(td)
            # create data entry in row and place it in the row
            #  (distance)
            td = soup.new_tag('td')
            td.append(str(sum(probes[probes.keys()[i]].distances)/probes[probes.keys()[i]].density))
            tr.append(td)
            # place row in the body of the table
            soup.table.tbody.append(tr)
        # overwrite the old file with the new one
        filename = open('devices.html', 'w')
        filename.write(str(soup))
        filename.close()

        # open the aps page, store it, and close it
        filename = open('aps.html', 'r')
        dev = filename.read()
        filename.close()
        # use the bs4 library to store the contents of the webpage in a variable
        #  that can be manipulated
        soup = bs4.BeautifulSoup(dev, "html.parser")
        # clear the current data in the table
        soup.table.tbody.string = ''
        # for each of the hosts, add their data to the webpage
        for i in range(len(aps)):
            # create new row of table
            tr = soup.new_tag('tr')
            # create data entry in row and place it in the row
            #  (count)
            td = soup.new_tag('td')
            td.append(str(i+1))
            tr.append(td)
            # create data entry in row and place it in the row
            #  (ssid)
            td = soup.new_tag('td')
            td.append(aps[aps.keys()[i]].name)
            tr.append(td)
            # create data entry in row and place it in the row
            #  (mac address)
            td = soup.new_tag('td')
            td.append(aps[aps.keys()[i]].mac)
            tr.append(td)
            # create data entry in row and place it in the row
            #  (vendor)
            td = soup.new_tag('td')
            td.append(aps[aps.keys()[i]].vendor)
            tr.append(td)
            # create data entry in row and place it in the row
            #  (channel)
            td = soup.new_tag('td')
            td.append(aps[aps.keys()[i]].channel)
            tr.append(td)
            # create data entry in row and place it in the row
            #  (encryption)
            td = soup.new_tag('td')
            td.append(aps[aps.keys()[i]].enc)
            tr.append(td)
            # create data entry in row and place it in the row
            #  (density)
            td = soup.new_tag('td')
            td.append(str(aps[aps.keys()[i]].density))
            tr.append(td)
            # create data entry in row and place it in the row
            #  (distance)
            td = soup.new_tag('td')
            td.append(str(sum(aps[aps.keys()[i]].distances)/aps[aps.keys()[i]].density))
            tr.append(td)
            # place row in the body of the table
            soup.table.tbody.append(tr)
        # overwrite the old file with the new one
        filename = open('aps.html', 'w')
        filename.write(str(soup))
        filename.close()
        

aps = dict()
probes = dict()

# Packet handler (all your packets are belong to us)
def classifier(pkt):

    # packet is from an AP that is not in the list
    if pkt.haslayer(Dot11Beacon):
        if not aps.has_key(pkt.addr2):
            # grab the mac
            mac = pkt.addr2
            # add the AP to the list
            aps[mac] = AccessPoint(mac, 1)
            # get the distance
            dBm = pkt.notdecoded
            dBm = dBm[6]
            dBm = dBm.encode('hex')
            dBm = dBmConverter(dBm)
            aps[mac].distances.append(dBm)
            # get the ssid
            aps[mac].name = pkt.info
            # if the ssid is blank, call it <unknown>
            if aps[mac].name == "":
                aps[mac].name = "<Hidden>"
            # get the channel
            aps[mac].channel = str(ord(pkt[Dot11Elt:3].info))
            # cycle to test if it has WPA2 Encryption
            while True:
                try:
                    if pkt.ID == 48:
                        aps[mac].enc = "Locked"
                    pkt = pkt.payload
                except:
                    break
            # if WPA2 is not found, assume it is Open
            if not aps[mac].enc:
                aps[mac].enc = "Open"
            # add vendor if vendor exists
            if vendors.has_key(macSplit(mac)):
                aps[mac].vendor = vendors[macSplit(mac)]

    # packet is from a Probe that is not in the list
    elif pkt.haslayer(Dot11ProbeReq):
        if not probes.has_key(pkt.addr2):
            # grab the mac
            mac = pkt.addr2
            # add the Probe to the list
            probes[mac] = Probe(pkt.addr2, 1)
            # get the distance
            dBm = pkt.notdecoded
            dBm = dBm[6]
            dBm = dBm.encode('hex')
            dBm = dBmConverter(dBm)
            probes[mac].distances.append(dBm)
            # add vendor if vendor exists
            if vendors.has_key(macSplit(mac)):
                probes[mac].vendor = vendors[macSplit(mac)]

    # packet is from a Probe that is in the list
    elif probes.has_key(pkt.addr2):
        # increase the density
        probes[pkt.addr2].density += 1
        # get the distance
        dBm = pkt.notdecoded
        dBm = dBm[6]
        dBm = dBm.encode('hex')
        dBm = dBmConverter(dBm)
        probes[pkt.addr2].distances.append(dBm)
        # Check if the Probe has a parent
        if ((pkt.addr1 != 'ff:ff:ff:ff:ff:ff') and (pkt.addr1 and pkt.addr2)):
            probes[pkt.addr2].parent = pkt.addr1

    # packet is from anAP that is in the list
    elif aps.has_key(pkt.addr2):
        # increase the density
        aps[pkt.addr2].density += 1
        # get the distance
        dBm = pkt.notdecoded
        dBm = dBm[6]
        dBm = dBm.encode('hex')
        dBm = dBmConverter(dBm)
        aps[pkt.addr2].distances.append(dBm)

window = Tk()
p = MainGUI(window)
window.mainloop()

'''
timeouttext = Label(window, text="Timeout: ", font=("Arial", 18))
        timeouttext.grid(row=4, column=0, sticky=E+N+S)
        e1 = Entry(window)
        e1.grid(row=4, column=1, sticky=W)
        b1 = Button(window, text="Submit", bg="#ffffff",
                    command=lambda:self.process(e1.get()))
        b1.grid(row=4, column=1)
'''

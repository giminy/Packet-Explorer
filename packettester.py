# Copyright Digital Bond, Inc
# Author: K. Reid Wightman, wightman - at - digitalbond - dot - com

import sys
def usage():
  print "This application sorts through a pcap file and prints out unique packets"
  print "Usage: ", sys.argv[0], " <pcapfile> <udp/tcp> <portnumber> <ignorelist=0,1,2,3,4,5,etc>"
  print "Where: <pcapfile> is a filename of a pcap file (not pcapng)"
  print "\t<udp/tcp> is one of udp or tcp"
  print "\t<portnumber> is a port 1-65535"
  print "\t<ignorelist> is a comma-separate list of bytes to ignore when comparing packets"
  print "Example usage:"
  print " $ python ", sys.argv[0], " myfile.pcap tcp 502 0,1,2,3,4,5"
  print "(The result will be a list of unique modbus packets, ignoring some header bytes)" 
  exit(1)


if len(sys.argv) < 5:
  usage()

import scapy.all
# yeah yeah, I'm not sanitizing my inputs :P
filename = sys.argv[1]
proto = sys.argv[2].upper()
portnum = int(sys.argv[3])
ignores = sys.argv[4]

# proto used for helping to filter the packets that are interesting
if proto == "UDP":
  proto = 17
elif proto == "TCP":
  proto = 6
else:
  usage()


ignorebytes = []

try:
  for i in ignores.split(","):
    ignorebytes.append(int(i))
except:
  print "bad ignorebyte list"
  usage()

def comparelist(testload, packetlist, ignorelist):
  seen = False
  for packet in packetlist:
    if compare(testload, packet, ignorelist):
      seen = True
      break
  return seen

def compare(input1, input2, ignorelist):
  l1 = len(input1)
  l2 = len(input2)
  li = len(ignorelist)
  if l1 != l2:
    return False
  for i in range(0,l1):
    if i not in ignorelist:
      if input1[i] != input2[i]:
        return False
  return True
    
pc = scapy.utils.rdpcap(filename)
packetnum = 1
mydict = {}
for packet in pc:
  #print "inspect packet, proto", packet.proto, packet.sport, packet.dport
  if packet.proto == proto:
    if packet.sport == portnum or packet.dport == portnum:
      pl = packet.load
      if comparelist(pl, mydict.keys(), ignorebytes):
        #print "seen before, adding"
        # first find the key to append to
        for k in mydict.keys():
          if compare(pl, k, ignorebytes):
            mydict[k].append(packetnum)
            break # leave for k in mydict.keys()
      else:
        #print "not seen before"
        mydict[pl] = [packetnum]
  packetnum += 1
# now that we've processed the packets, let's look at the unique ones
uniquepacketlist = []
for k in mydict.keys():
 if len(mydict[k]) == 1:
#  print mydict[k][0], "is a unique packet"
  uniquepacketlist.append(mydict[k][0])
uniquepacketlist.sort()
print uniquepacketlist



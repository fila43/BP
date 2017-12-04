import subprocess
import sys
import os
import re
import json


def search(input):
    data = json.loads(input)
    server = ""
    client = ""
    packet_count = 0
    retr_pos = -100
    status = None
    length = 0
    direction_to = None
    packet_length = []
    size = 0
    info={}
    flows=[]


    for ip in data:
        if "pop" in ip["_source"]["layers"]:
            pop = ip["_source"]["layers"]["pop"]
            if isinstance(pop, dict):
                if pop.has_key("pop.request_tree"):
                    if ip["_source"]["layers"]["pop"]["pop.request_tree"]["pop.request.command"] == 'RETR':
                        retr_pos = packet_count
                        size=0
                        for i in packet_length:
                            size += i

                       # print "delka_celkem: " + str(size)
                        packet_length[:] = []
                        client = ip["_source"]["layers"]["ip"]["ip.src"]
                        server = ip["_source"]["layers"]["ip"]["ip.dst"]
                        direction_to = server
                        flows.append(info)
                        info={}
                        info["name"]=ip["_source"]["layers"]["pop"]["pop.request_tree"]["pop.request.parameter"]
                        info["server"]=server+"."+ip["_source"]["layers"]["tcp"]["tcp.dstport"]
                        print "DSTPORT: "+ip["_source"]["layers"]["tcp"]["tcp.dstport"]
                      #  print "-------------------------"

                      #  print "server: " + server
                      #  print "client: " + client
                if pop.has_key("pop.response_tree"):
                    if pop["pop.response_tree"]["pop.response.indicator"] == '+OK' and packet_count == retr_pos + 1:
                        status = True
            if ip["_source"]["layers"].has_key("tcp") and status and packet_count > retr_pos and direction_to == ip["_source"]["layers"]["ip"]["ip.src"]:
                #   print "nextseq: "+ip["_source"]["layers"]["tcp"]["tcp.nxtseq"]
               # print "seq: " + ip["_source"]["layers"]["tcp"]["tcp.seq"]
                if not "seq" in info:
                    info["seq"]=ip["_source"]["layers"]["tcp"]["tcp.seq"]
               # print "delka_tshark: " + ip["_source"]["layers"]["tcp"]["tcp.len"]
                if "length" in info:
                    info["length"]+=int(ip["_source"]["layers"]["tcp"]["tcp.len"])
                else:
                    info["length"]=int(ip["_source"]["layers"]["tcp"]["tcp.len"])

                    # print "delka "+str(length)
                    packet_length.append(length - 1)
            if direction_to == ip["_source"]["layers"]["ip"]["ip.dst"]:
                status = False
        packet_count += 1
    flows.append(info)

    size = 0

    return flows



def convert_ip(ip):
    bytes=ip.split('.')
    final_ip=""
    i=0
    for byte in bytes:
        if i<4:
            i+=1
            if len(byte) == 1:
                final_ip+="00"+byte+"."
            elif len(byte) == 2:
                final_ip+="0"+byte+"."
            else:
                final_ip+=byte+"."
        else:
            for x in range(0,5-len(byte)):
                final_ip+="0"
            final_ip+=byte+"."

    return final_ip[:-1]

def read_data(start,size,file):
    in_file = open(file, "rb")  # opening for [r]eading as [b]inary
    if in_file.closed:
        print "zavreno !!!!!!!!"

    print start
    print size
    in_file.seek(start* 2)
    data = in_file.read(size * 2)  # if you only wanted to read 512 bytes, do .read(512)
    data = data.strip()
    print data.decode("hex")[:-2]
    in_file.close()
  #  print "---------------------------------------------------------------------------------"



if not os.path.isdir("hexa"):
    os.mkdir("hexa")

pokus=""
p=subprocess.Popen(["tshark","-r",sys.argv[1],"-T","json"],stdout=subprocess.PIPE)
json_data,err=p.communicate()
meta_data=search(json_data)



p=subprocess.Popen(["tcpflow","-r",sys.argv[1],"-c","-D"],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
out,err=p.communicate()
if os.path.exists("report.xml"):
    subprocess.call(["rm","report.xml"])



regex = r"^\d{3}\.\d{3}.\d{3}\.\d{3}.\d{5}-\d{3}\.\d{3}.\d{3}\.\d{3}.\d{5}\:"
ip={}
actual_ip=None
for line in out.split('\n'):
    if re.match(regex, line) is not None:
        line=line[:-24]
        actual_ip=line
        continue
    if actual_ip in ip:
        ip[actual_ip]+=line+"\n"
    else:
        ip[actual_ip] = line+"\n"

#print ip
for item in ip:
    converted_item=convert_ip(item)
    with open("hexa/"+converted_item, 'a') as the_file:
        the_file.write(ip[item])

flag=True

for item in meta_data:
    if not "length" in item :
        continue
    server=convert_ip(item["server"])

    if (flag):
        subprocess.call(["./hexa_data","hexa/"+server])
        flag=False
    print "SEQ: "+item["seq"]
    print "LEN: "+str(item["length"])
    print "SERVER: "+server
    read_data(int(item["seq"]),item["length"],"hexa/"+server+".data")





import json
import sys
import os
import subprocess
import re


class ObjectData:
    def __init__(self, start=None):
        self.__start = start
        self.__length = 0

    def set_length(self, value):
        self.__length = value

    def add(self, value):
        self.__length += value

    def __str__(self):
        return "Start: "+str(self.__start)+"\nLength: "+str(self.__length)


class Protocol:
    def __init__(self, command_key, command, find_attr, json_file):
        self.__command = command
        self.__find_attr = find_attr
        self.__command_key = command_key
        self.__client = None
        self.__server = None
        self.__json_data = self.__read_json(json_file)
        self.__obj_stack = []

    def __str__(self):
        for obj in self.__obj_stack:
            print obj
        return ""

    def obj_count(self):
        print self.__obj_stack
        return len(self.__obj_stack)

    def __add_object(self, obj):
        self.__obj_stack.append(obj)

    def get_last_object(self):
        return self.__obj_stack[len(self.__obj_stack)-1:][0]

    def __search(self, pattern, d):
        """search key in nested dict, if found return value of key"""
        if pattern in d:
            return d[pattern]
        else:
            for key in d:
                if isinstance(d[key], dict):
                    result = self.__search(pattern, d[key])
                    if result is not None:
                        return result

    @staticmethod
    def __read_json(filename):
        with open(filename) as my_file:
            return json.load(my_file)

    def find_length(self):
        """ find starts and lengths of all sending object and store it into list of ObjectData"""
        command_found = False   # flag True if object was found
        relative_seq = 1        # TODO relative seqv, used for connect streams
        for packet in self.__json_data: # loop over each packet
            if self.__server is not None and (self.__server != self.__search("ip.src", packet)):
                command_found = False   # restart process of searching when whole object was send

            if not command_found:       # searching start of object
                command_value = self.__search(self.__command_key, packet)
                if command_value is not None:
                    command_found = True

                    if relative_seq != 1:   # set up client server , create object
                        self.__add_object(ObjectData(int(self.__search("tcp.ack", packet))+relative_seq-1))
                    else:
                        self.__add_object(ObjectData(self.__search("tcp.ack", packet)))
                    self.__client = self.__search("ip.src", packet)
                    self.__server = self.__search("ip.dst", packet)

            if self.__server == self.__search("ip.src", packet):
                relative_seq += int(self.__search("tcp.len", packet))

            if command_found and (self.__server == self.__search("ip.src", packet)):    # setup object length
                tcp_length = self.__search(self.__find_attr, packet)
                if tcp_length is not None:
                    self.get_last_object().add(int(tcp_length))


class HexaData:
    def __init__(self, file_path):
        self.__ip_regex = r"^\d{3}\.\d{3}.\d{3}\.\d{3}.\d{5}-\d{3}\.\d{3}.\d{3}\.\d{3}.\d{5}\:"
        self.__ip = None

        if not os.path.isdir("hexa"):
            os.mkdir("hexa")

        p = subprocess.Popen(["tcpflow", "-r", file_path, "-c", "-D"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.__tcpflow_data, err = p.communicate()
        if os.path.exists("report.xml"):
            subprocess.call(["rm", "report.xml"])

    def __split_data(self):
        """split hexa data based on end of line , each line append into
            right field in ip list
        """
        actual_ip = None
        for line in self.__tcpflow_data.split('\n'):
            if re.match(self.__ip_regex, line) is not None:
                line = line[:-24]
                actual_ip = line
                continue
            if actual_ip in self.__ip:
                self.__ip[actual_ip] += line + "\n"
            else:
                self.__ip[actual_ip] = line + "\n"

        for item in self.__ip:      # create name for file
            converted_item = self.__convert_ip(item)
            with open("hexa/" + converted_item, 'a') as the_file:
                the_file.write(self.__ip[item])
            file.close("hexa/" + converted_item)

            subprocess.call(["./hexa_data", "hexa/" + converted_item])  # remove redundant spaces

    @staticmethod
    def __convert_ip(ip):
        """add 0 into ip address 10.10.10.10 -> 010.010.010.010"""
        octets = ip.split('.')
        final_ip = ""
        i = 0
        for byte in octets:
            if i < 4:
                i += 1
                if len(byte) == 1:
                    final_ip += "00" + byte + "."
                elif len(byte) == 2:
                    final_ip += "0" + byte + "."
                else:
                    final_ip += byte + "."
            else:
                for x in range(0, 5 - len(byte)):
                    final_ip += "0"
                final_ip += byte + "."

        return final_ip[:-1]







if sys.argv <= 1:
    print "lepe argumenty"
    exit(1)


  #  print json.dumps(packet, indent=4, sort_keys=True)

protokol = Protocol("http.request.method","GET","tcp.len",sys.argv[1])
protokol.find_length()
print protokol






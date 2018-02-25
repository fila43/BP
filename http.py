import json
import sys
import os
import subprocess
import re
import binascii
import argparse




class ObjectData:
    def __init__(self, start=None):
        self.__start = start
        self.__length = 0

    def set_length(self, value):
        self.__length = value

    def add(self, value):
        self.__length += value

    def length(self):
        return int(self.__length)

    def start(self):
        return int(self.__start)

    def __str__(self):
        return "Start: "+str(self.__start)+"\nLength: "+str(self.__length)


class Protocol:
    def __init__(self, command_key, command, find_attr, pcap):
        self.__command = command
        self.__find_attr = find_attr
        self.__command_key = command_key
        self.__client = None
        self.__server = None
        self.__server_port = None
        self.__client_port = None
        self.__error = None
        self.__error_code = None
        self.__json_data = json.loads(self.__create_json(pcap))
        self.__obj_stack = []

    def __str__(self):
        for obj in self.__obj_stack:
            print (obj)
        return ""

    @staticmethod
    def __create_json(pcap):
        p = subprocess.Popen(["tshark", "-r", pcap, "-T", "json"], stdout=subprocess.PIPE)
        json_data, err = p.communicate()
        return json_data

    def server_ip(self):
        return self.__server

    def set_error(self, error, error_code):
        self.__error = error
        self.__error_code = error_code

    def server_port(self):
        return self.__server_port

    def obj_count(self):
        print (self.__obj_stack)
        return len(self.__obj_stack)

    def __remove_last(self):
        self.__obj_stack = self.__obj_stack[:-1]

    def __add_object(self, obj):
        self.__obj_stack.append(obj)

    def get_object(self, index):
        return self.__obj_stack[index]

    def get_obj_list_len(self):
        return len(self.__obj_stack)

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

        for packet in self.__json_data: # loop over each packet
            if self.__server is not None and (self.__server != self.__search("ip.src", packet)) and (self.__search("tcp.len", packet) != "0"):
                command_found = False   # restart process of searching when whole object was send

            if not command_found:       # searching start of object
                command_value = self.__search(self.__command_key, packet)

                if command_value == self.__command:
                    command_found = True

                    self.__add_object(ObjectData(self.__search("tcp.ack", packet)))
                    self.__client = self.__search("ip.src", packet)
                    self.__server = self.__search("ip.dst", packet)
                    self.__server_port = self.__search("tcp.dstport", packet)
                    self.__client_port = self.__search("tcp.srcport", packet)

            if command_found and (self.__server == self.__search("ip.src", packet)):    # setup object length
                error_value = self.__search(self.__error, packet)
                if error_value is not None:
                    if error_value == self.__error_code:
                        self.__remove_last()
                        command_found = False
                        print ("deleting")
            if command_found and (self.__server == self.__search("ip.src", packet)):
                tcp_length = self.__search(self.__find_attr, packet)
                if tcp_length is not None:
                    self.get_last_object().add(int(tcp_length))


class HexaData:
    def __init__(self, file_path):
        self.__ip_regex = r"^\d{3}\.\d{3}.\d{3}\.\d{3}.\d{5}-\d{3}\.\d{3}.\d{3}\.\d{3}.\d{5}\:"
        self.__ip = {}

        if not os.path.isdir("hexa"):
            os.mkdir("hexa")

        p = subprocess.Popen(["tcpflow", "-r", file_path, "-c", "-D"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.__tcpflow_data, err = p.communicate()
        if os.path.exists("report.xml"):
            subprocess.call(["rm", "report.xml"])

        self.__split_data()

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
            converted_item = self.convert_ip(item)
            with open("hexa/" + converted_item, 'a') as the_file:
                the_file.write(self.__ip[item])
            file.close(the_file)

            subprocess.call(["./hexa_data", "hexa/" + converted_item])  # remove redundant spaces

    @staticmethod
    def convert_ip(ip):
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

    def write_data(self, source_name, dest_name, protocol, delimiter = None):
        with open("hexa/" + source_name + ".data", 'rb') as myfile:

            i = 0
            while i<protocol.get_obj_list_len():
                myfile.seek(2 * (protocol.get_object(i).start() - 1))
                data = myfile.read((protocol.get_object(i).length()) * 2)  # if you only wanted to read 512 bytes, do .read(512)
                if delimiter is not None:
                    offset = data.find(delimiter)
                    if offset == -1:
                        offset = 0  # TODO exception
                        delimiter = ''
                    if delimiter != "":
                        data = data[offset + len(delimiter):]
                data = binascii.unhexlify(data)
                with open(dest_name+str(i), 'wb') as out:
                    out.seek(0)
                    out.write(data)
                file.close(out)
                print "Creating file: "+dest_name+str(i)
                i = i+1

    def __del__(self):
        os.system('rm -r hexa/')


class Initialization:
    def __init__(self):
        self.__args = None
        self.__protocol = {}
        self.__arguments()
        self.__read_config()

    def __arguments(self):
        parser = argparse.ArgumentParser(description='Extraction of some application data')
        parser.add_argument('file', metavar='file', help='source pcap file')
        parser.add_argument('--level', help='filtering level 1 - all, 2 - user data with headers, 3 - only user data,'
                                            ' default level is 1')
        parser.add_argument('--config', help='path to configuration file, default config')
        parser.add_argument('--errors', action='store_true', help='extract successful and wrong response,'
                                                                  ' default options is only ''for successful response')
        self.__args = parser.parse_args()
        if not "config" in self.__args:
            self.__args['config'] = "config"

    def __read_config(self):
        with open(self.__args.config, 'r') as config_file:
            self.__protocol['json_field'] = config_file.readline().strip()[9:]
            self.__protocol['command'] = config_file.readline().strip()[6:]
            self.__protocol['error'] = config_file.readline().strip()[6:]
            self.__protocol['error_value'] = config_file.readline().strip()[12:]
            delimiter = config_file.readline().strip()[10:]
            self.__protocol['delimiter'] = delimiter.decode("unicode_escape").encode("hex")

    def __get_error_name(self):
        return self.__protocol['error']

    def __get_error_value(self):
        return self.__protocol['error_value']

    def run(self):
        if "level" not in self.__args or self.__args.level == "1":
            p = subprocess.Popen(["tcpflow", "-r", self.__args.file, "-C"], stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
            data, err = p.communicate()
            with open("vysledek.jpeg", 'wb') as out:
                out.seek(0)
                out.write(data)
                file.close(out)
            if os.path.exists("report.xml"):
                subprocess.call(["rm", "report.xml"])
            print "Creating file: Vysledek.jpeg" # TODO pridat jmeno
            exit(0)

        protocol = Protocol(self.__protocol['json_field'], self.__protocol['command'], "tcp.len", self.__args.file)

        if "errors" not in self.__args:
            protocol.set_error(self.__get_error_name(), self.__get_error_value())
        protocol.find_length()
        if protocol.get_obj_list_len() == 0:
            print "Nothing to do! "
            exit(0)

        data = HexaData(self.__args.file)
        name = HexaData.convert_ip(protocol.server_ip() + "." + protocol.server_port())
        if self.__args.level == "3":
            data.write_data(name, "vysledek.jpeg", protocol, self.__protocol['delimiter'])
        else:
            data.write_data(name, "vysledek.jpeg", protocol)

        return protocol.get_obj_list_len()


init = Initialization()
init.run()





#print data






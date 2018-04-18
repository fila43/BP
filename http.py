import json
import sys
import os
import subprocess
import re
import binascii
import argparse

window = 5


class ObjectData:
    def __init__(self, start=None, header=None):
        """
        Constructor setting up start of data object
        :param start: start of object
        :param header: header of object in some cases
        """
        self.__start = start
        self.__length = 0
        self.__header = header
        self.__request = None

    def set_request(self, request):
        """
        setup request (header)
        :param request:
        :return: setter have no return
        """
        self.__request = request

    def get_request(self):
        """
        getter of request
        :return: request value
        """
        return self.__request

    def set_length(self, value):
        """
        setup length
        :param value: length value
        :return:
        """
        self.__length = value

    def add(self, value):
        """
        add value to length
        :param value: value to add
        :return:
        """
        self.__length += value

    def length(self):
        """

        :return: length converted to int
        """
        return int(self.__length)

    def start(self):
        """

        :return: begin of object like int
        """
        return int(self.__start)

    def add_header(self, header):
        """
        setup header
        :param header:
        :return:
        """
        self.__header = header

    def get_header(self):
        """

        :return: header value
        """
        return self.__header

    def __str__(self):
        """
        get info about self
        :return:  string start and length
        """
        return "Start: "+str(self.__start)+"\nLength: "+str(self.__length)


def check_duplicates(array):
    """
    check if key already exists in dict, if key exist, key will be change
    :param array: array with duplicates
    :return: dict with duplicates with changed duplicate-keys
    """
    count = 0
    new_dict = {}
    for k, v in array:
        if k in new_dict:
            new_dict[k+'_'+str(count)] = v
            count = count + 1
        else:
            new_dict[k] = v
    return new_dict


class Protocol:
    def __init__(self, command_key, command, find_attr, pcap):
        """

        :param command_key: value for comparing
        :param command: name of json field whose value is compared with command_key
        :param find_attr:
        :param pcap: source file
        """
        self.__command = command.upper()
        self.__find_attr = find_attr
        self.__command_key = command_key
        self.__client = None
        self.__server = None
        self.__server_port = None
        self.__client_port = None
        self.__error = None
        self.__error_code = None
        self.__json_data = json.loads(self.__create_json(pcap), object_pairs_hook=check_duplicates)
        self.__obj_stack = []
        self.__request_value = None

    def __str__(self):
        """
        print information about all objects in obj_stack
        :return:
        """
        for obj in self.__obj_stack:
            print (obj)
        return ""

    def get_command(self):
        """

        :return: value of attribute command
        """
        return self.__command

    def remove_request(self):
        """
        clear attribute request value and setup value None
        :return:
        """
        self.__request_value = None

    @staticmethod
    def __remove_duplicates(path):
        """
        run editcap for removing identical packets in file path
        :param path: path to source file
        :return:
        """
        subprocess.Popen(["editcap", path, path, "-D", str(window)])

    @staticmethod
    def __create_json(pcap):
        """
        run tshark and return its result
        :param pcap: source file
        :return: json data from tshark
        """
        Protocol.__remove_duplicates(pcap)
        p = subprocess.Popen(["tshark", "-r", pcap, "-T", "json", "-Y", "not tcp.analysis.retransmission and not tcp.analysis.fast_retransmission"], stdout=subprocess.PIPE)
        json_data, err = p.communicate()
        return json_data

    def server_ip(self):
        """

        :return: source ip
        """
        return self.__server

    def client_ip(self):
        """

        :return: destination ip
        """
        return self.__client

    def client_port(self):
        """

        :return: destination port
        """
        return self.__client_port

    def set_error(self, error, error_code):
        """
        set up error values mostly from configuration file
        :param error: JSON key
        :param error_code: JSON value
        :return:
        """
        self.__error = error
        self.__error_code = error_code

    def remove_error(self):
        """
        used to for remove error options and reset obj_stack
        attribute for new searching without errors
        :return:
        """
        self.__error = None
        self.__error_code = None
        self.clean_obj_stack()

    def clean_obj_stack(self):
        """
        erase all object from stack
        :return:
        """
        del self.__obj_stack[:]

    def server_port(self):
        """

        :return: source port
        """
        return self.__server_port

    def obj_count(self):
        """

        :return: count of items in obj_stack attribute
        """
        return len(self.__obj_stack)

    def __remove_last(self):
        """
        remove last searched object
        :return:
        """
        self.__obj_stack = self.__obj_stack[:-1]

    def __add_object(self, obj):
        """
        add new object at top of stack
        :param obj: reference to new object
        :return:
        """
        self.__obj_stack.append(obj)

    def get_object(self, index):
        """
        return object from obj_stack on index position
        :param index: index into "stack" actually from array
        :return: reference to object
        """
        return self.__obj_stack[index]

    def get_obj_list_len(self):
        """

        :return: count of objects in obj_stack
        """
        return len(self.__obj_stack)

    def get_last_object(self):
        """

        :return: return last added object from obj_stack attribute
        """
        return self.__obj_stack[len(self.__obj_stack)-1:][0]

    def find_field(self, key):
        """
        search key in JSON and return value form key field
        :param key: searched json field from json_data
        :return: return found value or None
        """
        value = None
        for packet in self.__json_data:
            value = self.__search(key, packet)
            if value is not None:
                self.__server = self.__search("ip.src", packet)
                self.__client = self.__search("ip.dst", packet)
                self.__client_port = self.__search("tcp.dstport", packet)
                self.__server_port = self.__search("tcp.srcport", packet)
                return value
        return None

    def __search(self, pattern, d):
        """
        search key in nested dict, if found return value of key
        :return: found string value
        """
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
        """
        open file and load json data
        :param filename: path to json file
        :return: json object
        """
        with open(filename) as my_file:
            return json.load(my_file)

    def find_length(self, protocol_rules=None):
        """
        find starts and lengths of all sending object and store it into list of ObjectData
        setup ports, ips
        :param protocol_rules rules from config file
        """
        command_found = False   # flag True if object was found
        header_flag = False
        header = None

        tmp_header_value = None
        for packet in self.__json_data: # loop over each packet
            tmp_header_value = None
            if protocol_rules is not None and protocol_rules['request'] != "":
                tmp_header_value = self.__search(protocol_rules['request'], packet)
                if tmp_header_value == protocol_rules['request_parameter']:
                    header = ObjectData(self.__search("tcp.seq", packet))
                    header_flag = True
                    self.__server = self.__search("ip.src", packet)
                    self.__client = self.__search("ip.dst", packet)
                    self.__client_port = self.__search("tcp.dstport", packet)
                    self.__server_port = self.__search("tcp.srcport", packet)

            if self.__server is not None \
                    and (self.__server != self.__search("ip.src", packet) or self.__server_port != self.__search("tcp.srcport", packet)) \
                    and (self.__search("tcp.len", packet) != "0"):
                command_found = False   # restart process of searching when whole object was send

            if not command_found:       # searching start of object
                command_value = self.__search(self.__command_key, packet)

                if (command_value is not None) and command_value.upper() == self.__command:         # find and create start of object

                    header_flag = False
                    command_found = True

                    self.__add_object(ObjectData(self.__search("tcp.ack", packet), header))
                    self.__client = self.__search("ip.src", packet)
                    self.__server = self.__search("ip.dst", packet)
                    self.__server_port = self.__search("tcp.dstport", packet)
                    self.__client_port = self.__search("tcp.srcport", packet)

                    if protocol_rules is not None and protocol_rules['request'] != "" and protocol_rules['request_parameter'] == "":
                        self.get_last_object().set_request(self.__search(protocol_rules['request'], packet))  # level 2 zjisteni prikazu pri splynuti smeru

            if header_flag and not command_found \
                    and (self.__server == self.__search("ip.src", packet) or self.__server_port == self.__search("tcp.srcport", packet)):             # setup header length
                header.add(int(self.__search(self.__find_attr, packet)))

            if command_found and (self.__server == self.__search("ip.src", packet) or self.__server_port == self.__search("tcp.srcport", packet)):    # setup object length
                if self.__error is not None:                                            # protocol ERROR handle
                    error_value = self.__search(self.__error, packet)
                    if error_value is not None:
                        if error_value == self.__error_code:
                            self.__remove_last()
                            command_found = False
                            print ("deleting")          # TODO smazat

            if command_found and (self.__server == self.__search("ip.src", packet) or self.__server_port == self.__search("tcp.srcport", packet)):    # length addition
                tcp_length = self.__search(self.__find_attr, packet)
                if tcp_length is not None:
                    self.get_last_object().add(int(tcp_length))


class HexaData:
    def __init__(self, file_path):
        """
        constructor, sets up ip regex
        runs tcpflow
        :param file_path: path to source file
        """
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
        """
        split hexa data based on end of line , each line append into right field in ip list

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
        """
        adds 0 into ip address 10.10.10.10 -> 010.010.010.010

        :return converted ip
        """
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

    def write_value(self, filename, value):
        """
        write data from value to file with name filename

        :param filename: name of created file
        :param value: data to write
        :return:
        """
        with open(filename, 'wb') as out:
            out.write(value)

    def write_data(self, source_name, dest_name, protocol, delimiter=None):
        """
        read specific part of data from source_name file depending on protocol and delimiter and write it into dest_name
        file
        :param source_name: name of input file
        :param dest_name: name file which wil be creat
        :param protocol: object with informations about user objects
        :param delimiter: if is set all data before delimiter are cutted
        :return:
        """
        with open("hexa/" + source_name + ".data", 'rb') as myfile:

            i = 0
            while i < protocol.get_obj_list_len():
                myfile.seek(2 * (protocol.get_object(i).start() - 1))
                data = myfile.read((protocol.get_object(i).length()) * 2)  # if you only wanted to read 512 bytes, do .read(512)    jen request request param prazdny u HTTP -smazat request_value

                if delimiter is not None:
                    offset = data.find(delimiter)
                    if offset == -1:
                        offset = 0  # TODO exception
                        delimiter = ''

                    if delimiter != "":
                        data = data[offset + len(delimiter):]
                data = binascii.unhexlify(data)

                header = protocol.get_object(i).get_header()
                header_data = None
                if header is not None:
                    myfile.seek(2*header.start()-2)
                    header_data = binascii.unhexlify(myfile.read(header.length()*2))

                with open(dest_name+"("+str(i)+")", 'wb') as out:
                    out.seek(0)

                    if protocol.get_object(i).get_request() is not None:
                        out.write(protocol.get_command()+" "+protocol.get_object(i).get_request()+"\n")
                    if header_data is not None:
                        out.write(header_data)

                    out.write(data)
                file.close(out)
                print "Creating file: "+dest_name+"("+str(i)+")"
                i = i+1

    def __del__(self):
        """
        destructor use to for remove temporary directory
        :return:
        """
        os.system('rm -r hexa/')


class Initialization:
    def __init__(self):
        self.__args = None
        self.__protocol_rules = {}
        self.__arguments()
        self.__read_config()
        self.__hexa_data = HexaData(self.__args.file)
        self.__file_name = None
        self.__protocol = Protocol(self.__protocol_rules['json_field'], self.__protocol_rules['command'], "tcp.len", self.__args.file)

    def __arguments(self):
        parser = argparse.ArgumentParser(description='Extraction of some application data')
        parser.add_argument('file', metavar='file', help='source pcap file')
        parser.add_argument('--level', help='filtering level 1 - all, 2 - user data with headers, 3 - only user data,'
                                            ' default all levels')
        parser.add_argument('--debug', action='store_true', help='output name is same like input name + suffix .out')
        parser.add_argument('--config', help='path to configuration file, default config')
        parser.add_argument('--errors', action='store_true', help='extract successful and wrong response,'
                                                                  ' default options is only ''for successful response')
        self.__args = parser.parse_args()
        if not "config" in self.__args:
            self.__args['config'] = "config"

    def __read_config(self):
        with open(self.__args.config, 'r') as config_file:
            self.__protocol_rules['json_field'] = config_file.readline().strip()[9:]
            self.__protocol_rules['json_field'] = self.__protocol_rules['json_field'][:self.__protocol_rules['json_field'].find('#')].strip()

            self.__protocol_rules['command'] = config_file.readline().strip()[15:]
            self.__protocol_rules['command'] = self.__protocol_rules['command'][:self.__protocol_rules['command'].find('#')].strip()

            self.__protocol_rules['request'] = config_file.readline().strip()[8:]
            self.__protocol_rules['request'] = self.__protocol_rules['request'][:self.__protocol_rules['request'].find('#')].strip()

            self.__protocol_rules['request_parameter'] = config_file.readline().strip()[14:]
            self.__protocol_rules['request_parameter'] = self.__protocol_rules['request_parameter'][:self.__protocol_rules['request_parameter'].find('#')]
            self.__protocol_rules['request_parameter'] = self.__protocol_rules['request_parameter'].strip()

            self.__protocol_rules['error'] = config_file.readline().strip()[6:]
            self.__protocol_rules['error'] = self.__protocol_rules['error'][:self.__protocol_rules['error'].find('#')].strip()

            self.__protocol_rules['error_value'] = config_file.readline().strip()[12:]
            self.__protocol_rules['error_value'] = self.__protocol_rules['error_value'][:self.__protocol_rules['error_value'].find('#')].strip()

            delimiter = config_file.readline().strip()[10:]
            delimiter = delimiter[:delimiter.find('#')].strip()
            self.__protocol_rules['delimiter'] = delimiter.decode("unicode_escape").encode("hex")

    def __get_error_name(self):
        return self.__protocol_rules['error']

    def __get_error_value(self):
        return self.__protocol_rules['error_value']

    def level1(self):
            self.__protocol.remove_error()
            self.__protocol.find_length()
            self.test_object_count()
            name = self.__protocol.server_ip() + ":" + self.__protocol.server_port() + "-" + \
                   self.__protocol.client_ip() + ":" + self.__protocol.client_port() + "_full"
            self.__protocol.clean_obj_stack()

            p = subprocess.Popen(["tcpflow", "-r", self.__args.file, "-C"], stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE)
            data, err = p.communicate()

            with open(name, 'wb') as out:
                out.seek(0)
                out.write(data)
                file.close(out)
            if os.path.exists("report.xml"):
                subprocess.call(["rm", "report.xml"])
            print "Creating file: "+ name
    def test_object_count(self):

        if self.__protocol.get_obj_list_len() == 0:
            print "Nothing to do! "
            exit(1)

        self.__file_name = HexaData.convert_ip(self.__protocol.server_ip() + "." + self.__protocol.server_port())

    def level3(self):
        self.__protocol.set_error(self.__get_error_name(), self.__get_error_value())
        self.__protocol.find_length()
        self.test_object_count()
        self.__protocol.remove_request()
        self.__hexa_data.write_data(self.__file_name,
                                    self.__protocol.server_ip()+":"+self.__protocol.server_port()+"-" +
                                    self.__protocol.client_ip()+":"+self.__protocol.client_port()+"_object",
                                    self.__protocol, self.__protocol_rules['delimiter'])

        self.__protocol.clean_obj_stack()

    def level2(self):
        self.__protocol.find_length(self.__protocol_rules)
        self.test_object_count()
        self.__hexa_data.write_data(self.__file_name,
                                    self.__protocol.server_ip()+":"+self.__protocol.server_port()+"-" +
                                    self.__protocol.client_ip()+":"+self.__protocol.client_port()+"_request",
                                    self.__protocol)
        self.__protocol.clean_obj_stack()

    def level4(self):
        data = self.__protocol.find_field(self.__protocol_rules['json_field'])
        name = self.__protocol.server_ip()+":"+self.__protocol.server_port()+"-" + self.__protocol.client_ip()+":"+self.__protocol.client_port()
        self.__hexa_data.write_value(name, data)

        print "Creating file: " + name


    def run(self):
        r = self.__protocol_rules
        if (r['json_field']!= "" and r['command'] == "" and r['request'] == "" and r['request_parameter'] == ""
            and r['error'] == "" and r['error_value'] == ""):
            self.level4()
        else:
            if "level" not in self.__args or self.__args.level == "1":
                self.level1()
            elif "level" in self.__args and self.__args.level == "2":
                self.level2()
            elif "level" in self.__args and self.__args.level == "3":
                self.level3()
            else:
                self.level1()
                self.level2()
                self.level3()


init = Initialization()
init.run()





#print data






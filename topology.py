import re
from database import db_session
from models.vulnerability import Vulnerability
import logging
from xml.etree.ElementTree import parse, Element
import csv
from netaddr import IPNetwork, IPAddress, valid_ipv4, AddrFormatError
import xml.etree.ElementTree as ET

def clean_host_name(hostname):
    cleaned_hostname = hostname.replace(' ', '')
    return cleaned_hostname

def clean_vlan_name(hostname):
    cleaned_hostname = hostname.strip().replace(' ', '')
    return cleaned_hostname

class Topology:
    def __init__(self):
        self._vlans = []
        self._zones = []  # contains only the "zones : parents of real vlans"
        self._hosts = []
        self._services = []
        self.flow_matrix = None

    @property
    def hosts(self):
        return self._hosts

    @property
    def vlans(self):
        return self._vlans

    @property
    def global_vlans(self):
        return self._zones

    @property
    def vulnerabilities(self):
        vulnerabilities = {}
        for host in self.hosts:
            for cve, vulnerability in host.vulnerabilities.items():
                vulnerabilities[vulnerability.cve] = vulnerability
        return vulnerabilities

    def get_host_by_ip(self, host_ip):
        for host in self.hosts:
            if host.has_ip(host_ip):
                return host
        return None

    def add_unknown_host_by_ip(self, host_ip):
        host = self.add_host("Unknown_host_" + host_ip, "unknown_int", host_ip)
        interface = host.get_interface_by_ip_address(host_ip)
        if not interface:
            logging.warning("The ip address " + host_ip + " should exist on the host " + "Unknown_host_" + host_ip)
        else:
            self.add_interface_to_vlan(interface)
        return host

    def get_host_by_name(self, host_name):
        for host in self.hosts:
            if host.name == host_name:
                return host
        return None

    def add_host(self, host_name, first_interface_name=None, first_ip_address=None):
        host = Host(host_name, first_interface_name, first_ip_address)
        self._hosts.append(host)
        return host

    def add_host_or_update_existing(self, host_name, interface_name, ip_address, connectedToWAN, security_requirement):
        host = self.get_host_by_name(host_name)
        if not host:
            host = self.add_host(host_name, interface_name, ip_address)
        else:
            host.add_interface(interface_name, ip_address)
        interface = host.get_interface_by_ip_address(ip_address)
        if not interface:
            logging.warning("The ip address " + ip_address + " should exist on the host " + host_name)
        else:
            self.add_interface_to_vlan(interface)
        if connectedToWAN:
            interface.set_connected_to_wan()
        host._security_requirement = security_requirement
        return host

    def get_vlan_by_name(self, vlan_name):
        for vlan in self.vlans:
            if vlan.name == vlan_name:
                return vlan
        return None

    def get_vlan_by_cidr(self, vlan_cidr):
        cidr = IPNetwork(vlan_cidr)
        for vlan in self.vlans:
            if vlan.network == cidr:
                return vlan
        return None

    def add_vlan(self, vlan_name, vlan_network, vlan_mask, vlan_gateway=None):
        vlan = VLAN(vlan_name, vlan_network, vlan_mask, vlan_gateway)

        logging.debug("Adding vlan " + str(vlan))

        # Test if the vlan is contained in an other global vlan of the topology :
        contained_in_vlan = None

        for global_vlan in self.global_vlans:
            if global_vlan.contains_subnet(IPNetwork(vlan_network + "/" + vlan_mask)):
                contained_in_vlan = global_vlan
        if contained_in_vlan:
            contained_in_vlan.add_vlan_to_containing_list(vlan)
            logging.debug("The vlan " + str(vlan) + " is contained in global vlan " + str(contained_in_vlan))

        # Test if the vlan is contained in an other "normal" vlan of the topology :
        contained_in_vlan = None

        for topology_vlan in self.vlans:
            if topology_vlan.contains_subnet(IPNetwork(vlan_network + "/" + vlan_mask)):
                contained_in_vlan = topology_vlan
        if contained_in_vlan:
            contained_in_vlan.add_vlan_to_containing_list(vlan)
            #Move the container vlan into the "global vlans list" and remove it from the "normal" vlans
            self._zones.append(contained_in_vlan)
            self.vlans.remove(contained_in_vlan)
            logging.debug("The vlan " + str(vlan) + " is contained in normal vlan " + str(contained_in_vlan))

        #Test if the vlan contains other normal vlans of the topology :
        contained_vlans = []

        for topology_vlan in self.vlans:
            if vlan.contains_subnet(topology_vlan.network):
                contained_vlans.append(topology_vlan)
        if contained_vlans and len(contained_vlans) > 0:
            for contained_vlan in contained_vlans:
                vlan.add_vlan_to_containing_list(contained_vlan)
                logging.debug("The vlan " + str(contained_vlan) + " is contained in global vlan " + str(vlan))
            self.global_vlans.append(vlan)
        else:
            # add vlan to normal vlans, only if it is not a global
            self.vlans.append(vlan)

    def add_interface_to_vlan(self, interface):
        number_added_vlans_to_interface = 0
        added_vlans = []

        for vlan in self.vlans:
            if vlan.contains_ip(interface.ip):
                interface.set_vlan(vlan)
                number_added_vlans_to_interface += 1
                added_vlans.append(vlan)

        if number_added_vlans_to_interface == 0:
            logging.info("The ip address " + interface.ip + " can not be assigned to a vlan")
        elif number_added_vlans_to_interface > 1:
            logging.warning("The ip address " + interface.ip + " has been assigned to " + str(
                number_added_vlans_to_interface) + " vlans :" + str(added_vlans))

    def load_from_topological_input_files(self, hosts_interfaces_csv_file_path, hosts_vlans_csv_file_path=None):
        logging.info("Loading the topological information...")

        if hosts_vlans_csv_file_path:
            logging.info("[ ] Load VLANS from CSV file")

            with open(hosts_vlans_csv_file_path) as hosts_vlans_csv_file:
                hosts_vlans_csv = csv.reader(hosts_vlans_csv_file, delimiter=';')
                for hosts_vlans_line in hosts_vlans_csv:
                    if (len(hosts_vlans_line) < 3) or hosts_vlans_line[0] == "name":
                        logging.warning("Line not parsed in VLAN input file :\"" + ';'.join(hosts_vlans_line) + "\"")
                    else:
                        vlan_name = clean_vlan_name(hosts_vlans_line[0])
                        vlan_address = hosts_vlans_line[1].strip()
                        vlan_mask = hosts_vlans_line[2].strip()
                        if hosts_vlans_line[3]:
                            vlan_gateway = hosts_vlans_line[3].strip()
                        else:
                            vlan_gateway = None

                        if not vlan_name or not vlan_address or not vlan_mask:
                            logging.warning(
                                "Can't add line with parameters vlan_name=" + vlan_name + " ,vlan_address=" + vlan_address + " ,vlan_mask=" + vlan_mask)
                        else:
                            self.add_vlan(vlan_name, vlan_address, vlan_mask, vlan_gateway)

            logging.info("[X] Load VLANS from CSV file done")

        logging.info("[ ] Load hosts and interfaces CSV file")

        with open(hosts_interfaces_csv_file_path) as hosts_interfaces_csv_file:
            hosts_interfaces_csv = csv.reader(hosts_interfaces_csv_file, delimiter=';')
            for hosts_interfaces_line in hosts_interfaces_csv:
                if (len(hosts_interfaces_line) < 3) or hosts_interfaces_line[0] == "Hostname":
                    logging.warning("Line not parsed in input file :\"" + ';'.join(hosts_interfaces_line) + "\"")
                else:
                    host_name = clean_host_name(hosts_interfaces_line[0])
                    if_name = hosts_interfaces_line[1].strip()
                    ip_address = hosts_interfaces_line[2].strip()
                    connectedToWAN = hosts_interfaces_line[3].strip()
                    if len(hosts_interfaces_line) >     4  and hosts_interfaces_line[4]:
                        security_requirement = hosts_interfaces_line[4].strip()
                    else:
                        security_requirement = 0.

                    if not host_name or not if_name or not ip_address:
                        logging.warning(
                            "Can't add line with parameters host_name=" + host_name + " ,ifname=" + if_name + " ,ip_address=" + ip_address)
                    else:
                        self.add_host_or_update_existing(host_name, if_name, ip_address, connectedToWAN, security_requirement)

        for host in self.hosts:
            host.routing_table.add_default_gateway()
        logging.info("[X] Load hosts and interfaces CSV file done")

    def load_routing_file(self, csv_routing_file_path):
        if csv_routing_file_path:
            logging.info("[ ] Load routing information from CSV file")

            with open(csv_routing_file_path) as csv_routing_file:
                csv_routing = csv.reader(csv_routing_file, delimiter=';')
                for csv_routing_line in csv_routing:
                    if (len(csv_routing_line) != 5) or csv_routing_line[0] == "host":
                        logging.warning("Line not parsed in VLAN input file :\"" + ';'.join(csv_routing_line) + "\"")
                    else:
                        host_name = csv_routing_line[0]
                        destination = csv_routing_line[1]
                        mask = csv_routing_line[2]
                        gateway = csv_routing_line[3]
                        interface = csv_routing_line[4]

                        host = self.get_host_by_name(host_name)
                        if host:
                            host.routing_table.add_line(destination, mask, gateway, interface)
                        else:
                            logging.warning("Did not find in the topology a host named : " + host_name)

    def add_nessus_report_information(self, nessus_file_path):
        logging.info("Loading in memory the vulnerability database")
        vulnerability_database = load_vulnerability_database()

        logging.info("Parsing the Nessus file : " + nessus_file_path)
        tree = parse(nessus_file_path)
        root = tree.getroot()

        number_of_treated_host = 0
        number_of_added_vulnerabilities = 0

        assert isinstance(root, Element)
        # For all hosts
        for report_host in root.findall("Report/ReportHost"):
            assert isinstance(report_host, Element)
            host_name_or_ip = report_host.attrib['name']

            logging.info("Found host in Nessus report '" + host_name_or_ip + "'")
            host = self.get_host_by_ip(host_name_or_ip)
            if not host:
                logging.warning(
                    "Host '" + host_name_or_ip + "' was not found in the topology. Added it as unknown host.")
                host = self.add_unknown_host_by_ip(host_name_or_ip)

            number_of_treated_host += 1

            # Services for this host
            for report_item in report_host.findall('ReportItem'):

                assert isinstance(report_item, Element)
                port = int(report_item.attrib['port'])
                svc_name = report_item.attrib['svc_name'].lower()
                protocol = report_item.attrib['protocol'].lower()

                service = Service(svc_name, host_name_or_ip, port, protocol)

                logging.debug(
                    "Vulnerable service : '" + svc_name + "' exposed on port " + str(
                        port) + " using protocol " + protocol)

                host.add_service(service)

                #Vulnerabilities for this service
                for cve_item in report_item.findall('cve'):
                    assert isinstance(cve_item, Element)
                    cve = cve_item.text
                    service.add_vulnerability(cve, vulnerability_database)
                    number_of_added_vulnerabilities += 1

        logging.info(
            str(number_of_treated_host) + " hosts where found both in the topology and the vulnerability scan.")
        logging.info(
            str(number_of_added_vulnerabilities) + " vulnerabilities where added thanks to this vulnerability scan.")

    def to_mulval_input_file(self, mulval_input_file_path , attackerlocation_file_path):
        logging.info("Export the topology as mulval input file.")
        mulval_input_file = open(mulval_input_file_path, "w")

        attacker_csv_file = open(attackerlocation_file_path)
        host_attacker_location = csv.reader(attacker_csv_file, delimiter=';')
        host_attacker_location_line = next(host_attacker_location)
        logging.warning(host_attacker_location_line)
        ### Add Internet
        mulval_input_file.write("attackerLocated(internet_host).\n")
        mulval_input_file.write("hasIP(internet_host,'1.1.1.1').\n")
        mulval_input_file.write("defaultLocalFilteringBehavior('internet_host',allow).\n")
        mulval_input_file.write("isInVlan('1.1.1.1',internet).\n")

        ### Add all other machines
        for host in self._hosts:
            assert isinstance(host, Host)
            mulval_input_file.write("\n\n/****\n *** " + host.name + "\n ***/\n")
            hostname = host.name
            if host_attacker_location is not None:
                logging.warning("here3" + hostname)
                if any(attacker == hostname for attacker in host_attacker_location_line):
                    logging.warning("here4" + hostname)
                    mulval_input_file.write("attackerLocated('" + hostname + "').\n")
                    mulval_input_file.write("attackGoal(execCode('" + hostname + "',_)).\n")
            else:
                mulval_input_file.write("attackerLocated('" + hostname + "').\n")
                mulval_input_file.write("attackGoal(execCode('" + hostname + "',_)).\n")

            for interface in host.interfaces:
                mulval_input_file.write("hasIP('" + hostname + "','" + interface.ip + "').\n")
                if interface.vlan:
                    mulval_input_file.write("isInVlan('" + interface.ip + "','" + interface.vlan.name + "').\n")
                else:
                    logging.info(hostname + " (" + interface.ip + ") is not in any VLAN.")

            mulval_input_file.write("hostAllowAccessToAllIP('" + hostname + "').\n")

            for service in host.services:
                assert isinstance(service, Service)
                svc_name = service.name
                port = service.port
                protocol = service.protocol

                mulval_input_file.write("/* " + svc_name + " */\n")

                if port >= 0 and protocol in ["tcp", "udp", "icmp"]:
                    # svc_user = svc_name + "_user"
                    svc_user = "user"
                    mulval_input_file.write(
                        "networkServiceInfo('" + service.ip + "', '" + svc_name + "', '" + protocol.upper() + "', " + str(
                            port) + ", '" + svc_user + "').\n")

                    for vulnerability in service.vulnerabilities:
                        assert isinstance(vulnerability, Vulnerability)
                        if vulnerability.cvss.access_vector == "NETWORK":
                            mulval_input_file.write(
                                "vulProperty('" + vulnerability.cve + "', remoteExploit, privEscalation).\n")
                            mulval_input_file.write(
                                "vulExists('" + hostname + "','" + vulnerability.cve + "', '" + svc_name + "', remoteExploit, privEscalation).\n")

                        elif vulnerability.cvss.access_vector == "LOCAL":
                            mulval_input_file.write(
                                "vulProperty('" + vulnerability.cve + "', localExploit, privEscalation).\n")
                            mulval_input_file.write(
                                "vulExists('" + hostname + "','" + vulnerability.cve + "', '" + svc_name + "', localExploit, privEscalation).\n")

        if self.flow_matrix and len(self.flow_matrix.lines) > 0:
            for flow_matrix_line in self.flow_matrix.lines:

                assert isinstance(flow_matrix_line.source_element, FlowMatrixLineElement)
                assert isinstance(flow_matrix_line.destination_element, FlowMatrixLineElement)

                mulval_destination_port = ""
                if flow_matrix_line.destination_port == "any":
                    mulval_destination_port = "_"
                elif flow_matrix_line.destination_port.isdigit():
                    mulval_destination_port = flow_matrix_line.destination_port
                else:
                    logging.warning("Destination port of the flow matrix must be a integer or 'any'. Row ignored.")

                mulval_protocol = ""
                if flow_matrix_line.protocol == "any":
                    mulval_protocol = "_"
                elif flow_matrix_line.protocol.upper() in ['TCP', 'UDP', 'ICMP']:
                    mulval_protocol = "'" + flow_matrix_line.protocol.upper() + "'"
                else:
                    logging.warning("Protocol must be 'TCP', 'UDP', 'ICMP' or 'any'. Row ignored. (It is "+ str(flow_matrix_line.protocol) + ").")

                if mulval_destination_port and mulval_protocol:
                    if flow_matrix_line.source_element.type == FlowMatrixLineElement.IP and flow_matrix_line.destination_element.type == FlowMatrixLineElement.IP:
                        mulval_input_file.write(
                            "haclprimit('" + flow_matrix_line.source_element.resource + "','" + flow_matrix_line.destination_element.resource + "'," + mulval_destination_port + "," + mulval_protocol + ").\n")
                    elif flow_matrix_line.source_element.type == FlowMatrixLineElement.INTERNET and flow_matrix_line.destination_element.type == FlowMatrixLineElement.IP:
                        mulval_input_file.write(
                            "vlanToIP(internet,'" + flow_matrix_line.destination_element.resource + "'," + mulval_destination_port + "," + mulval_protocol + ").\n")
                    elif flow_matrix_line.source_element.type == FlowMatrixLineElement.VLAN and flow_matrix_line.destination_element.type == FlowMatrixLineElement.IP:
                        mulval_input_file.write(
                            "vlanToIP('" + flow_matrix_line.source_element.resource.name + "','" + flow_matrix_line.destination_element.resource + "'," + mulval_destination_port + "," + mulval_protocol + ").\n")
                    elif flow_matrix_line.source_element.type == FlowMatrixLineElement.IP and flow_matrix_line.destination_element.type == FlowMatrixLineElement.VLAN:
                        mulval_input_file.write(
                            "ipToVlan('" + flow_matrix_line.source_element.resource + "','" + flow_matrix_line.destination_element.resource.name + "'," + mulval_destination_port + "," + mulval_protocol + ").\n")
                    elif flow_matrix_line.source_element.type == FlowMatrixLineElement.INTERNET and flow_matrix_line.destination_element.type == FlowMatrixLineElement.VLAN:
                        mulval_input_file.write(
                            "vlanToVlan(internet,'" + flow_matrix_line.destination_element.resource.name + "'," + mulval_destination_port + "," + mulval_protocol + ").\n")
                    elif flow_matrix_line.source_element.type == FlowMatrixLineElement.VLAN and flow_matrix_line.destination_element.type == FlowMatrixLineElement.VLAN:
                        mulval_input_file.write(
                            "vlanToVlan('" + flow_matrix_line.source_element.resource.name + "','" + flow_matrix_line.destination_element.resource.name + "'," + mulval_destination_port + "," + mulval_protocol + ").\n")
                    elif flow_matrix_line.source_element.type == FlowMatrixLineElement.IP and flow_matrix_line.destination_element.type == FlowMatrixLineElement.INTERNET:
                        mulval_input_file.write(
                            "ipToVlan('" + flow_matrix_line.source_element.resource + "', internet," + mulval_destination_port + "," + mulval_protocol + ").\n")
                    elif flow_matrix_line.source_element.type == FlowMatrixLineElement.VLAN and flow_matrix_line.destination_element.type == FlowMatrixLineElement.INTERNET:
                        mulval_input_file.write(
                            "vlanToVlan('" + flow_matrix_line.source_element.resource.name + "', internet," + mulval_destination_port + "," + mulval_protocol + ").\n")
                else:
                    logging.warning("Unknown port or protocol : line skipped - port :" + mulval_destination_port + " - protocol : " + mulval_protocol)

        else:
            logging.info("No flow matrix has been loaded, we set authorized access between each couple of VLAN.")
            for vlan1 in self.vlans:
                for vlan2 in self.vlans:
                    if vlan1 is not vlan2:
                        mulval_input_file.write("vlanToVlan('" + vlan1.name + "','" + vlan2.name + "',_,_).\n")
        mulval_input_file.write("defaultLocalFilteringBehavior(_,allow).\n")  # local access is allowed on
        # each IP address (no interfaces have local filtering rules)


    def print_details(self):
        print("This topology contains " + str(len(self.vlans)) + " vlans and " + str(len(self.hosts)) + " hosts.")

        print("#################\n"
              "##      VLANS    \n"
              "#################\n")

        for vlan in self._vlans:
            print('-------------------------')
            print('Vlan "' + vlan.name + '"')
            print(str(vlan.network))
            print("It contains " + str(len(vlan.hosts)) + " hosts.")
            number_vulnerabilties = 0
            for host in vlan.hosts:
                number_vulnerabilties += len(host.vulnerabilities)
            print("Which totaled " + str(number_vulnerabilties) + " vulnerabilities.")

        print("########################\n"
              "##      GLOBAL VLANS    \n"
              "########################\n")

        for vlan in self.global_vlans:
            print('-------------------------')
            print('Global Vlan "' + vlan.name + '"')
            print(str(vlan.network))
            print("It contains " + str(len(vlan.contains_vlan)) + " vlans.")

        print("#################\n"
              "##      HOSTS    \n"
              "#################\n")

        for host in self._hosts:
            print('-------------------------')
            print('Host "' + host.name + '"')
            for interface in host.interfaces:
                print('\t"' + interface.name + '" : ' + interface.ip)

    def to_fiware_topology_file(self, topology_xml_file):
        xml_root = self.to_fiware_topology_xml_element()
        indent_xml(xml_root)
        ET.ElementTree(xml_root).write(topology_xml_file)

    def to_fiware_topology_xml_element(self):
        element = ET.Element('topology')

        for host in self.hosts:
            element.append(host.to_fiware_topology_xml_element())

        element.append(self.flow_matrix.to_fiware_topology_xml_element())

        return element

class VLAN:
    def __str__(self):
        return 'Vlan "' + self.name + '": ' + str(self.network)

    def __repr__(self):
        return self.__str__()

    def __init__(self, name, network, mask, gateway=None):
        self._name = name
        self._network = IPNetwork(network + "/" + mask)
        self._hosts = []
        self._interfaces = []
        self._contains_vlan = []
        self._is_contained_in_vlan = []
        self._default_gateway = gateway

    @property
    def hosts(self):
        """
        :return: List[Host] the list of hosts contained in the vlan
        """
        return self._hosts

    @property
    def interfaces(self):
        """
        :return: List|Interface] the list of network interfaces belonging to this vlan
        """
        return self._interfaces

    def add_interface(self, interface):
        if interface not in self._interfaces:
            self._interfaces.append(interface)
            self._hosts.append(interface.host)

    @property
    def name(self):
        return self._name

    @property
    def network(self):
        """
        :return: IPNetwork the network object (address + mask) related of the vlan
        """
        return self._network

    @property
    def network(self):
        return self._network

    @property
    def mask(self):
        return self.network.netmask

    @property
    def contains_vlan(self):
        return self._contains_vlan

    @property
    def is_contained_in_vlan(self):
        return self._is_contained_in_vlan

    @property
    def default_gateway(self):
        return self._default_gateway

    def add_vlan_to_containing_list(self, vlan_contained):
        if not vlan_contained in self._contains_vlan:
            self._contains_vlan.append(vlan_contained)
        vlan_contained._is_contained_in_vlan.append(self)

    def contains_ip(self, ip):
        return IPAddress(ip) in self.network

    def contains_subnet(self, network):
        return network in self.network

    def to_fiware_topology_xml_element(self):
        element = ET.Element('vlan')
        element.attrib['id'] = self.name
        element.attrib['name'] = self.name
        element.attrib['network'] = str(self.network)
        element.attrib['nbInterface'] = str(len(self.interfaces))

        hosts_element = ET.SubElement(element, 'hosts')
        for host in self.hosts:
            host_name_element = ET.SubElement(hosts_element, 'host')
            host_name_element.attrib['name'] = "#" + host.name

        interfaces_element = ET.SubElement(element, 'interfaces')

        for interface in self.interfaces:
            interface_element = ET.SubElement(interfaces_element, 'interface')
            interface_element.attrib['ip'] = "#" + interface.ip

        return element


def is_a_CIDR_network(network_to_test):
    try:
        network = IPNetwork(network_to_test)
        return network
    except ValueError:
        return None
    except AddrFormatError:
        return None


class Host:
    def __init__(self, name, first_interface_name=None, first_interface_ip=None):
        self._name = name
        self._services = []
        self._interfaces = []
        self._security_requirement = 0
        self._routing_table = RoutingTable(self)
        if first_interface_name and first_interface_ip:
            self.add_interface(first_interface_name, first_interface_ip)

    @property
    def services(self):
        return self._services

    def add_service(self, service):
        self._services.append(service)

    @property
    def routing_table(self):
        return self._routing_table

    @property
    def security_requirement(self):
        return self._security_requirement

    @property
    def interfaces(self):
        return self._interfaces

    def add_interface(self, interface_name, interface_ip):
        interface = Interface(interface_name, interface_ip, self)
        self._interfaces.append(interface)

    def get_interface_by_ip_address(self, interface_ip):
        for interface in self.interfaces:
            if interface.ip == interface_ip:
                return interface
        return None

    @property
    def vulnerabilities(self):
        vulnerabilities = {}
        for service in self.services:
            for vulnerability in service.vulnerabilities:
                vulnerabilities[vulnerability.cve] = vulnerability
        return vulnerabilities

    @property
    def name(self):
        return self._name

    def has_ip(self, host_ip):
        for interface in self.interfaces:
            if interface.ip == host_ip:
                return True
        return False

    @property
    def vlans(self):
        result = []
        for interface in self.interfaces:
            if interface.vlan not in result:
                result.append(interface.vlan)
        return result

    def to_fiware_topology_xml_element(self):
        element = ET.Element('machine')
        machine_name = ET.SubElement(element, 'name')
        machine_name.text = self.name
        security_requirement_element = ET.SubElement(element, 'security_requirement')
        security_requirement_element.text = str(self.security_requirement)

        interfaces_element = ET.SubElement(element, 'interfaces')

        for interface in self.interfaces:
            interfaces_element.append(interface.to_fiware_topology_xml_element())

        services_element = ET.SubElement(element, 'services')
        for service in self.services:
            services_element.append(service.to_fiware_topology_xml_element())

        element.append(self.routing_table.to_fiware_topology_xml_element())

        return element


class Interface:
    def __init__(self, name, ip, host):
        self._name = name
        self._ip = ip
        self._host = host
        self._vlan = None
        self._connectedToWAN = False

    @property
    def name(self):
        return self._name

    @property
    def ip(self):
        return self._ip

    @property
    def host(self):
        return self._host

    @property
    def vlan(self):
        return self._vlan

    @property
    def connected_to_wan(self):
        return self._connectedToWAN

    def set_connected_to_wan(self):
        self._connectedToWAN = True

    def set_vlan(self, vlan):
        self._vlan = vlan
        vlan.add_interface(self)

    def has_public_ip(self):
        ip = IPAddress(self.ip)
        return ip.is_unicast() and not ip.is_private()

    def to_fiware_topology_xml_element(self):
        element = ET.Element('interface')
        interface_name = ET.SubElement(element, 'name')
        interface_name.text = self.name
        interface_ip = ET.SubElement(element, 'ipaddress')
        interface_ip.text = self.ip
        if self.vlan:
            vlan_element = ET.SubElement(element, 'vlan')
            vlan_name_element = ET.SubElement(vlan_element, 'name')
            vlan_name_element.text = str(self.vlan.name)
            vlan_label_element = ET.SubElement(vlan_element, 'label')
            vlan_label_element.text = str(self.vlan.name)
        if self.connected_to_wan:
            directly_connected_element = ET.SubElement(element, 'directly-connected')
            internet_element = ET.SubElement(directly_connected_element, 'internet')

        return element


class Service:
    def __init__(self, name, ip, port, protocol):
        self._name = name
        self._ip = ip
        self._port = port
        self._protocol = protocol
        self._vulnerabilities = []

    @property
    def name(self):
        return self._name

    @property
    def vulnerabilities(self):
        """
        :return: List[Vulnerability] the list of vulnerabilities of this service
        """
        return self._vulnerabilities

    def add_vulnerability(self, vulnerability, vulnerability_database):
        topology_vulnerability = vulnerability_database.get(vulnerability)
        if topology_vulnerability:
            self._vulnerabilities.append(topology_vulnerability)
        else:
            logging.warning(
                "The vulnerability " + vulnerability + " has not been found in the vulnerability database and will be ignored.")


    @property
    def port(self):
        return self._port

    @property
    def ip(self):
        return self._ip

    @property
    def protocol(self):
        return self._protocol

    def to_fiware_topology_xml_element(self):
        element = ET.Element('service')
        service_name = ET.SubElement(element, 'name')
        service_name.text = self.name
        service_ip = ET.SubElement(element, 'ipaddress')
        service_ip.text = self.ip
        service_protocol = ET.SubElement(element, 'protocol')
        service_protocol.text = self.protocol
        service_port = ET.SubElement(element, 'port')
        service_port.text = str(self.port)

        if len(self.vulnerabilities) > 0:
            vulnerabilities_element = ET.SubElement(element, 'vulnerabilities')
            for vulnerability in self.vulnerabilities:
                vulnerability_element = ET.SubElement(vulnerabilities_element, 'vulnerability')
                access_vector = vulnerability.cvss.access_vector
                if access_vector == "LOCAL":
                    vulnerability_type = ET.SubElement(vulnerability_element, 'type')
                    vulnerability_type.text = "localExploit"
                elif access_vector == "NETWORK":
                    vulnerability_type = ET.SubElement(vulnerability_element, 'type')
                    vulnerability_type.text = "remoteExploit"
                vulnerability_cve = ET.SubElement(vulnerability_element, 'cve')
                vulnerability_cve.text = str(vulnerability.cve)
                vulnerability_goal = ET.SubElement(vulnerability_element, 'goal')
                vulnerability_goal.text = "privEscalation"
                vulnerability_cvss = ET.SubElement(vulnerability_element, 'cvss')
                vulnerability_cvss.text = str(vulnerability.cvss.score)

        return element


# Load in memory all the vulnerabilities of the vulnerability database
def load_vulnerability_database():
    vulnerability_database = {}
    database_vulnerabilities = db_session.query(Vulnerability).all()
    for database_vulnerability in database_vulnerabilities:
        vulnerability_database[database_vulnerability.cve] = database_vulnerability
    return vulnerability_database


class FlowMatrix:
    def __init__(self, topology, csv_file=None):
        assert isinstance(topology, Topology)

        self.topology = topology
        self.lines = []

        logging.info("Loading the flow matrix from CSV file")
        if csv_file:
            with open(csv_file) as flow_matrix_csv_file:
                flow_matrix_csv = csv.reader(flow_matrix_csv_file, delimiter=';')
                for flow_matrix_line in flow_matrix_csv:
                    if (len(flow_matrix_line) < 5) or flow_matrix_line[0] == "source":
                        logging.warning(
                            "Line not parsed in flow matrix input file :\"" + ';'.join(flow_matrix_line) + "\"")
                    else:
                        source = flow_matrix_line[0].strip()
                        destination = flow_matrix_line[1].strip()
                        source_port = flow_matrix_line[2].strip()
                        destination_port = flow_matrix_line[3].strip()
                        protocol = flow_matrix_line[4].strip()

                        source_element = None
                        destination_element = None

                        ########
                        # Loading source and destination elements
                        if valid_ipv4(source):
                            #source is an IP address
                            source_host = self.topology.get_host_by_ip(source)
                            if source_host:
                                source_element = FlowMatrixLineElement(FlowMatrixLineElement.IP, source)
                            else:
                                logging.warning("The source IP '" + source + "' is not one of an host of the topology.")
                        elif source == "internet":
                            #source is "internet"
                            source_element = FlowMatrixLineElement(FlowMatrixLineElement.INTERNET)
                        elif is_a_CIDR_network(source):
                            #source is a CIDR address (of a VLAN)
                            source_vlan = self.topology.get_vlan_by_cidr(source)
                            if source_vlan:
                                source_element = FlowMatrixLineElement(FlowMatrixLineElement.VLAN, source_vlan)
                            else:
                                logging.warning(
                                    "The source CIDR '" + source + "' is not one of a VLAN of the topology.")
                        else:
                            #source must be a VLAN name
                            source_vlan = self.topology.get_vlan_by_name(source)
                            if source_vlan:
                                source_element = FlowMatrixLineElement(FlowMatrixLineElement.VLAN, source_vlan)
                            else:
                                logging.warning(
                                    "The source parameter '" + source + "' has not been recognized as an IP address, nor internet nor a VLAN name of the topology")

                        if valid_ipv4(destination):
                            #destination is an IP address
                            destination_host = self.topology.get_host_by_ip(destination)
                            if destination_host:
                                destination_element = FlowMatrixLineElement(FlowMatrixLineElement.IP, destination)
                            else:
                                logging.warning(
                                    "The destination IP '" + destination + "' is not one of an host of the topology.")

                        elif destination == "internet":
                            #destination is "internet"
                            destination_element = FlowMatrixLineElement(FlowMatrixLineElement.INTERNET)
                        elif is_a_CIDR_network(destination):
                            #destination is a CIDR address (of a VLAN)
                            destination_vlan = self.topology.get_vlan_by_cidr(destination)
                            if destination_vlan:
                                destination_element = FlowMatrixLineElement(FlowMatrixLineElement.VLAN,
                                                                            destination_vlan)
                            else:
                                logging.warning(
                                    "The destination CIDR '" + destination + "' is not one of a VLAN of the topology.")
                        else:
                            #destination must be a VLAN name
                            destination_vlan = self.topology.get_vlan_by_name(destination)
                            if destination_vlan:
                                destination_element = FlowMatrixLineElement(FlowMatrixLineElement.VLAN,
                                                                            destination_vlan)
                            else:
                                logging.warning(
                                    "The destination parameter '" + destination + "' has not been recognized as an IP address, nor internet nor a VLAN name of the topology")

                        if source_element and destination_element:
                            # Both source and destination elements have been recognized.
                            # Add the tupple to the flow matrix : (source_element, destination_element, source_port, destination_port, protocol)
                            line = FlowMatrixLine(source_element, destination_element, source_port, destination_port,
                                                  protocol)
                            self.lines.append(line)
                        else:
                            logging.warning("An error occurred on the line '" + (
                                ';'.join(flow_matrix_line)) + "'. It has not been added to the flow matrix.")

            logging.info("[X] Load flow matrix from CSV file done")

    def to_fiware_topology_xml_element(self):
        element = ET.Element('flow-matrix')
        for line in self.lines:
            element.append(line.to_fiware_topology_xml_element())

        return element


class FlowMatrixLine:
    def __init__(self, source_element, destination_element, source_port, destination_port, protocol):
        self.source_element = source_element
        self.destination_element = destination_element
        self.source_port = source_port
        self.destination_port = destination_port
        self.protocol = protocol

    def to_fiware_topology_xml_element(self):
        element = ET.Element('flow-matrix-line')

        source_xml_element = ET.SubElement(element, 'source')
        source_xml_element.attrib['type'] = self.source_element.type
        if self.source_element.type == FlowMatrixLineElement.VLAN:
            source_xml_element.attrib['resource'] = self.source_element.resource.name
        elif self.source_element.type == FlowMatrixLineElement.IP:
            source_xml_element.attrib['resource'] = self.source_element.resource

        destination_xml_element = ET.SubElement(element, 'destination')
        destination_xml_element.attrib['type'] = self.destination_element.type
        if self.destination_element.type == FlowMatrixLineElement.VLAN:
            destination_xml_element.attrib['resource'] = self.destination_element.resource.name
        elif self.destination_element.type == FlowMatrixLineElement.IP:
            destination_xml_element.attrib['resource'] = self.destination_element.resource

        source_port_element = ET.SubElement(element, 'source_port')
        source_port_element.text = self.source_port

        destination_port_element = ET.SubElement(element, 'destination_port')
        destination_port_element.text = self.destination_port

        protocol_element = ET.SubElement(element, 'protocol')
        protocol_element.text = self.protocol

        return element


class FlowMatrixLineElement:
    INTERNET = "INTERNET"
    VLAN = "VLAN"
    IP = "IP"

    def __init__(self, type, ip_or_vlan=None):
        if type not in (FlowMatrixLineElement.INTERNET, FlowMatrixLineElement.VLAN, FlowMatrixLineElement.IP):
            raise AttributeError("Invalid type")

        if not ip_or_vlan and type != FlowMatrixLineElement.INTERNET:
            raise AttributeError("The ip or vlan attribute has not been given")

        self.type = type
        self.resource = None

        if type == FlowMatrixLineElement.VLAN or type == FlowMatrixLineElement.IP:
            self.resource = ip_or_vlan


class RoutingTable:
    def __init__(self, host):
        self.lines = []
        self.host = host

    def add_line(self, destination_address, mask, gateway, interface):
        new_line = RoutingTableLine(destination_address, mask, gateway, interface)
        self.lines.append(new_line)

    def add_default_gateway(self):
        if len(self.host.interfaces) == 1 and self.host.interfaces[0].vlan and self.host.interfaces[0].vlan.default_gateway:
            self.add_line("0.0.0.0", "0.0.0.0", self.host.interfaces[0].vlan.default_gateway, self.host.interfaces[0].name)

    def to_fiware_topology_xml_element(self):
        element = ET.Element('routes')
        for line in self.lines:
            element.append(line.to_fiware_topology_xml_element())
        return element


class RoutingTableLine:
    def __init__(self, destination_address, mask, gateway, interface):
        self.destination_address = destination_address
        self.mask = mask
        self.gateway = gateway
        self.interface = interface

    def to_fiware_topology_xml_element(self):
        element = ET.Element('route')

        destination_xml_element = ET.SubElement(element, 'destination')
        destination_xml_element.text = self.destination_address

        mask_xml_element = ET.SubElement(element, 'mask')
        mask_xml_element.text = self.mask

        gateway_xml_element = ET.SubElement(element, 'gateway')
        gateway_xml_element.text = self.gateway

        interface_xml_element = ET.SubElement(element, 'interface')
        interface_xml_element.text = self.interface

        return element

class PortRange:
    def __init__(self, port_range_string):
        port_range_string = port_range_string.strip().to_lower()

        match = re.search("(\d+)-(\d+)", port_range_string)

        self.from_port = 0
        self.to_port = 0
        self.any = False

        if match:
            self.from_port = int(match.group(0))
            self.to_port = int(match.group(1))
        elif port_range_string == "any":
            self._any = True
        elif port_range_string.isdigit():
            self.from_port = int(port_range_string)
            self.to_port = int(port_range_string)
        else:
            logging.warning(
                "The folowing port range string is not valid and as not been parsed so it is beeing ignored. :" + port_range_string)


def indent_xml(elem, level=0):
    i = "\n" + level * "  "
    if len(elem):
        if not elem.text or not elem.text.strip():
            elem.text = i + "  "
        if not elem.tail or not elem.tail.strip():
            elem.tail = i
        for elem in elem:
            indent_xml(elem, level + 1)
        if not elem.tail or not elem.tail.strip():
            elem.tail = i
    else:
        if level and (not elem.tail or not elem.tail.strip()):
            elem.tail = i

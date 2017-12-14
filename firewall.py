import bisect
from collections import defaultdict

class Firewall(object):
    """
    Class containing the central firewall logic. Initializes by creating a rule
    object. Provides methods to check if a packet is valid or not
    """
    def __init__(self, rule_file):
        self._rules = Rule(rule_file)

    def accept_packet(self, direction, protocol, port, ip_address):
        """
        Central method that checks if a packet will be filtered(accept/reject)
        by the Firewall

        :param direction: (string) type of traffic
        :param protocol: (string) protocol followed
        :param port: (int) port number to check
        :param ip_address: (string) ip address to check
        :return: True or False depending on whether a packet can be accepted/not
        """

        def __preconditions(direction, protocol):
            if protocol not in self._rules.get_rule(direction):
                return False
            return True

        if not __preconditions(direction, protocol):
            return False


        index = self.__is_valid_port(port, self._rules.get_port_ranges(direction, protocol))
        if index < 0:
            return False

        port_range = self._rules.get_port_ranges(direction, protocol)[index]
        ip_range = self._rules.get_rule(direction)[protocol][port_range]

        if not self.__is_valid_ip(ip_address, ip_range):
            return False

        return True

    def __is_valid_port(self, target_port, ports):
        """
        Checks if the given port is valid. Performs binary search against
        the range to find the closest start. This is followed by a check to
        see if the target port is l.t.e the range end

        :param target_port: (int) port to check
        :param ports: (List[(tuple)]) list of tuples each containing the port range
        :return: -1 if target_port doesn't satisfy the range, else valid index
        """
        INVALID = -1

        index = bisect.bisect_right(zip(*ports)[0], target_port)
        index -= 1

        # if the port range starts after the target port
        if index < 0:
            return INVALID

        # If the port range is less than the target port
        # x = [(100, 120), (10000, 20000)]
        # target = 130
        if ports[index][1] < target_port:
            return INVALID

        return index

    def __is_valid_ip(self, ip_address, ip_range):
        """
        Checks if the given ip is valid. Converts the ip string to integer
        This is followed by a binary search to find the appropriate range

        :param ip_address: (string) target ip-address
        :param ip_range: (List[(tuple)] list of tuples containing the ip ranges
        :return: True if the ip_address was found in the range else False
        """

        ip_address = int("".join(ip_address.split(".")))

        index = bisect.bisect_right(zip(*ip_range)[0], ip_address)
        index -= 1

        # print zip(*ip_range)[0], ip_address, index
        if index < 0:
            return False

        if ip_range[index][1] < ip_address:
            return False

        return True


class Rule(object):
    """

    """

    INBOUND = "inbound"
    OUTBOUND = "outbound"

    def __init__(self, input_file):
        """

        :param input_file:
        """
        self._inbound_rules = defaultdict(dict)
        self._outbound_rules = defaultdict(dict)

        self._inbound_ports = defaultdict(dict)
        self._outbound_ports = defaultdict(dict)

        with open(input_file, "r") as fr:
            for line in fr:
                line = line.strip()
                self.__create_rule(line)

    def __initialize_mapping(self, direction, protocol, port_range=None):
        """

        :param direction:
        :param protocol:
        :param port_range:
        :return:
        """
        if direction == Rule.INBOUND:
            if self._inbound_ports.get(protocol) is None:
                self._inbound_ports[protocol] = []

            if self._inbound_rules[protocol].get(port_range) is None:
                self._inbound_rules[protocol][port_range] = []
        elif direction == Rule.OUTBOUND:
            if self._outbound_ports.get(protocol) is None:
                self._outbound_ports[protocol] = []

            if self._outbound_rules[protocol].get(port_range) is None:
                self._outbound_rules[protocol][port_range] = []

    def __create_rule(self, line):
        """

        :param line:
        :return:
        """

        def __sanitize_port_range(port_range):
            port_range = map(int, port_range)
            if len(port_range) == 1:
                port_range.append(port_range[0])
            return tuple(port_range)

        def __sanitize_ip_range(ip_range):
            if len(ip_range) == 1:
                ip_range.append(ip_range[0])
            ip_range = map(lambda x: int("".join(x.split("."))), ip_range)
            return tuple(ip_range)

        direction, protocol, port, ip_addr = line.split(",")
        port_range = __sanitize_port_range(port.split("-"))
        ip_range = __sanitize_ip_range(ip_addr.split("-"))

        # Should not be called each time but for now this works
        self.__initialize_mapping(direction, protocol, port_range)

        if direction == Rule.INBOUND:
            # self._inbound_rules[protocol][port_range] = ip_range
            bisect.insort_right(self._inbound_rules[protocol][port_range], ip_range)
            bisect.insort_right(self._inbound_ports[protocol], port_range)
        elif direction == Rule.OUTBOUND:
            # self._outbound_rules[protocol][port_range] = ip_range
            bisect.insort_right(self._outbound_rules[protocol][port_range], ip_range)
            bisect.insort_right(self._outbound_ports[protocol], port_range)


    def get_port_ranges(self, direction, protocol):
        """

        :param direction: string indicating direction(inbound/outbound) traffic
        :return: list[(tuples)]: list containing port ranges as tuple, filtered by
                                 direction and protocol
        """
        if direction == Rule.INBOUND:
            return self._inbound_ports[protocol]
        elif direction == Rule.OUTBOUND:
            return self._outbound_ports[protocol]
        else:
            return None

    def get_rule(self, direction):
        """

        :param direction: string indicating direction(inbound/outbound) traffic
        :return: rule map (dict) inbound/outbound rule mapping
        """
        if direction == Rule.INBOUND:
            return self._inbound_rules
        elif direction == Rule.OUTBOUND:
            return self._outbound_rules
        else:
            return None


if __name__ == "__main__":
    firewall = Firewall("firewall_rules.csv")

    # print firewall._rules.get_rule("inbound")
    print firewall.accept_packet("inbound", "tcp", 80, "192.168.1.2")
    print firewall.accept_packet("inbound", "udp", 53, "192.168.2.1")
    print firewall.accept_packet("outbound", "tcp", 10234, "192.168.10.11")

    print firewall.accept_packet("inbound", "tcp", 81, "192.168.1.2")
    print firewall.accept_packet("inbound", "udp", 24, "52.12.48.92")


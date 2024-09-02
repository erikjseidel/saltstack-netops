# Copyright 2016 Dravetech AB. All rights reserved.
#
# The contents of this file are licensed under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with the
# License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.

"""
Napalm driver for VyOS.

Read napalm.readthedocs.org for more information.


"""

import re
import os

from netaddr import IPAddress
import vyattaconfparser

from napalm_vyos.utils.vyos_api import (
    VyosAPI,
    VyosAPIException,
)

from netmiko import __version__ as netmiko_version

# NAPALM base
import napalm.base.constants as C
from napalm.base.base import NetworkDriver
from napalm.base.exceptions import (
    NapalmException,
    MergeConfigException,
    ReplaceConfigException,
    CommitError,
    CommandErrorException,
)


class VyOSDriver(NetworkDriver):

    _MINUTE_SECONDS = 60
    _HOUR_SECONDS = 60 * _MINUTE_SECONDS
    _DAY_SECONDS = 24 * _HOUR_SECONDS
    _WEEK_SECONDS = 7 * _DAY_SECONDS
    _YEAR_SECONDS = 365 * _DAY_SECONDS
    _DEST_FILENAME = "/var/tmp/candidate_running.conf"
    _BACKUP_FILENAME = "/var/tmp/backup_running.conf"
    _BOOT_FILENAME = "/config/config.boot"

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.timeout = timeout

        self.optional_args = optional_args if optional_args else {}
        self.api_port = self.optional_args.pop("api_port", 8443)
        self.api_key = self.optional_args.pop("api_key", self.password)
        self.tls_verify = self.optional_args.pop("tls_verify", False)

        self.device = VyosAPI(
            host=self.hostname,
            port=self.api_port,
            key=self.api_key,
            verify=self.tls_verify,
        )

        self._scp_client = None
        self._new_config = None
        self._old_config = None
        self._ssh_usekeys = False

        # Netmiko possible arguments
        netmiko_argument_map = {
            'port': None,
            'secret': '',
            'verbose': False,
            'global_delay_factor': 1,
            'use_keys': False,
            'key_file': None,
            'ssh_strict': False,
            'system_host_keys': False,
            'alt_host_keys': False,
            'alt_key_file': '',
            'ssh_config_file': None,
        }

        fields = netmiko_version.split('.')
        fields = [int(x) for x in fields]
        maj_ver, min_ver, _ = fields

        if maj_ver >= 2:
            netmiko_argument_map['allow_agent'] = False
        elif maj_ver == 1 and min_ver >= 1:
            netmiko_argument_map['allow_agent'] = False

        # Build dict of any optional Netmiko args
        self.netmiko_optional_args = {}
        if optional_args is not None:
            for k, _ in netmiko_argument_map.items():
                try:
                    self.netmiko_optional_args[k] = optional_args[k]
                except KeyError:
                    pass
            self.global_delay_factor = optional_args.get('global_delay_factor', 1)
            self.port = optional_args.get('port', 22)

    def _reset(self):
        """
        Clear any pending merge candidate configuration that may exist

        """
        self.device.reset_merge_candidate()

    def open(self):
        """
        Open a connection to the device. As Vyos API is stateless the connection can
        always be considered 'open' we simply clear any pending merge candidate here.

        """
        self._reset()

    def close(self):
        """
        Close a connection to the device. As Vyos API is stateless the connection can
        always be considered 'open' we simply clear any pending merge candidate here.

        """
        self._reset()

    def load_merge_candidate(self, filename=None, config=None):
        """
        Only configuration in set-format is supported with load_merge_candidate.
        """
        if filename is None:
            if not config:
                raise MergeConfigException('filename or config param must be provided.')

            cfg = [x for x in config.split("\n") if x]

        elif os.path.exists(filename) is True:
            with open(filename, encoding="utf-8") as f:
                cfg = [x for x in f.read().split("\n") if x]

        else:
            raise MergeConfigException(f"config file {filename} is not found")

        self.device.add_config_set(cfg)

    def discard_config(self):
        """
        Discard merge candidate configuration

        """
        self._reset()

    def compare_config(self):
        """
        Compare a merge candidate configuration to the device's running configuration

        """
        try:
            output_compare = self.device.compare()
        except VyosAPIException as e:
            self._reset()
            raise CommitError(e.message) from e

        match = re.findall(
            "No changes between working and active configurations", output_compare
        )
        if match:
            return ""

        diff = ''.join(output_compare.splitlines(True))
        return diff or ""

    def commit_config(self, message=""):
        """
        Commit a candidate configuration to the device

        """
        if message:
            raise NotImplementedError(
                "Commit message not implemented for this platform"
            )

        if not self.device.merge_candidate:
            # Nothing to commit.
            return

        try:
            self.device.save(self._BACKUP_FILENAME)

            self.device.commit()
            self.device.save()

        except VyosAPIException as e:
            raise CommitError(e.message) from e

    def rollback(self):
        """Rollback configuration to filename or to self.rollback_cfg file."""
        filename = None
        if filename is None:
            filename = self._BACKUP_FILENAME

            try:
                self.device.load(filename)
            except VyosAPIException as e:
                raise ReplaceConfigException(
                    "Failed rollback config: " + e.message
                ) from e

    def get_environment(self):
        """
        Return a dict containing certain device environmental information

        """

        #
        #  'vmstat' output:
        #  procs -----------memory---------- ---swap-- -----io---- -system-- ----cpu----
        #  r  b   swpd   free   buff  cache   si   so    bi    bo   in   cs us sy id wa
        #  0  0      0  61404 139624 139360    0    0     0     0    9   14  0  0 100  0
        #
        output_cpu_list = []
        output_cpu = self.device.send_command("vmstat")
        output_cpu = str(output_cpu)
        output_cpu_list = output_cpu.split("\n")
        output_cpu_list = (
            output_cpu_list[-1] if len(output_cpu_list[-1]) > 0 else output_cpu_list[-2]
        )
        output_cpu_idle = output_cpu_list.split()[-2]

        cpu = 100 - int(output_cpu_idle)

        #
        #  'free' output:
        #               total       used       free     shared    buffers     cached
        #  Mem:        508156     446784      61372          0     139624     139360
        #  -/+ buffers/cache:     167800     340356
        #  Swap:            0          0          0
        #
        output_ram = self.device.send_command("free").split("\n")[1]
        available_ram, used_ram = output_ram.split()[1:3]

        environment = {
            "fans": {"invalid": {"status": False}},
            "temperature": {
                "invalid": {"temperature": 0.0, "is_alert": False, "is_critical": False}
            },
            "power": {"invalid": {"status": True, "capacity": 0.0, "output": 0.0}},
            "cpu": {
                "0": {"%usage": float(cpu)},
            },
            "memory": {"available_ram": int(available_ram), "used_ram": int(used_ram)},
        }

        return environment

    def get_interfaces(self):
        """
        "show interfaces" output example:
        Interface        IP Address                        S/L  Description
        ---------        ----------                        ---  -----------
        br0              -                                 u/D
        eth0             192.168.1.1/24                   u/u  Management
        eth1             192.168.1.2/24                    u/u
        eth2             192.168.3.1/24                    u/u  foobar
                         192.168.2.2/24
        lo               127.0.0.1/8                       u/u
                         ::1/128
        """
        output_iface = self.device.send_command("show interfaces summary")

        # Collect all interfaces' name and status
        match = re.findall(r"(\S+)\s+[:\-\d/\.]+\s+([uAD])/([uAD])", output_iface)

        # 'match' example:
        # [("br0", "u", "D"), ("eth0", "u", "u"), ("eth1", "u", "u")...]
        iface_state = {
            iface_name: {"State": state, "Link": link}
            for iface_name, state, link in match
        }

        output_conf = self.device.send_command("show configuration")

        # Convert the configuration to dictionary
        config = vyattaconfparser.parse_conf(output_conf)

        iface_dict = {}

        for iface_type in config["interfaces"]:

            ifaces_detail = config["interfaces"][iface_type]

            for iface_name in ifaces_detail:
                details = ifaces_detail[iface_name]
                description = details.get("description", "")
                speed = details.get("speed", "0")
                if speed == "auto":
                    speed = 0
                hw_id = details.get("hw-id", "00:00:00:00:00:00")

                is_up = iface_state[iface_name]["Link"] == "u"
                is_enabled = iface_state[iface_name]["State"] == "u"

                iface_dict.update(
                    {
                        iface_name: {
                            "is_up": bool(is_up),
                            "is_enabled": bool(is_enabled),
                            "description": description,
                            "last_flapped": float(-1),
                            "mtu": -1,
                            "speed": int(speed),
                            "mac_address": hw_id,
                        }
                    }
                )

        return iface_dict

    def get_arp_table(self, vrf=""):
        # 'age' is not implemented yet

        """
        'show arp' output example:
        Address                  HWtype  HWaddress           Flags Mask            Iface
        10.129.2.254             ether   00:50:56:97:af:b1   C                     eth0
        192.168.1.134                    (incomplete)                              eth1
        192.168.1.1              ether   00:50:56:ba:26:7f   C                     eth1
        10.129.2.97              ether   00:50:56:9f:64:09   C                     eth0
        192.168.1.3              ether   00:50:56:86:7b:06   C                     eth1
        """

        if vrf:
            raise NotImplementedError(
                "VRF support has not been added for this getter on this platform."
            )

        output = self.device.send_command("show arp")
        output = output.split("\n")

        # Skip the header line
        output = output[1:-1]

        arp_table = []
        for line in output:

            line = line.split()
            # 'line' example:
            # ["10.129.2.254", "ether", "00:50:56:97:af:b1", "C", "eth0"]
            # [u'10.0.12.33', u'(incomplete)', u'eth1']
            if "incomplete" in line[1]:
                macaddr = "00:00:00:00:00:00"
            else:
                macaddr = line[2]

            arp_table.append(
                {
                    'interface': line[-1],
                    'mac': macaddr,
                    'ip': line[0],
                    'age': 0.0,
                }
            )

        return arp_table

    def get_bgp_neighbors(self):
        # 'description', 'sent_prefixes' and 'received_prefixes' are not implemented yet

        """
        'show ip bgp summary' output example:
        BGP router identifier 192.168.1.2, local AS number 64520
        IPv4 Unicast - max multipaths: ebgp 1 ibgp 1
        RIB entries 3, using 288 bytes of memory
        Peers 3, using 13 KiB of memory

        Neighbor        V    AS MsgRcvd MsgSent   TblVer  InQ OutQ Up/Down  State/PfxRcd
        192.168.1.1     4 64519    7226    7189        0    0    0 4d23h40m        1
        192.168.1.3     4 64521    7132    7103        0    0    0 4d21h05m        0
        192.168.1.4     4 64522       0       0        0    0    0 never    Active
        """

        output = self.device.send_command("show ip bgp summary")
        output = output.split("\n")

        match = re.search(
            r".* router identifier (\d+\.\d+\.\d+\.\d+), local AS number (\d+)",
            output[0],
        )
        if not match:
            return {}
        router_id = match.group(1)
        local_as = int(match.group(2))

        bgp_neighbor_data = {'global': {}}
        bgp_neighbor_data["global"]["router_id"] = router_id
        bgp_neighbor_data["global"]["peers"] = {}

        # delete the header and empty element
        bgp_info = [i.strip() for i in output[6:-2] if i]

        for i in bgp_info:
            if len(i) > 0:
                (
                    peer_id,
                    bgp_version,
                    remote_as,
                    _,  # msg_rcvd
                    _,  # msg_sent
                    _,  # table_version
                    _,  # in_queue
                    _,  # out_queue
                    up_time,
                    state_prefix,
                ) = i.split()

                is_enabled = "(Admin)" not in state_prefix

                received_prefixes = None

                try:
                    state_prefix = int(state_prefix)
                    received_prefixes = int(state_prefix)
                    is_up = True
                except ValueError:
                    state_prefix = -1
                    received_prefixes = -1
                    is_up = False

                if bgp_version not in ["4", "6"]:
                    raise ValueError("BGP neighbor parsing failed")

                #
                #  'show ip bgp neighbors 192.168.1.1' output example:
                #  BGP neighbor is 192.168.1.1, remote AS 64519, local AS 64520, external link
                #  BGP version 4, remote router ID 192.168.1.1
                #  For address family: IPv4 Unicast
                #  ~~~
                #  Community attribute sent to this neighbor(both)
                #  1 accepted prefixes
                #  ~~~
                #
                bgp_detail = self.device.send_command(
                    "show ip bgp neighbors %s" % peer_id
                )

                match_rid = re.search(
                    r"remote router ID (\d+\.\d+\.\d+\.\d+).*", bgp_detail
                )
                remote_rid = match_rid.group(1)

                match_prefix_accepted = re.search(
                    r"(\d+) accepted prefixes", bgp_detail
                )
                accepted_prefixes = match_prefix_accepted.group(1)

                bgp_neighbor_data["global"]["peers"].setdefault(peer_id, {})
                peer_dict = {
                    "description": "",
                    "is_enabled": bool(is_enabled),
                    "local_as": int(local_as),
                    "is_up": bool(is_up),
                    "remote_id": remote_rid,
                    "uptime": int(self._bgp_time_conversion(up_time)),
                    "remote_as": int(remote_as),
                }

                af_dict = {
                    'address_family': {
                        "sent_prefixes": int(-1),
                        "accepted_prefixes": int(accepted_prefixes),
                        "received_prefixes": int(received_prefixes),
                    }
                }

                peer_dict["address_family"] = af_dict
                bgp_neighbor_data["global"]["peers"][peer_id] = peer_dict

        return bgp_neighbor_data

    def _bgp_time_conversion(self, bgp_uptime):
        # uptime_letters = set(["y", "w", "h", "d"])

        if "never" in bgp_uptime:
            return -1

        if "y" in bgp_uptime:
            match = re.search(r"(\d+)(\w)(\d+)(\w)(\d+)(\w)", bgp_uptime)
            uptime = (
                (int(match.group(1)) * self._YEAR_SECONDS)
                + (int(match.group(3)) * self._WEEK_SECONDS)
                + (int(match.group(5)) * self._DAY_SECONDS)
            )

        elif "w" in bgp_uptime:
            match = re.search(r"(\d+)(\w)(\d+)(\w)(\d+)(\w)", bgp_uptime)
            uptime = (
                (int(match.group(1)) * self._WEEK_SECONDS)
                + (int(match.group(3)) * self._DAY_SECONDS)
                + (int(match.group(5)) * self._HOUR_SECONDS)
            )

        elif "d" in bgp_uptime:
            match = re.search(r"(\d+)(\w)(\d+)(\w)(\d+)(\w)", bgp_uptime)
            uptime = (
                (int(match.group(1)) * self._DAY_SECONDS)
                + (int(match.group(3)) * self._HOUR_SECONDS)
                + (int(match.group(5)) * self._MINUTE_SECONDS)
            )

        else:
            hours, minutes, seconds = map(int, bgp_uptime.split(":"))
            uptime = (
                (hours * self._HOUR_SECONDS)
                + (minutes * self._MINUTE_SECONDS)
                + seconds
            )

        return uptime

    def get_lldp_neighbors(self):
        """
        Return a dict containing information about device's LLDP neighbors

        """
        # Multiple neighbors per port are not implemented
        # The show lldp neighbors commands lists port descriptions, not IDs
        output = self.device.send_command("show lldp neighbors detail")
        pattern = r'''(?s)Interface: +(?P<interface>\S+), [^\n]+
.+?
 +SysName: +(?P<hostname>\S+)
.+?
 +PortID: +ifname (?P<port>\S+)'''

        def _get_interface(match):
            return [
                {
                    'hostname': match.group('hostname'),
                    'port': match.group('port'),
                }
            ]

        return {
            match.group('interface'): _get_interface(match)
            for match in re.finditer(pattern, output)
        }

    def get_interfaces_counters(self):
        # 'rx_unicast_packet', 'rx_broadcast_packets', 'tx_unicast_packets',
        # 'tx_multicast_packets' and 'tx_broadcast_packets' are not implemented yet

        """
        'show interfaces detail' output example:
        eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state
        UP group default qlen 1000
        link/ether 00:50:56:86:8c:26 brd ff:ff:ff:ff:ff:ff
        ~~~
        RX:  bytes    packets     errors    dropped    overrun      mcast
          35960043     464584          0        221          0        407
        TX:  bytes    packets     errors    dropped    carrier collisions
          32776498     279273          0          0          0          0
        """
        output = self.device.send_command("show interfaces detail")
        interfaces = re.findall(r"(\S+): <.*", output)
        # count = re.findall("(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+", output)
        count = re.findall(r"(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)", output)
        counters = {}

        j = 0

        for i in count:
            if j % 2 == 0:
                rx_errors = i[2]
                rx_discards = i[3]
                rx_octets = i[0]
                rx_unicast_packets = i[1]
                rx_multicast_packets = i[5]
                rx_broadcast_packets = -1
            else:
                counters.update(
                    {
                        interfaces[j // 2]: {
                            "tx_errors": int(i[2]),
                            "tx_discards": int(i[3]),
                            "tx_octets": int(i[0]),
                            "tx_unicast_packets": int(i[1]),
                            "tx_multicast_packets": int(-1),
                            "tx_broadcast_packets": int(-1),
                            "rx_errors": int(rx_errors),
                            "rx_discards": int(rx_discards),
                            "rx_octets": int(rx_octets),
                            "rx_unicast_packets": int(rx_unicast_packets),
                            "rx_multicast_packets": int(rx_multicast_packets),
                            "rx_broadcast_packets": int(rx_broadcast_packets),
                        }
                    }
                )
            j += 1

        return counters

    def get_snmp_information(self):
        """
        Return a dict containing device SNMP configuration. ACL not implemented.

        """

        output = self.device.send_command("show configuration")
        # convert the configuration to dictionary
        config = vyattaconfparser.parse_conf(output)

        snmp = {'community': {}}

        try:
            for i in config["service"]["snmp"]["community"]:
                snmp["community"].update(
                    {
                        i: {
                            "acl": "",
                            "mode": config["service"]["snmp"]["community"][i][
                                "authorization"
                            ],
                        }
                    }
                )

            snmp.update(
                {
                    "chassis_id": "",
                    "contact": config["service"]["snmp"]["contact"],
                    "location": config["service"]["snmp"]["location"],
                }
            )

            return snmp
        except KeyError:
            return {}

    def get_facts(self):
        """
        Return a dict containing basic information about the device

        """
        output_uptime = self.device.send_command("cat /proc/uptime | awk '{print $1}'")

        uptime = int(float(output_uptime.split()[0]))

        output = self.device.send_command("show version").split("\n")
        ver_str = [line for line in output if "Version" in line][0]
        version = self.parse_version(ver_str)

        sn_str = [line for line in output if "Hardware S/N" in line][0]
        hwmodel_str = [line for line in output if "Hardware model" in line][0]

        snumber = self.parse_snumber(sn_str)
        hwmodel = self.parse_hwmodel(hwmodel_str)

        output = self.device.send_command("show configuration")
        config = vyattaconfparser.parse_conf(output)

        if "host-name" in config["system"]:
            hostname = config["system"]["host-name"]
        else:
            hostname = None

        if "domain-name" in config["system"]:
            fqdn = config["system"]["domain-name"]
        else:
            fqdn = ""

        iface_list = []
        for iface_type in config["interfaces"]:
            for iface_name in config["interfaces"][iface_type]:
                iface_list.append(iface_name)

        facts = {
            "uptime": int(uptime),
            "vendor": "VyOS",
            "os_version": version,
            "serial_number": snumber,
            "model": hwmodel,
            "hostname": hostname,
            "fqdn": fqdn,
            "interface_list": iface_list,
        }

        return facts

    @staticmethod
    def parse_version(ver_str):
        """
        Parse the device version string
        """
        version = ver_str.split()[-1]
        return version

    @staticmethod
    def parse_snumber(sn_str):
        """
        Parse the device Serial Number string
        """
        sn = sn_str.split(":")
        return sn[1].strip()

    @staticmethod
    def parse_hwmodel(model_str):
        """
        Parse the device Hardware Model string
        """
        model = model_str.split(":")
        return model[1].strip()

    def get_interfaces_ip(self):
        """
        Get IP addresses assigned to device interfaces
        """
        output = self.device.send_command("show interfaces")
        output = output.split("\n")

        # delete the header line and the interfaces which has no ip address
        if len(output[-1]) > 0:
            ifaces = [x for x in output[3:] if "-" not in x]
        else:
            ifaces = [x for x in output[3:-1] if "-" not in x]

        ifaces_ip = {}

        for iface in ifaces:
            iface = iface.split()
            if len(iface) != 1:

                iface_name = iface[0]

                # Delete the "Interface" column
                iface = iface[1:-1]
                # Key initialization
                ifaces_ip[iface_name] = {}

            ip_addr, mask = iface[0].split("/")
            ip_ver = self._get_ip_version(ip_addr)

            # Key initialization
            if ip_ver not in ifaces_ip[iface_name]:
                ifaces_ip[iface_name][ip_ver] = {}

            ifaces_ip[iface_name][ip_ver][ip_addr] = {"prefix_length": int(mask)}

        return ifaces_ip

    @staticmethod
    def _get_ip_version(ip_address):
        return "ipv" + int(IPAddress(ip_address).version)

    def get_users(self):
        """
        Get the system users

        """
        output = self.device.send_command("show configuration commands").split("\n")

        user_conf = [x.split() for x in output if "login user" in x]

        # Collect all users' name
        user_name = [x[4] for x in user_conf]

        user_auth = {}

        for user in user_name:
            sshkeys = []
            password = ""

            # extract the configuration which relates to 'user'
            for line in [x for x in user_conf if user in x]:

                # "set system login user alice authentication encrypted-password 'abc'"
                if line[6] == "encrypted-password":
                    password = line[7].strip("'")

                # "set system login user alice authentication public-keys
                # alice@example.com key 'ABC'"
                elif len(line) == 10 and line[8] == "key":
                    sshkeys.append(line[9].strip("'"))

            user_auth.update({user: {"password": password, "sshkeys": sshkeys}})

        return user_auth

    def ping(
        self,
        destination,
        source=C.PING_SOURCE,
        ttl=C.PING_TTL,
        timeout=C.PING_TIMEOUT,
        size=C.PING_SIZE,
        count=C.PING_COUNT,
        vrf=C.PING_VRF,
    ):
        """
        Run a ping command on the device. Does not support multiple destinations.

        Arguments

            destination:
               Target host to ping

            source:
               Source IP address to use

            ttl:
               Set a Time-To-Live constraint on the ping

            timeout:
               Set a timeout constraint on the ping

            size:
               Set the size of the echo request packet

            count:
               Number of echo request packets to send

            vrf:
               Originate packets from a vrf

        """
        deadline = timeout * count

        command = "ping %s " % destination
        command += "ttl %d " % ttl
        command += "deadline %d " % deadline
        command += "size %d " % size
        command += "count %d " % count
        if source != "":
            command += "interface %s " % source

        ping_result = {}
        output_ping = self.device.send_command(command)

        if "Unknown host" in output_ping:
            err = "Unknown host"
        else:
            err = ""

        if err:
            ping_result["error"] = err
        else:
            # 'packet_info' example:
            # ['5', 'packets', 'transmitted,' '5', 'received,' '0%', 'packet',
            # 'loss,', 'time', '3997ms']
            packet_info = output_ping.split("\n")

            if len(packet_info[-1]) > 0:
                packet_info = packet_info[-2]
            else:
                packet_info = packet_info[-3]

            packet_info = [x.strip() for x in packet_info.split()]

            sent = int(packet_info[0])
            received = int(packet_info[3])
            lost = sent - received

            # 'rtt_info' example:
            # ["0.307/0.396/0.480/0.061"]
            rtt_info = output_ping.split("\n")

            if len(rtt_info[-1]) > 0:
                rtt_info = rtt_info[-1]
            else:
                rtt_info = rtt_info[-2]

            match = re.search(r"([\d\.]+)/([\d\.]+)/([\d\.]+)/([\d\.]+)", rtt_info)

            if match is not None:
                rtt_min = float(match.group(1))
                rtt_avg = float(match.group(2))
                rtt_max = float(match.group(3))
                rtt_stddev = float(match.group(4))
            else:
                rtt_min = None
                rtt_avg = None
                rtt_max = None
                rtt_stddev = None

            ping_result["success"] = {
                "probes_sent": sent,
                "packet_loss": lost,
                "rtt_min": rtt_min,
                "rtt_max": rtt_max,
                "rtt_avg": rtt_avg,
                "rtt_stddev": rtt_stddev,
                "results": [{"ip_address": destination, "rtt": rtt_avg}],
            }

        return ping_result

    def get_config(self, retrieve="all", full=False, sanitized=False):
        """
        Return the configuration of a device.
        :param retrieve: String to determine which configuration type you want to retrieve, default is all of them.
                              The rest will be set to "".
        :param full: Boolean to retrieve all the configuration. (Not supported)
        :param sanitized: Boolean to remove secret data. (Only supported for 'running')
        :return: The object returned is a dictionary with a key for each configuration store:
            - running(string) - Representation of the native running configuration
            - candidate(string) - Representation of the candidate configuration.
            - startup(string) - Representation of the native startup configuration.
        """
        if retrieve not in ["running", "candidate", "startup", "all"]:
            raise NapalmException(
                "ERROR: Not a valid option to retrieve.\nPlease select from 'running', 'candidate', "
                "'startup', or 'all'"
            )

        config_dict = {"running": "", "startup": "", "candidate": ""}
        if retrieve in ["running", "all"]:
            config_dict['running'] = self._get_running_config()
        if retrieve in ["startup", "all"]:
            config_dict['startup'] = self.device.send_command(
                f"cat {self._BOOT_FILENAME}"
            )
        if retrieve in ["candidate", "all"]:
            config_dict['candidate'] = self._new_config or ""

        return config_dict

    def _get_running_config(self):
        try:
            return self.device.send_command("show configuration")
        except VyosAPIException as e:
            return e.message

    def get_vyos_config(self, path=None):
        """
        Get configuration data from the device by path

        Arguments

            path: ``None``
                What part of the configuration hierarchy to retrieve. Will retrieve entire
                device configuration if set to None or [].

        """
        path = path or []

        try:
            return self.device.retrieve(path)
        except VyosAPIException as e:
            raise CommandErrorException(e.message) from e

    def cli(self, commands):
        """
        Execute a list of commands and return the output in a dictionary format using the command
        as the key.

        Example input:
        ['show clock', 'show calendar']

        Output example:
        {   'show calendar': u'22:02:01 UTC Thu Feb 18 2016',
            'show clock': u'*22:01:51.165 UTC Thu Feb 18 2016'}

        """
        cli_output = {}
        if not isinstance(commands, list):
            raise TypeError("Please enter a valid list of commands!")

        for command in commands:
            output = self.device.send_command(command)
            cli_output.setdefault(command, {})
            cli_output[command] = output

        return cli_output

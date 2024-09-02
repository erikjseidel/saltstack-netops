from typing import Optional, Union
import re
import warnings
import requests

from beartype.typing import List
from beartype import beartype

# We use unauthenticated connections internally.
warnings.filterwarnings("ignore")


class VyosAPIException(Exception):
    def __init__(self, message: str):
        self.message = message


@beartype
class VyosAPI:

    # VyosAPI class ops to Vyos Router API mapper
    API_ENDPOINTS = {
        'compare': 'configure-compare',
        'commit': 'configure',
        'file': 'config-file',
        'retrieve': 'retrieve',
        'run': 'run',
    }

    #
    # Used to properly format config string to a  Vyos router API config
    # op list.
    #
    PATH_SPLIT_REGEX = r'\s+(?=(?:"[^"]*"|[^"])*$)(?=(?:\'[^\']*\'|[^\'])*$)'

    #
    # Merge candidate config lines stored client side and then sent
    # as one operation when config commit or config compare called.
    # Initialized at object instantiation time.
    #
    merge_candidate: Optional[List[dict]] = None

    def __init__(
        self, host: str, port: int, key: str, tls: bool = True, verify: bool = True
    ):
        """
        Intialize a new VyosAPI object. VyosAPI provides an interface which
        Napalm Vyos driver can use to interact with the ZNSL customized
        Vyos 1.4 API which includes config compare and operational command
        support.

        Arguments:

            host: str
                The FQDN or IP address of the target Vyos device

            port: int
                The port on which the device's API is listening

            key: str
                The key string used to authenticate against the device API

            tls: bool ``True``
                Whether to use TLS (HTTPS) when connecting to the device

            verify: bool ``True``
                If false, unverified HTTPS connections are allowed

        """
        schema = 'https' if tls else 'http'

        self.url_base = f'{schema}://{host}:{port}/'

        self.key = key
        self.verify = verify

        self.merge_candidate = []

    def _make_config_statement(self, cmd: str) -> dict:
        """
        Converts a config string into a Vyos router API Op format. Op format
        is as follows:

            {
                'op':     The configuration operation (e.g. 'set', 'delete')

                'path':   A list representing the location of the targer config value
                          in the hierarchy (e.g. ['protocols', 'bgp', 'neighbor']

                'value':  A string containing the target value (if exists). In case
                          of certain ops (such as 'delete') a value may not be
                          present.
             }

        Arguments:

            cmd: str
                The configuration command line in string format

        Returns:

            A dict containing the final config Op command as described above

        """
        elements = re.split(self.PATH_SPLIT_REGEX, cmd)

        op = elements.pop(0)
        value = None
        if op != 'delete':
            try:
                last = elements.pop()
            except IndexError as exc:
                raise VyosAPIException(
                    f'Invalid statement: {cmd}\n\nA value is required.'
                ) from exc

            value = str(last).strip('"').strip('\'')

        path = elements
        if len(path) == 0:
            raise VyosAPIException(f'Invalid statement: {cmd}\n\nA path is required.')

        out = {'op': op, 'path': path}
        if value:
            out['value'] = value

        return out

    def _send_request(self, url, data: Optional[dict] = None) -> dict:
        """
        Sends properly structured HTTP request to the device Vyos router API.

        Arguments:

            data: ``None``
                Optional dict containing data to be sent to the device

        Returns:

            Device's JSON responce in dict format

        """
        payload = {
            'key': self.key,
        }

        if data:
            payload.update(data)

        headers = {}

        response = requests.request(
            "POST", url, headers=headers, json=payload, verify=self.verify
        )

        return response.json()

    def _compare_commit(self, endpoint: str) -> str:
        """
        Send a commit config or compare merge candidate to running config
        on the Vyos device. Compare merge candidate op requires the device
        to support the Vyos 1.4 extended API.

        Arguments:

            endpoint:
                One of 'commit' to commit config  or 'compare' to comparee
                merge candidate to target device's running config

        Returns:

            A string containing the result from the device

        """
        url = self.url_base + self.API_ENDPOINTS[endpoint]

        data = {'commands': self.merge_candidate}

        ret = self._send_request(url, data)

        if not ret['success']:
            raise VyosAPIException(ret['error'])

        return ret['data'] or ''

    def _file(self, op: str, file: Optional[str]) -> str:
        """
        Send file ops to the target Vyos device.

        Arguments:

            op: str
                File operation to run (e.g. 'save', 'load')

            file: str
                Path of file on the target device

        """
        url = self.url_base + self.API_ENDPOINTS['file']
        data = {'op': op}

        if file:
            data['file'] = file

        ret = self._send_request(url, data)

        if not ret['success']:
            raise VyosAPIException(ret['error'])

        return ret['data'] or ''

    def reset_merge_candidate(self):
        """
        Clear the merge candidate. Used to clear merge candidate after it's
        been committed to the device or otherwise discard a merge candidate
        in anticipation of a new candidate.

        """
        self.merge_candidate = []

    def add_config_set(self, cmds: Union[str, List[str]]):
        """
        Add a config line or multiple config lines to the merge candidate.

        Arguments:

            cmds: str | List[str]
                Config line strings to be added to the merge candidate

        """
        if not isinstance(cmds, list):
            cmds = [cmds]

        for cmd in cmds:
            statement = self._make_config_statement(cmd)
            self.merge_candidate.append(statement)

    def compare(self):
        """
        Compare merge candidate to running config on the Vyos device. Compare
        merge candidate op requires the device to support the Vyos 1.4
        extended API.

        Returns:

            A string containing the config diff from the device

        """
        return self._compare_commit('compare')

    def commit(self):
        """
        Commit merge candidate to running config on the Vyos device. Compare
        merge candidate op requires the device to support the Vyos 1.4
        extended API.

        Returns:

            A string containing the config diff from the device

        """
        ret = self._compare_commit('commit')
        self.reset_merge_candidate()
        return ret

    def save(self, file: Optional[str] = None) -> str:
        """
        Save running config on the target Vyos device to file identifed by
        file argument

        Arguments:

            file: str ``None``
                Path of target file on the target device. In case of None
                the default saved config file will be used.

        """
        return self._file('save', file)

    def load(self, file: Optional[str] = None) -> str:
        """
        Replace running config on the target Vyos device with that found in
        configuration file.

        Arguments:

            file: str
                Path of target file on the target device

        """
        return self._file('load', file)

    def retrieve(self, path: Optional[List[str]] = None) -> dict:
        """
        Retrieve parts of the configuration from the Vyos device.

        Arguments:

            path: List[str]
                An optional path list identifying part of configuration
                to retrieve

        """
        path = path or []

        url = self.url_base + self.API_ENDPOINTS['retrieve']

        data = {'op': 'showConfig', 'path': path}

        ret = self._send_request(url, data)

        if not ret['success']:
            raise VyosAPIException(ret['error'])

        return ret['data'] or {}

    def send_command(self, cmd: str):
        """
        Send an operational command to the Vyos device. This method
        requires that the Vyos device supports the Vyos 1.4 extended
        config API.

        cmd: str
            Operational command to run

        """
        url = self.url_base + self.API_ENDPOINTS['run']

        data = {'commands': [cmd]}

        ret = self._send_request(url, data)

        if not ret['success']:
            return ret['error']

        return ret['data'] or ''

import requests, json, re
import warnings

# We use unauthenticated connections internally.
warnings.filterwarnings("ignore")

API_ENDPOINTS = {
    'compare': 'configure-compare',
    'commit': 'configure',
    'file': 'config-file',
    'retrieve': 'retrieve',
    'run': 'run',
}

PATH_SPLIT_REGEX = '\s+(?=(?:"[^"]*"|[^"])*$)(?=(?:\'[^\']*\'|[^\'])*$)'


class VyosAPIException(Exception):
    def __init__(self, message):
        self.message = message


class VyosStartConfigException(VyosAPIException):
    pass


class VyosExitConfigException(VyosAPIException):
    pass


class VyosAPI:

    def __init__(self, host, port, key, tls=True, verify=True):
        scheme = 'http'
        if tls:
            scheme = 'https'

        self.url_base = f'{scheme}://{host}:{port}/'

        self.key = key
        self.verify = verify

        self.merge_candidate = []

    def _make_config_statement(self, cmd):
        elements = re.split(PATH_SPLIT_REGEX, cmd)

        op = elements.pop(0)
        value = None
        if op != 'delete':
            try:
                last = elements.pop()
            except IndexError:
                raise VyosAPIException(
                    f'Invalid statement: {cmd}\n\nA value is required.'
                )

            value = str(last).strip('"').strip('\'')

        path = elements
        if len(path) == 0:
            raise VyosAPIException(f'Invalid statement: {cmd}\n\nA path is required.')

        out = {'op': op, 'path': path}
        if value:
            out['value'] = value

        return out

    def _send_request(self, url, data=None):
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

    def _compare_commit(self, endpoint):
        url = self.url_base + API_ENDPOINTS[endpoint]

        data = {'commands': self.merge_candidate}

        ret = self._send_request(url, data)

        if not ret['success']:
            raise VyosAPIException(ret['error'])

        return ret['data'] or ''

    def _file(self, op, file):
        url = self.url_base + API_ENDPOINTS['file']
        data = {'op': op}

        if file:
            data['file'] = file

        ret = self._send_request(url, data)

        if not ret['success']:
            raise VyosAPIException(ret['error'])

        return ret['data'] or ''

    def reset_merge_candidate(self):
        self.merge_candidate = []

    def add_config_set(self, cmds):

        if not isinstance(cmds, list):
            cmds = [cmds]

        for cmd in cmds:
            statement = self._make_config_statement(cmd)
            self.merge_candidate.append(statement)

    def compare(self):
        return self._compare_commit('compare')

    def commit(self):
        ret = self._compare_commit('commit')
        self.reset_merge_candidate()
        return ret

    def save(self, file=None):
        return self._file('save', file)

    def load(self, file=None):
        return self._file('load', file)

    def retrieve(self, path=None):
        path = path or []

        url = self.url_base + API_ENDPOINTS['retrieve']

        data = {'op': 'showConfig', 'path': path}

        ret = self._send_request(url, data)

        if not ret['success']:
            raise VyosAPIException(ret['error'])

        return ret['data'] or {}

    def send_command(self, cmd):
        url = self.url_base + API_ENDPOINTS['run']

        data = {'commands': [cmd]}

        ret = self._send_request(url, data)

        if not ret['success']:
            return ret['error']

        return ret['data'] or ''

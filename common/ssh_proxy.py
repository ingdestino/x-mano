from paramiko import SSHClient
import paramiko
import logging
from enum import Enum

LOG = logging.getLogger(__name__)


class LoginMode(Enum):
    credentials = 1,
    key = 2


class SSHProxy:
    def __init__(self, proxy_config, paramiko_config):
        level = logging.getLevelName(paramiko_config['log_level'])
        logging.getLogger("paramiko").setLevel(level)
        self.proxy_config = proxy_config

        if 'password' in proxy_config:
            self.login_mode = LoginMode.credentials
        else:
            self.login_mode = LoginMode.key

        self._open_channels = {}
        self._proxy_ip = proxy_config['public_ip']
        self._proxy_username = proxy_config['username']
        self._proxy_port = int(proxy_config['port'])

        if self.login_mode == LoginMode.credentials:
            self._proxy_password = proxy_config['password']
        else:
            self._private_key_path = paramiko_config['private_key_path']

        self._first_local_port = int(paramiko_config['first_tunnel_port'])

        self._proxy_client = SSHClient()
        self._proxy_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        if self.login_mode == LoginMode.key:
            key = paramiko.RSAKey.from_private_key_file(self._private_key_path)
            self._proxy_client.connect(self._proxy_ip,
                                       port=self._proxy_port,
                                       username=self._proxy_username,
                                       pkey=key)
        else:
            self._proxy_client.connect(self._proxy_ip,
                                       port=self._proxy_port,
                                       username=self._proxy_username,
                                       password=self._proxy_password)

        stdin , stdout, stderr = self._proxy_client.exec_command('echo test Vital')
        returned_string = stdout.read().rstrip().decode('utf-8')
        assert returned_string == 'test Vital'
        self._open_channels[self._proxy_ip] = self._proxy_client
        self.remove_resolvehost_error = bool(paramiko_config['remove_resolvehost_error'])

    def _open_channel(self, ip):
        transport = self._proxy_client.get_transport()
        dest_addr = (ip, int(self.proxy_config['port']))
        local_addr = ('127.0.0.1', self._first_local_port)
        channel = transport.open_channel("direct-tcpip", dest_addr, local_addr)
        remote_client = SSHClient()
        remote_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        if self.login_mode == LoginMode.key:
            key = paramiko.RSAKey.from_private_key_file(self._private_key_path)
            remote_client.connect('localhost',
                                  port=self._first_local_port,
                                  username=self._proxy_username,
                                  pkey=key, sock=channel)
        else:
            remote_client.connect('localhost',
                                  port=self._first_local_port,
                                  username=self._proxy_username,
                                  password=self._proxy_password, sock=channel)

        self._first_local_port += 1
        stdin , stdout, stderr = remote_client.exec_command('echo test Vital')
        returned_string = stdout.read().rstrip().decode('utf-8')
        assert returned_string == 'test Vital'
        self._open_channels[ip] = remote_client

    def send_command(self, host_ip, command):
        if host_ip not in self._open_channels:
            LOG.debug('Opening a new channel toward ' + host_ip)
            self._open_channel(host_ip)
        stdin , stdout, stderr = self._open_channels[host_ip].exec_command(command)
        stdout_str = stdout.read().rstrip().decode('utf-8')
        stderr_str = stderr.read().rstrip().decode('utf-8')

        if self.remove_resolvehost_error:
            stderr_list_str = stderr_str.split('\n')
            stderr_str = ''
            for error in stderr_list_str:
                if 'sudo: unable to resolve host' not in error:
                    stderr_str += error + '\n'
            if stderr_str[len(stderr_str) - 1:] == '\n':
                stderr_str = stderr_str[:len(stdout_str) - 1]

        return ({'command': command},
                {'stdout': stdout_str},
                {'stderr': stderr_str})




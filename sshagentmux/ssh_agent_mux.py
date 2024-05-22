# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2015, IBM
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations

import argparse
import os
import socketserver
import struct
import sys
from functools import partial

from base_agent_request import BaseAgentRequestHandler
from upstream_socket_thread import UpstreamSocketThread
from daemonize import Daemonize

# LOG = logging.getLogger(__name__)

SOCK_PATH = '/tmp/ssh_auth_mux.sock'
PID_FILE = '/tmp/sshagentmux.pid'


class AgentMultiplexerRequestHandler(BaseAgentRequestHandler):
    """
    Handle a single SSH agent session
    """

    def setup(self):
        self._identity_map = {}

    def handle(self):
        """
        Handle a single SSH agent session
        """
        for request in self._each_msg():
            r_len, r_type = struct.unpack_from('> I B', request)

            if r_type == self.SSH2_AGENTC_REQUEST_IDENTITIES:
                response = self._merge_identities(request)
            elif r_type == self.SSH2_AGENTC_SIGN_REQUEST:
                # Extract key blob from request
                key_blob_len = struct.unpack_from('> I', request, 5)[0]
                key_blob = request[9:9 + key_blob_len]
                hex_blob = ''.join('{:02x}'.format(b) for b in key_blob)

                agent = self._identity_map[hex_blob]
                response = agent.forward_request(request)
            else:
                response = self.server.default_agent.forward_request(request)

            self.request.sendall(response)

    def _merge_identities(self, request):
        """
        Gather identities from all upstream agents and merge into a single
        response, keep track of where we found each identity
        """
        identities = []
        for agent in self.server.agents():
            response = agent.forward_request(request)

            for key_blob, key_comment in self._parse_identities(response):
                # Record where each identity came from
                hex_blob = ''.join('{:02x}'.format(b) for b in key_blob)
                # if hex_blob in self._identity_map and self._identity_map[hex_blob] != agent:
                #     LOG.error("identity %s duplicated in %s and %s by %s",
                #               hex_blob, agent, self._identity_map[hex_blob],
                #               self.username)

                self._identity_map[hex_blob] = agent

                identity = (key_blob, key_comment)
                identities.append(identity)

        return self._build_identities_answer(identities)


class AgentMultiplexer(socketserver.ThreadingUnixStreamServer):
    timeout = 3

    def __init__(self, listening_sock, *upstream_socks):
        # XXX BaseServer is an old style class, so we need to explicitly call
        # our parents initializer
        socketserver.ThreadingUnixStreamServer.__init__(self, listening_sock, AgentMultiplexerRequestHandler)

        self.__agents = []
        for sock in upstream_socks:
            new_agent = UpstreamSocketThread(sock)
            new_agent.start()
            self.__agents.append(new_agent)

    @property
    def default_agent(self):
        return self.__agents[0]

    def agents(self):
        for agent in self.__agents:
            yield agent


def start_agent_mux(parent_pid, upstream_socks):

    try:
        # FIXME: "parent pid handling"

        # generate unique socket path

        # pass all sockets to AgentMultiplexer
        server = AgentMultiplexer(SOCK_PATH, *upstream_socks)

        # Let parent know the socket is ready
        # ready_pipeout.send(SOCK_PATH)
        # ready_pipeout.close()

        # FIXME
        # while check_pid(parent_pid):
        while True:
            server.handle_request()

    except Exception as e:
        os.remove(SOCK_PATH)
        print(str(e), file=sys.stderr)


def check_pid(pid):
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    else:
        return True


def main(args, extra_args):
    # if extra_args and extra_args[0] == '--':
    #     extra_args = extra_args[1:]

    # level = logging.INFO
    # if args.debug:
    #     level = logging.DEBUG
    # setup_logging("sshagentmux", level)

    # LOG.info("Starting sshagentmux")

    # Save original parent pid so we can detect when it exits
    parent_pid = os.getppid()

    # if extra_args:
    #     parent_pid = os.getpid()

    # Start proxy process and wait for it to creating auth socket
    # Using a pipe for compatibility with OpenBSD
    # ready_pipein, ready_pipeout = multiprocessing.Pipe()

    start_agent_mux(parent_pid, args.sockets)

    # daemonize(target=start_agent_mux,
    #           stdout='/tmp/ssh_agent_mux_out.log',
    #           stderr='/tmp/ssh_agent_mux_err.log',
    #           args=(parent_pid, args.sockets))

    # Wait for server to setup listening socket
    # sock_path = ready_pipein.recv()
    # ready_pipein.close()
    # ready_pipeout.close()

    # print(f'export SSH_AUTH_SOCK={SOCK_PATH}')


if __name__ == '__main__':
    if os.path.exists(SOCK_PATH):
        sys.exit(1)

    # fetch alternate socket path from command line
    parser = argparse.ArgumentParser()
    parser.add_argument('--daemonize', '-d', action='store_true',
                        help='start server in background')
    parser.add_argument('--pidfile', '-p', default=PID_FILE,
                        help='pid file')
    parser.add_argument('--sockets', '-s', required=True, nargs='+',
                        help='list of upstream SSH agent sockets')

    args, extra_args = parser.parse_known_args()

    if args.daemonize:
        Daemonize(app='sshagentmus', pid=args.pidfile, action=partial(main, args, extra_args)).start()
    else:
        main(args, extra_args)

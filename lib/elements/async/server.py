# This file is part of Elements.
# Copyright (c) 2010 Sean Kerr. All rights reserved.
#
# The full license is available in the LICENSE file that was distributed with this source code.
#
# Author: Sean Kerr <sean@code-box.org>

try:
    from fcntl import fcntl   as fcntl_func
    from fcntl import F_GETFL as fcntl_getfl
    from fcntl import F_SETFL as fcntl_setfl

except:
    from win32_support import fcntl   as fcntl_func
    from win32_support import F_GETFL as fcntl_getfl
    from win32_support import F_SETFL as fcntl_setfl

import errno
import os
import select
import signal
import socket
import sys
import traceback

from time import time

from elements.async          import client
from elements.async.client   import ChannelClient
from elements.async.client   import HostClient
from elements.async.event    import EPollEventManager
from elements.async.event    import KQueueEventManager
from elements.async.event    import PollEventManager
from elements.async.event    import SelectEventManager
from elements.core.exception import ChannelException
from elements.core.exception import ElementsException
from elements.core.exception import HostException
from elements.core.exception import ServerException

# ----------------------------------------------------------------------------------------------------------------------

class Server:

    def __init__ (self, hosts=None, daemonize=False, user=None, group=None, umask=None, chroot=None, loop_interval=1,
                  timeout=None, timeout_interval=10, worker_count=0, channel_count=1, event_manager=None,
                  print_settings=True):
        """
        Create a new Server instance.

        @param hosts            (tuple)     A tuple that contains one or more tuples of host ip/port pairs.
        @param daemonize        (bool)      Indicates that the process should be daemonized.
        @param user             (str)       The process user.
        @param group            (str)       The process group.
        @param umask            (octal)     The process user mask.
        @param chroot           (str)       The root directory into which the process will be forced.
        @param loop_interval    (int/float) The interval between loop calls.
        @param timeout          (int/float) The client idle timeout.
        @param timeout_interval (int)       The interval between checks for client timeouts.
        @param worker_count     (int)       The worker process count.
        @param channel_count    (int)       The communication channel count for each worker.
        @param event_manager    (str)       The event manager.
        @param print_settings   (bool)      Indicates that the server settings should be printed to the console.
        """

        self._channels                 = {}               # worker channels
        self._channel_count            = channel_count    # count of channels to be created
        self._chroot                   = chroot           # process chroot
        self._clients                  = {}               # all active clients
        self._event_manager            = None             # event manager instance
        self._event_manager_modify     = None             # event manager modify method
        self._event_manager_poll       = None             # event manager poll method
        self._event_manager_register   = None             # event manager register method
        self._event_manager_unregister = None             # event manager unregister method
        self._group                    = group            # process group
        self._hosts                    = []               # host client/server sockets
        self._is_daemon                = daemonize        # indicates that this is running as a daemon
        self._is_listening             = False            # indicates that this process is listening on all hosts
        self._is_long_running          = False            # indicates that clients are long-running
        self._is_parent                = True             # indicates that this process is the parent
        self._is_shutting_down         = False            # indicates that this server is shutting down
        self._is_serving_client        = False            # indicates that a client is being served
        self._loop_interval            = 1                # the interval in seconds between calling handle_loop()
        self._print_settings           = print_settings   # indicates that the settings should be printed to the console
        self._timeout                  = timeout          # the timeout in seconds for a client to be removed
        self._timeout_interval         = timeout_interval # the interval in seconds between checking for idle clients
        self._umask                    = umask            # process umask
        self._user                     = user             # process user
        self._worker_count             = worker_count     # count of worker processes

        # channel count must be at least 1 since channels are used to determine child status
        if self._channel_count < 1:
            self._channel_count = 1

        # choose event manager
        if hasattr(select, "epoll") and (event_manager is None or event_manager == "epoll"):
            self._event_manager = EPollEventManager(self)

        elif hasattr(select, "kqueue") and (event_manager is None or event_manager == "kqueue"):
            self._event_manager = KQueueEventManager(self)
            self._worker_count  = 0

            if worker_count > 0:
                print "KQueue does not support parent process file descriptor inheritence, " \
                      "so workers have been disabled. If you want that ability, you must use the Select event manager."

        elif hasattr(select, "poll") and (event_manager is None or event_manager == "poll"):
            self._event_manager = PollEventManager(self)

        elif hasattr(select, "select") and (event_manager is None or event_manager == "select"):
            self._event_manager = SelectEventManager(self)

        else:
            raise ServerException("Could not find a suitable event manager for your platform")

        # initialize the event manager methods and events
        self._event_manager_modify     = self._event_manager.modify
        self._event_manager_poll       = self._event_manager.poll
        self._event_manager_register   = self._event_manager.register
        self._event_manager_unregister = self._event_manager.unregister

        # update server with proper events
        self.EVENT_LINGER = self._event_manager.EVENT_LINGER

        # update the client module with the proper events
        client.EVENT_LINGER = self._event_manager.EVENT_LINGER
        client.EVENT_READ   = self._event_manager.EVENT_READ
        client.EVENT_WRITE  = self._event_manager.EVENT_WRITE

        # change group
        if group:
            try:
                try:
                    import grp
                except:
                    raise ServerException("Cannot set group, because this platform does not support this feature")

                os.setgid(grp.getgrnam(group).gr_gid)

            except Exception, e:
                raise ServerException("Cannot set group to '%s': %s" % (group, e))

        # change user
        if user:
            try:
                try:
                    import pwd
                except:
                    raise ServerException("Cannot set user, because this platform does not support this feature")

                os.setuid(pwd.getpwnam(user).pw_uid)

            except Exception, e:
                raise ServerException("Cannot set user to '%s': %s" % (user, e))

        # change directory
        if chroot:
            try:
                os.chroot(chroot)

            except Exception, e:
                raise ServerException("Cannot change directory to '%s': %s" % (chroot, e))

        # change umask
        if umask is not None:
            try:
                os.umask(umask)

            except Exception, e:
                raise ServerException("Cannot set umask to '%s': %s" % (umask, e))

        # daemonize
        if daemonize:
            if not hasattr(os, "fork"):
                raise ServerException("Cannot daemonize, because this platform does not support forking")

            if os.fork():
                os._exit(0)

            os.setsid()

            if os.fork():
                os._exit(0)

        # add all hosts
        if hosts:
            for host in hosts:
                self.add_host(*host)

        # register signal handlers
        signal.signal(signal.SIGCHLD, self.handle_signal)
        signal.signal(signal.SIGHUP,  self.handle_signal)
        signal.signal(signal.SIGINT,  self.handle_signal)
        signal.signal(signal.SIGTERM, self.handle_signal)

    # ------------------------------------------------------------------------------------------------------------------

    def add_host (self, ip, port):
        """
        Add a host.

        @param ip   (str) A hostname or ip address.
        @param port (int) The port.
        """

        try:
            host = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # disable blocking
            fcntl_func(host.fileno(), fcntl_setfl, fcntl_func(host.fileno(), fcntl_getfl) | os.O_NONBLOCK)

            host.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            host.bind((ip, port))
            host.listen(socket.SOMAXCONN)

            self.register_host(HostClient(host, (ip, port), self))

        except socket.error, e:
            raise HostException("Cannot add host on ip '%s' port '%d': %s" % (ip, port, e[1]))

    # ------------------------------------------------------------------------------------------------------------------

    def handle_channels (self, pid, sockets):
        """
        This callback is executed when channels need to be prepared for a worker process.

        @param pid     (int)  The process id.
        @param sockets (list) A list of channel sockets for process communication.
        """

        channels = []

        for i in xrange(0, self._channel_count):
            channels.append(ChannelClient(sockets[i], pid, self))

        return channels

    # ------------------------------------------------------------------------------------------------------------------

    def handle_client (self, client_socket, client_address, server_address):
        """
        Handle a new client connection. This is an abstract method that must be overridden in a sub-class.

        @param client_socket  (socket) The client socket.
        @param client_address (tuple)  The client ip address and port.
        @param server_address (tuple)  The server ip address and port upon which the client connected.
        """

        try:
            client_socket.close()

        except:
            pass

        raise ServerException("Server.handle_client() must be overridden")

    # ------------------------------------------------------------------------------------------------------------------

    def handle_exception (self, exception, client=None):
        """
        This callback is executed when an uncaught exception is found while processing a client.

        @param exception (Exception) The exception.
        @param client    (Client)    The Client instance that was active during the exception.

        @return (bool) True, if processing should continue, otherwise False.
        """

        if isinstance(exception, ServerException):
            print "Important server message: %s" % exception

        elif isinstance(exception, ElementsException):
            print "Elements message: %s" % exception

        else:
            print "Unhandled exception:"
            print

            traceback.print_exc()

        return False

    # ------------------------------------------------------------------------------------------------------------------

    def handle_init (self):
        """
        This callback is executed during the start of the process immediately before the processing loop starts. This
        will be executed only once per process.
        """

        pass

    # ------------------------------------------------------------------------------------------------------------------

    def handle_loop (self):
        """
        This callback is executed at the top of each event manager loop.

        @return (object) A list of modified clients (or an empty list), if processing should continue, otherwise False.
        """

        return []

    # ------------------------------------------------------------------------------------------------------------------

    def handle_signal (self, code, frame):
        """
        This callback is executed when a signal has been received.

        @param code  (int)    The signal code.
        @param frame (object) The stack frame.
        """

        if code != signal.SIGCHLD:
            self._is_shutting_down = True

            return

        # allow a child to exit
        pid, status = os.wait()

        del self._channels[pid]

        self.handle_worker_exited(pid, status)

    # ------------------------------------------------------------------------------------------------------------------

    def handle_timeout_check (self):
        """
        Loop through all active clients and find any that may be idle or have timed out.
        """

        clients      = []
        now          = time()
        minimum_time = now - self._timeout

        # iterate all clients and find the ones that are timed out/idle
        # execute the timeout callback and determine what to do
        for client in filter(lambda x: x._last_access_time < minimum_time and not x._is_channel and not x._is_host,
                             self._clients.values()):

            client._events = 0

            if not client.handle_timeout(self._timeout):
                self.unregister_client(client)

                continue

            client._last_access_time = now

            clients.append(client)

        return clients

    # ------------------------------------------------------------------------------------------------------------------

    def handle_worker_exited (self, pid, status):
        """
        This callback is executed when a worker process has exited.

        @param pid    (int) The process id.
        @param status (int) The exit status.
        """

        pass

    # ------------------------------------------------------------------------------------------------------------------

    def listen (self, status):
        """
        Notify the current process to start or stop listening on all hosts.

        @param status (bool) The listening status.
        """

        if self._is_listening == status:
            return

        if status:
            for host in self._hosts:
                self.register_client(host)

        else:
            for host in self._hosts:
                self.unregister_client(host)

        self._is_listening = status

    # ------------------------------------------------------------------------------------------------------------------

    def register_client (self, client):
        """
        Register a client.

        @param client (Client) The client.
        """

        self._clients[client._fileno] = client

        if not client._is_channel or not client._is_blocking:
            self._event_manager.register(client._fileno, client._events & (~self.EVENT_LINGER))

            self._is_serving_client = True

    # ------------------------------------------------------------------------------------------------------------------

    def register_host (self, host):
        """
        Register a host.

        @param host (HostClient) The host client.
        """

        self._hosts.append(host)

    # ------------------------------------------------------------------------------------------------------------------

    def shutdown (self):
        """
        Unregister all clients and kill worker processes.
        """

        # remove the sigchld handler
        signal.signal(signal.SIGCHLD, signal.SIG_IGN)

        # unregister and shutdown all clients
        for client in self._clients.values():
            self.unregister_client(client)

        # wait for all worker processes to exit
        if self._is_parent:
            for pid in self._channels:
                try:
                    os.kill(pid, signal.SIGINT)

                except:
                    pass

            for pid in self._channels:
                try:
                    self.handle_worker_exited(*os.wait())

                except:
                    pass

    # ------------------------------------------------------------------------------------------------------------------

    def spawn_worker (self):
        """
        Spawn a worker process.
        """

        if not self._is_parent:
            return

        if not hasattr(os, "fork"):
            raise ServerException("Cannot spawn worker, because this platform does not support forking")

        # create a socketpair for each channel
        parent_sockets = []
        worker_sockets = []

        for i in xrange(0, self._channel_count):
            pair = socket.socketpair()

            # disable blocking
            fcntl_func(pair[0].fileno(), fcntl_setfl, fcntl_func(pair[0].fileno(), fcntl_getfl) | os.O_NONBLOCK)
            fcntl_func(pair[1].fileno(), fcntl_setfl, fcntl_func(pair[1].fileno(), fcntl_getfl) | os.O_NONBLOCK)

            parent_sockets.append(pair[0])
            worker_sockets.append(pair[1])

        pid = os.fork()

        if pid:
            # initialize and register worker channels
            self.__register_channels(self.handle_channels(pid, parent_sockets))

            return

        # initialization from worker perspective
        try:
            self._channels     = {}
            self._clients      = {}
            self._is_listening = False
            self._is_parent    = False

            # initialize the event manager
            self._event_manager            = self._event_manager.__class__(self)
            self._event_manager_modify     = self._event_manager.modify
            self._event_manager_poll       = self._event_manager.poll
            self._event_manager_register   = self._event_manager.register
            self._event_manager_unregister = self._event_manager.unregister

            # initialize and register parent channels
            self.__register_channels(self.handle_channels(os.getpid(), worker_sockets))

            # start listening on all hosts and then start the server
            self.listen(True)
            self.start()

        except ElementsException:
            raise

        except Exception, e:
            self.handle_exception(e)

        finally:
            os._exit(0)

    # ------------------------------------------------------------------------------------------------------------------

    def start (self):
        """
        Start the infinite loop that iterates file descriptor events.
        """

        if self._is_parent:
            if self._print_settings:
                # show initialization settings
                print
                print "+---------------------------------------------------------------+"
                print "| Elements v0.1.1 Initialized                                   |"
                print "+---------------------------------------------------------------+"
                print "| Daemonized:          %-40s |" % self._is_daemon
                print "| Event manager:       %-40s |" % self._event_manager.__class__.__name__
                print "| Workers:             %-40d |" % self._worker_count
                print "| Channels per worker: %-40d |" % self._channel_count
                print "| User:                %-40s |" % (self._user if self._user else "-")
                print "| Group:               %-40s |" % (self._group if self._group else "-")
                print "| User mask:           %-40s |" % (self._umask if self._umask else "-")
                print "| Chroot:              %-40s |" % (self._chroot if self._chroot else "-")

                if len(self._hosts) > 0:
                    print "|                                                               |"
                    print "| Listening on hosts:                                           |"

                    for host in self._hosts:
                        print "|   %-59s |" % ("%s:%d" % host._client_address)

                else:
                    print "|                                                               |"
                    print "| Not listening on any hosts                                    |"

                print "+---------------------------------------------------------------+"

            # spawn workers
            for i in xrange(0, self._worker_count):
                self.spawn_worker()

            # if there are no workers, we need to force the process to listen on all hosts, otherwise no external clients
            # will be accepted
            if self._worker_count == 0:
                self.listen(True)

        EVENT_ERROR  = self._event_manager.EVENT_ERROR
        EVENT_LINGER = self._event_manager.EVENT_LINGER
        EVENT_READ   = self._event_manager.EVENT_READ
        EVENT_WRITE  = self._event_manager.EVENT_WRITE

        # we cache some methods/vars locally to avoid dereferencing in each loop which could potentially be
        # thousands of times per second
        clients                = self._clients
        is_shutting_down       = False
        loop_check             = 0
        modify_func            = self._event_manager_modify
        poll_func              = self._event_manager_poll
        timeout_check          = 0
        unregister_func        = self._event_manager_unregister
        unregister_client_func = self.unregister_client

        # initialize process
        self.handle_init()

        # loop until the server is going to shutdown
        while not is_shutting_down:
            now = time()

            try:
                # execute a loop callback at most once per second
                if now - self._loop_interval > loop_check:
                    is_shutting_down = self._is_shutting_down

                    try:
                        loop_check = now

                        loop_clients = self.handle_loop()

                        if loop_clients == False:
                            # the loop callback is telling us to shutdown
                            break

                        # update the events for any clients that were changed during the loop handler
                        for client in loop_clients:
                            modify_func(client._fileno, client._events & (~EVENT_LINGER))

                        # execute a timeout callback at most every [timeout interval] seconds
                        if self._timeout and now - self._timeout_interval > timeout_check:
                            timeout_check = now

                            # update the events for any clients that have timed out and are still going to be processed
                            for client in self.handle_timeout_check():
                                modify_func(client._fileno, client._events & (~EVENT_LINGER))

                    except Exception, e:
                        # an unhandled exception has been caught
                        self.handle_exception(e)

                        continue

                # iterate over all clients that have an active event
                for fileno, events in poll_func():
                    try:
                        client = clients[fileno]

                    except KeyError:
                        # invalid file descriptor
                        unregister_func(fileno)

                        continue

                    # copy the events so we know if they have changed after we handle the event
                    client_events = client._events

                    # handle the event
                    if events & EVENT_ERROR:
                        client.handle_error()

                        unregister_client_func(client)

                        continue

                    if events & EVENT_READ:
                        client.handle_read()

                    if events & EVENT_WRITE:
                        client.handle_write()

                    # check for event changes
                    if client_events != client._events:
                        if client._events == 0:
                            # no more events for this client
                            unregister_client_func(client)

                            continue

                        # update the events
                        modify_func(fileno, client._events & (~EVENT_LINGER))

                    # update the client time
                    client._last_access_time = now

            except socket.error, e:
                if e[0] not in (errno.EAGAIN, errno.EWOULDBLOCK):
                    # an unrecoverable socket error has occurred
                    unregister_client_func(client)

            except (select.error, IOError, OSError):
                pass

            except Exception, e:
                # an unhandled exception has been caught
                self.handle_exception(e, client)

                # check for event changes
                if client_events != client._events:
                    if client._events == 0:
                        # no more events for this client
                        unregister_client_func(client)

                        continue

                    # update the events
                    modify_func(fileno, client._events & (~EVENT_LINGER))

                # update the client time
                client._last_access_time = now

        self.shutdown()

    # ------------------------------------------------------------------------------------------------------------------

    def unregister_client (self, client):
        """
        Unregister a client

        @param client (Client) The client.
        """

        self._event_manager_unregister(client._fileno)

        if not client._is_channel and not client._is_host:
            self._is_serving_client = False

        del self._clients[client._fileno]

        client.handle_shutdown()

    # ------------------------------------------------------------------------------------------------------------------

    def unregister_host (self, host):
        """
        Unregister a host.

        @param host (HostClient) The host.
        """

        if host not in self._hosts:
            raise HostException("Host is not registered")

        if not self._is_listening:
            self._hosts.remove(host)

            return

        # disable listening, then remove the host, then re-enable listening
        self.listen(False)

        self._hosts.remove(host)

        self.listen(True)

    # ------------------------------------------------------------------------------------------------------------------

    def write_channel (self, data, channel_index=0, pid=0, flush=True):
        """
        Write data to a channel.

        @param data          (str)  The data.
        @param channel_index (int)  The channel index.
        @param pid           (int)  The process id.
        @param flush         (bool) Indicates that the data should be flushed to the channel immediately.

        @return (str) If the channel is blocking, the response will be returned immediately. Otherwise nothing is
                      returned.
        """

        try:
            channel = self._channels[pid][channel_index]

        except KeyError:
            raise ChannelException("Invalid pid or channel index")

        if channel._is_blocking:
            return channel.write(data)

        channel.write(data)

        if flush:
            channel.flush()

    # ------------------------------------------------------------------------------------------------------------------

    def __register_channels (self, channels):
        """
        Register worker channels.
        """

        if type(channels) in (list, tuple):
            if len(channels) != self._channel_count:
                raise ChannelException("Expected %d channels, but got %d" % (self._channel_count, len(channels)))

            for channel in channels:
                self.register_client(channel)

                if channel._pid in self._channels:
                    self._channels[channel._pid].append(channel)

                else:
                    self._channels[channel._pid] = [channel]

        else:
            if self._channel_count > 1:
                raise ChannelException("Expected %d channels, but got 1" % self._channel_count)

            self.register_client(channels)

            if channel._pid in self._channels:
                self._channels[channel._pid].append(channel)

            else:
                self._channels[channel._pid] = [channel]

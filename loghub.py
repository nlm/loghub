#!/usr/bin/env python3
"""
loghub

Syslog Forwarding Hub
"""

import argparse
import logging
import socketserver
import queue
import socket
import syslog
import syslogmp
import threading
import time
import re
import sys
from syslog_rfc5424_parser import SyslogMessage as RFC5452SyslogMessage
from syslog_rfc5424_parser import ParseError
import syslogmp


class SyslogHandler(socketserver.BaseRequestHandler):
    """
    A request handler for the TCPServer or UDPServer of NetworkServerThread
    """

    logger = logging.getLogger(__name__)

    def handle(self):
        """
        handle a syslog network packet
        """
        if isinstance(self.request, socket.socket):
            # handle request from TCPServer
            data = self.request.recv(4096)
        else:
            # handle request from UDPServer
            data = self.request[0]

        try:
            self.server.queue.put(data)
        except queue.Full:
            self.logger.error('{}: queue full'
                              .format(threading.current_thread().name))

        # Log Messages
        self.logger.debug('{} received {} bytes'
                          .format(threading.current_thread().name, len(data)))


class LogHubThread(threading.Thread):

    def __init__(self):
        threading.Thread.__init__(self)
        self.logger = logging.getLogger(__name__)
        self.name = self.__class__.__name__

    def shutdown(self):
        self.logger.error('{}: no shutdown function defined'.format(self.name))


class NetworkServerThread(LogHubThread):

    logger = logging.getLogger(__name__)
    serverclass = None

    def __init__(self, host, port, equeue):
        threading.Thread.__init__(self)
        self.name = '{}({}:{})'.format(self.__class__.__name__, host, port)
        self.server = self.serverclass((host, port), SyslogHandler)
        self.server.queue = equeue

    def run(self):
        """
        start this thread
        """
        self.server.allow_reuse_address = True
        self.server.serve_forever()

    def shutdown(self):
        """
        tell this thread to shutdown
        """
        self.server.shutdown()


class TCPServerThread(NetworkServerThread):
    """
    A class receiving syslog packets via TCP
    and putting them in a Queue
    """
    serverclass = socketserver.TCPServer


class UDPServerThread(NetworkServerThread):
    """
    A class receiving syslog packets via TCP
    and putting them in a Queue
    """
    serverclass = socketserver.UDPServer


class SyslogMessage(object):
    """
    A class to have a unique object layer for RFC 5424 and RFC 3164
    syslog messages
    """

    severities = {
        'emerg': syslog.LOG_EMERG,
        'alert': syslog.LOG_ALERT,
        'crit': syslog.LOG_CRIT,
        'err': syslog.LOG_ERR,
        'warning': syslog.LOG_WARNING,
        'notice': syslog.LOG_NOTICE,
        'info': syslog.LOG_INFO,
        'debug': syslog.LOG_DEBUG,
    }

    facilities = {
        'kern': syslog.LOG_KERN,
        'user': syslog.LOG_USER,
        'mail': syslog.LOG_MAIL,
        'daemon': syslog.LOG_DAEMON,
        'auth': syslog.LOG_AUTH,
        'lpr': syslog.LOG_LPR,
        'news': syslog.LOG_NEWS,
        'uucp': syslog.LOG_UUCP,
        'cron': syslog.LOG_CRON,
        'syslog': syslog.LOG_SYSLOG,
        'local0': syslog.LOG_LOCAL0,
        'local1': syslog.LOG_LOCAL1,
        'local2': syslog.LOG_LOCAL2,
        'local3': syslog.LOG_LOCAL3,
        'local4': syslog.LOG_LOCAL4,
        'local5': syslog.LOG_LOCAL5,
        'local6': syslog.LOG_LOCAL6,
        'local7': syslog.LOG_LOCAL7,
    }

    id = None
    message = None
    facility = None
    severity = None
    identifier = None
    hostname = None
    pid = None

    def __init__(self, rawdata):
        self.logger = logging.getLogger(__name__)
        if not self.parse(rawdata):
            raise ValueError("could not parse syslog message")
        self._rawdata = rawdata

    @property
    def rawdata(self):
        """
        Contains the SyslogMessage raw bytes
        """
        return self._rawdata

    def parse_3164_msg(self, message):
        """
        Parse an RFC 3164 message and try to extract
        the (identifier, pid, message) tuple.
        Any can be None, except message
        """
        # Full Message
        res = re.match('^([^ ]+)\[(\d+)\]: (.*)', message)
        if res:
            return res.groups()
        # No PID
        res = re.match('^([^ ]+): (.*)', message)
        if res:
            return (res.group(1), None, res.group(2))
        # Default
        return (None, None, message)

    def parse(self, rawdata):
        """
        Parse any of the two types of Syslog Formats
        and stores the result in this object
        """
        # RFC 5424
        try:
            msg = RFC5452SyslogMessage.parse(rawdata.decode()).as_dict()
            self.id = msg.get('msgid')
            self.message = msg.get('msg', '').rstrip(' \t\r\n\0')
            self.facility = self.facilities[msg['facility']]
            self.severity = self.severities[msg['severity']]
            self.identifier = msg.get('appname')
            self.pid = msg.get('procid')
            self.hostname = msg.get('hostname')
            return True
        except (ParseError, ValueError):
            # log err ?
            pass

        # RFC 3164
        try:
            if len(rawdata) > 1024:
                self.logger.warning('truncating message ({} > 1024)'
                                    .format(len(rawdata)))
                rawdata = rawdata[:1024]
            # truncate to 1024
            msg = syslogmp.parse(rawdata)
            self.id = None
            (self.identifier,
             self.pid,
             self.message) = self.parse_3164_msg(msg.message.decode().strip())
            self.message = self.message.rstrip(' \t\r\n\0')
            self.facility = int(msg.facility.value)
            self.severity = int(msg.severity.value)
            self.hostname = msg.hostname
            return True
        except (syslogmp.parser.MessageFormatError, ValueError):
            # log err ?
            pass

        return False

    def as_dict(self):
        """
        Returns a dict of the syslog-related attributes of this object
        """
        return {x: getattr(self, x) for x in ['id', 'message', 'facility',
                                              'hostname', 'severity',
                                              'identifier', 'pid']}


class LoopThread(LogHubThread):

    def __init__(self):
        LogHubThread.__init__(self)
        self._shutdown = False

    def shutdown(self):
        self._shutdown = True

    @property
    def must_shutdown(self):
        return self._shutdown

    def step(self):
        self.logger.error("{}: no 'step' function defined".format(self.name))
        time.sleep(1)

    def run(self, delay=0):
        """
        start this thread, calling step() in loop until shutdown() is called.
        optionally waits for a delay between calls

        if setup() is defined, call it before the first step()
        if cleanup() is defined, call it after the last step()
        """
        if callable(getattr(self, 'setup', None)):
            self.setup()

        while not self._shutdown:
            self.step()
            time.sleep(delay)

        if callable(getattr(self, 'cleanup', None)):
            self.cleanup()


class JournaldThread(LoopThread):
    """
    A class receiving SyslogMessages via a Queue
    and emitting messages to Journald
    """

    def __init__(self, queue):
        LoopThread.__init__(self)
        self.queue = queue
        import systemd.journal
        self.send_func = systemd.journal.send

    def step(self):
        try:
            msg = self.queue.get(timeout=1)
        except queue.Empty:
            return

        # Send to systemd
        self.send_func(msg.message,
                       MESSAGE_ID=msg.id,
                       PRIORITY=msg.severity,
                       SYSLOG_FACILITY=msg.facility,
                       SYSLOG_IDENTIFIER=msg.identifier,
                       SYSLOG_PID=msg.pid)
        self.logger.debug('{}: wrote message to journal'.format(self.name))


class TCPClientThread(LoopThread):
    """
    A class for sending data to a remote location via UDP
    """

    def __init__(self, equeue, host, port):
        LoopThread.__init__(self)
        self.name = '{}({}:{})'.format(self.__class__.__name__, host, port)
        self.queue = equeue
        self.host = host
        self.port = port
        self.sock = None

    def connect(self, timeout=10, backoff=10):
        """
        create a conection to a remote endpoint
        """
        try:
            return socket.create_connection((self.host, self.port),
                                            timeout=timeout)
        except socket.error as err:
            self.logger.error('{}: {}'.format(threading.current_thread().name,
                                              err))
            for i in range(backoff):
                if self.must_shutdown:
                    return None
                time.sleep(1)
            return None

    def step(self):
        if self.sock is None:
            self.sock = self.connect()
            return

        try:
            message = self.queue.get(timeout=1)
        except queue.Empty:
            return

        try:
            self.logger.debug('{}: sending {} bytes to {}:{}'
                              .format(self.name, len(message.rawdata),
                                      self.host, self.port))
            self.sock.send(message.rawdata)
        except BrokenPipeError:
            self.sock.close()
            self.sock = None

    def cleanup(self):
        if self.sock is not None:
            self.sock.close()


class UDPClientThread(LoopThread):
    """
    A class for sending data to a remote location via UDP
    """

    def __init__(self, equeue, host, port):
        LoopThread.__init__(self)
        self.name = '{}({}:{})'.format(self.__class__.__name__, host, port)
        self.queue = equeue
        self.host = host
        self.port = port
        self.sock = None

    def setup(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def step(self):
        try:
            message = self.queue.get(timeout=1)
        except queue.Empty:
            return

        self.logger.debug('{}: sending {} bytes to {}:{}'
                          .format(self.name, len(message.rawdata),
                                  self.host, self.port))
        self.sock.sendto(message.rawdata, (self.host, self.port))


class FileAppendThread(LoopThread):
    """
    A class for appending messages to a file
    """

    def __init__(self, equeue, filename):
        LoopThread.__init__(self)
        self.name = '{}({})'.format(self.__class__.__name__, filename)
        self.queue = equeue
        self.filename = filename

    def setup(self):
        self.fd = open(self.filename, 'a')

    def step(self):
        try:
            message = self.queue.get(timeout=1)
        except queue.Empty:
            return

        print(message.as_dict(), file=self.fd)

    def cleanup(self):
        self.fd.close()


class DataHubThread(LoopThread):
    """
    A class for receiving messages from receiving queue
    and forwarding them to the emitting queues
    """

    def __init__(self, receiving_queue, emitting_queues):
        LoopThread.__init__(self)
        self.receiving_queue = receiving_queue
        self.emitting_queues = emitting_queues

    def step(self):
        """
        Reads data from the input queue
        Parse the Syslog Message
        Push the data to the output queues
        """
        # Read new data from queue
        try:
            data = self.receiving_queue.get(timeout=1)
        except queue.Empty:
            return

        # Parse SyslogMessage
        try:
            message = SyslogMessage(data)
        except ValueError as err:
            self.logger.warning('{}: ignoring message: {}'
                                .format(self.name, err))
            return

        self.logger.debug('{}: {}'.format(self.name, message.as_dict()))

        # Send to active forwarders
        for equeue in self.emitting_queues:
            try:
                equeue.put(message)
            except queue.Full:
                self.logger.error('{}: queue full, discarding message'
                                  .format(threading.current_thread().name))


def host_port(hostport):
    """
    basic parser for a host:port argument
    """
    host, port = hostport.split(':')
    if not 0 < int(port) < 65536:
        raise ValueError
    try:
        return (socket.gethostbyname(host), int(port))
    except socket.gaierror as err:
        logger = logging.getLogger(__name__)
        logger.error(err)
        raise ValueError


def queue_size(size):
    """
    basic parser for a queue size
    """
    size = int(size)
    if not size >= 1:
        raise ValueError
    return size


def log_level(level):
    """
    basic parser for log priority
    """
    log_levels = {'emerg': logging.CRITICAL,
                  'alert': logging.CRITICAL,
                  'crit': logging.CRITICAL,
                  'err': logging.ERROR,
                  'warning': logging.WARNING,
                  'notice': logging.WARNING,
                  'info': logging.INFO,
                  'debug': logging.DEBUG}
    try:
        return log_levels[level]
    except KeyError:
        raise ValueError


def run_threads(args):
    """
    Prepare and manage the threads
    """
    logger = logging.getLogger(__name__)

    # Receiving
    receiving_threads = []
    receiving_queue = queue.Queue(maxsize=args.queues_size)

    for host, port in args.listen_tcp:
        receiving_threads.append(TCPServerThread(host, port, receiving_queue))
    for host, port in args.listen_udp:
        receiving_threads.append(UDPServerThread(host, port, receiving_queue))

    # Emitting
    emitting_threads = []
    emitting_queues = []

    for host, port in args.forward_udp:
        equeue = queue.Queue(args.queues_size)
        emitting_queues.append(equeue)
        emitting_threads.append(UDPClientThread(equeue, host, port))
    for host, port in args.forward_tcp:
        equeue = queue.Queue(args.queues_size)
        emitting_queues.append(equeue)
        emitting_threads.append(TCPClientThread(equeue, host, port))

    # Journald
    if args.forward_journal:
        jqueue = queue.Queue(args.queues_size)
        emitting_queues.append(jqueue)
        emitting_threads.append(JournaldThread(jqueue))

    # Data Exchange Hub
    datahub_thread = DataHubThread(receiving_queue, emitting_queues)

    logger.debug('starting threads')
    for thread in emitting_threads + [datahub_thread] + receiving_threads:
        logger.debug('starting thread {}'.format(thread.name))
        thread.start()

    logger.debug('watching threads')
    try:
        while True:
            for thread in receiving_threads + [datahub_thread] + emitting_threads:
                if not thread.is_alive():
                    logger.debug('thread {} died'.format(thread.name))
                    raise Exception('thread {} died'.format(thread.name))
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info('keyboard interrupt received')
    except Exception:
        raise

    logger.info('loghub stopping')
    logger.debug('stopping threads')
    for thread in receiving_threads + [datahub_thread] + emitting_threads:
        if thread.is_alive():
            logger.debug('stopping thread {}'.format(thread.name))
            thread.shutdown()


def parse_arguments():
    parser = argparse.ArgumentParser()

    p_listen = parser.add_argument_group('data reception')
    p_listen.add_argument('--listen-udp', '-u',
                          action='append', metavar='HOST:PORT', type=host_port,
                          help='listen on udp [HOST]:PORT', default=[])
    p_listen.add_argument('--listen-tcp', '-t',
                          action='append', metavar='HOST:PORT', type=host_port,
                          help='listen on tcp [HOST]:PORT', default=[])

    p_forward = parser.add_argument_group('data emission')
    p_forward.add_argument('--forward-udp', '-U',
                           action='append', metavar='HOST:PORT', type=host_port,
                           help='forward to udp [HOST]:PORT', default=[])
    p_forward.add_argument('--forward-tcp', '-T',
                           action='append', metavar='HOST:PORT', type=host_port,
                           help='forward to tcp [HOST]:PORT', default=[])
    p_forward.add_argument('--forward-journal', '-J', action='store_true',
                           default=False,
                           help='forward messages to local systemd journal')

    p_log = parser.add_argument_group('local logging')
    p_log.add_argument('--log-file', '-f', help='log to file')
    p_log.add_argument('--log-level', '-l', type=log_level,
                       default=logging.INFO, help='local log level')

    p_adv = parser.add_argument_group('advanced options')
    p_adv.add_argument('--queues-size', type=queue_size,
                       default=1000, help='max size of queues')

    args = parser.parse_args()

    if not args.listen_tcp and not args.listen_udp:
        parser.error('nothing to listen on')

    if not args.forward_journal and not args.forward_udp:
        parser.error('nothing to send to')

    if args.log_file or sys.stdout.isatty():
        args.log_format='[%(asctime)s] %(levelname)s: %(message)s'
    else:
        args.log_format='%(message)s'

    return args


def main():
    args = parse_arguments()
    logger = logging.getLogger(__name__)
    logging.basicConfig(level=args.log_level,
                        format=args.log_format,
                        datefmt='',
                        filename=args.log_file,
                        filemode='a')
    logger.info('loghub starting')
    return run_threads(args)


if __name__ == '__main__':
    main()

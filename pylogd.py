#!/usr/bin/env python3
import argparse
import logging
import socketserver
import syslog
import threading
import systemd.journal
from syslog_rfc5424_parser import SyslogMessage, ParseError

class SyslogHandler(socketserver.BaseRequestHandler):

    priorities = {
        'emerg': syslog.LOG_EMERG,
        'alert': syslog.LOG_ALERT,
        'crit': syslog.LOG_CRIT,
        'err': syslog.LOG_ERR,
        'warning': syslog.LOG_WARNING,
        'notice': syslog.LOG_NOTICE,
        'info': syslog.LOG_INFO,
        'debug': syslog.LOG_DEBUG,
    }

    pypriorities = {
        'emerg': logging.CRITICAL,
        'alert': logging.CRITICAL,
        'crit': logging.CRITICAL,
        'err': logging.ERROR,
        'warning': logging.WARNING,
        'notice': logging.WARNING,
        'info': logging.INFO,
        'debug': logging.DEBUG,
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

    def handle(self):
        data = self.request.recv(4096)

        # Parsing Message
        message = SyslogMessage.parse(data.decode())
        msgdict = message.as_dict()

        # Log Messages
        logger = logging.getLogger(__name__)
        logger.debug('{}: {}'.format(threading.current_thread().name, msgdict))

        # Send to systemd
        systemd.journal.send(msgdict.get('msg', '').strip(),
                             MESSAGE_ID=msgdict.get('msgid'),
                             PRIORITY=self.priorities[msgdict['severity']],
                             SYSLOG_FACILITY=self.facilities[msgdict['facility']],
                             SYSLOG_IDENTIFIER=msgdict.get('appname'),
                             SYSLOG_PID=msgdict.get('procid'))


class SyslogServerThread(threading.Thread):

    serverclass = None

    def __init__(self, host, port):
        threading.Thread.__init__(self)
        self.name = '{}({}:{})'.format(self.serverclass.__name__, host, port)
        self.server = self.serverclass((host, port), SyslogHandler)

    def run(self):
        self.server.allow_reuse_address = True
        self.server.serve_forever()

    def shutdown(self):
        self.server.shutdown()


class TCPThread(SyslogServerThread):

    serverclass = socketserver.TCPServer


class UDPThread(SyslogServerThread):

    serverclass = socketserver.UDPServer


def host_port(hostport):
    host, port = hostport.split(':')
    return (host, int(port))


def main():
    parser = argparse.ArgumentParser()
    p_group = parser.add_argument_group('listen')
    p_group.add_argument('-u', '--listen-udp',
                        action='append',
                        metavar='HOST:PORT',
                        type=host_port,
                        help='listen on udp [HOST]:PORT',
                        default=[])

    p_group.add_argument('-t', '--listen-tcp',
                        action='append',
                        metavar='HOST:PORT',
                        type=host_port,
                        help='listen tcp',
                        default=[])

    parser.add_argument('-f', '--log-file', help='log to file')
    parser.add_argument('-l', '--log-level', help='local log level')
    args = parser.parse_args()

    if not args.listen_tcp and not args.listen_udp:
        parser.error('nothing to listen on')

    logging.basicConfig(level=logging.DEBUG,
                        format='%(message)s',
                        datefmt='',
                        filename=args.log_file,
                        filemode='a')

    logger = logging.getLogger(__name__)
    logger.info('pylogd starting')

    threads = []
    for host, port in args.listen_tcp:
        threads.append(TCPThread(host, port))
    for host, port in args.listen_udp:
        threads.append(UDPThread(host, port))

    logger.debug('starting threads')
    for thread in threads:
        logger.debug('starting thread {}'.format(thread.name))
        thread.start()

    try:
        for thread in threads:
            thread.join()
    except KeyboardInterrupt:
        logger.info('pylogd stopping')
    except Exception:
        raise

    for thread in threads:
        logger.debug('stopping thread {}'.format(thread.name))
        thread.shutdown()


if __name__ == '__main__':
    main()

#!/usr/bin/env python

from logging import INFO
from logging.handlers import TimedRotatingFileHandler
from re import compile as re_compile, Pattern as RePattern
from typing import Type, Final
from socket import AddressFamily
from email import message_from_bytes as email_message_from_bytes
from email.utils import parseaddr as email_util_parseaddr
from functools import partial
from io import BytesIO

import Milter
from Milter import noreply as milter_noreply, CONTINUE as MILTER_CONTINUE, Base as MilterBase, \
    uniqueID as milter_unique_id, decode as milter_decode
from ecs_py import SMTP, Sender, Base, Server, Network, Client, TLS
from ecs_tools_py import make_log_handler, email_from_email_message

from log_milter import LOG
from log_milter.cli import LogMilterArgumentParser

log_handler = make_log_handler(
    base_class=TimedRotatingFileHandler,
    provider_name='log_milter',
    generate_field_names=('event.timezone', 'host.name', 'host.hostname')
)(filename='log_milter.log', when='D')

LOG.addHandler(hdlr=log_handler)
LOG.setLevel(level=INFO)

TLS_VERSION_PATTERN: Final[RePattern] = re_compile(pattern='^(?P<protocol>.+)v(?P<number>[0-9.]+)$')


class LogMilter(MilterBase):
    def __init__(self, server_port: int | None = None, network_transport: str | None = None):
        self.id = milter_unique_id()

        self._ecs_base: Base = Base(
            client=Client(),
            server=Server(),
            smtp=SMTP(),
            tls=TLS(),
            network=Network()
        )

        if server_port:
            self._ecs_base.server.port = server_port
            
        if network_transport:
            self._ecs_base.network.transport = network_transport

        self._message: BytesIO = BytesIO()

    @milter_noreply
    def connect(self, hostname, family, hostaddr):
        try:
            self._ecs_base.server.address = self.getsymval(sym='j')
            self._ecs_base.server.ip = self.getsymval(sym='{daemon_addr}')

            match family:
                case AddressFamily.AF_INET:
                    network_type = 'ipv4'
                case AddressFamily.AF_INET6:
                    network_type = 'ipv6'
                case _:
                    network_type = None

            if network_type:
                self._ecs_base.network.type = network_type
                self._ecs_base.client.ip=hostaddr[0]
                self._ecs_base.client.port = hostaddr[1]
        except:
            LOG.exception(msg='An unexpected exception occurred in connect.')

        return MILTER_CONTINUE

    @milter_noreply
    def hello(self, hostname: str):
        try:
            self._ecs_base.smtp.ehlo = hostname

            if cipher := self.getsymval(sym='{cipher}'):
                self._ecs_base.tls.cipher = cipher

            if tls_version := self.getsymval(sym='{tls_version}'):
                if match := TLS_VERSION_PATTERN.match(string=tls_version):
                    match_groupdict: dict[str, str] = match.groupdict()
                    self._ecs_base.tls.version_protocol = match_groupdict['protocol'].lower()
                    self._ecs_base.tls.version = match_groupdict['number']
        except:
            LOG.exception(msg='An unexpected exception occurred in hello.')

        return MILTER_CONTINUE

    @milter_noreply
    def envfrom(self, f: str, *args):
        try:
            self._ecs_base.smtp.mail_from = email_util_parseaddr(addr=f)[1]
        except:
            LOG.exception(msg='An unexpected exception occurred in envfrom.')

        return MILTER_CONTINUE

    @milter_noreply
    def envrcpt(self, to: str, *args):
        try:
            self._ecs_base.smtp.rcpt_to = email_util_parseaddr(addr=to)[1]
        except:
            LOG.exception(msg='An unexpected exception occurred in envrcpt.')

        return MILTER_CONTINUE

    @milter_noreply
    @milter_decode('bytes')
    def header(self, fld: str, val: bytes):
        try:
            self._message.write(fld.encode(encoding='ascii') + b': ' + val + b'\r\n')
        except:
            LOG.exception(msg='An unexpected exception occurred in header_bytes.')

        return MILTER_CONTINUE

    @milter_noreply
    def eoh(self):
        try:
            self._message.write(b'\r\n')
        except:
            LOG.exception(msg='An unexpected exception occurred in eoh.')

        return MILTER_CONTINUE

    @milter_noreply
    def body(self, blk: bytes):
        self._message.write(blk)
        return MILTER_CONTINUE

    @milter_noreply
    def close(self):
        try:
            try:
                self._ecs_base.email = email_from_email_message(
                    email_message=email_message_from_bytes(self._message.getvalue()),
                    include_raw_headers=True,
                    extract_attachments=True,
                    extract_bodies=True,
                    extract_attachment_contents=False,
                    extract_body_content=True
                )

                if mail_from := self._ecs_base.smtp.mail_from:
                    self._ecs_base.email.sender = Sender(address=mail_from)
            except:
                LOG.exception(
                    msg='An unexpected exception occurred when attempting to create a email.message.Message from bytes.'
                )

            LOG.info(
                msg='An incoming email was logged.',
                extra=dict(self._ecs_base) | dict(_ecs_logger_handler_options=dict(merge_extra=True))
            )
        except:
            LOG.exception(msg='An unexpected exception occurred in close.')

        return MILTER_CONTINUE


def main():
    args: Type[LogMilterArgumentParser.Namespace] = LogMilterArgumentParser().parse_args()

    try:
        Milter.factory = partial(
            LogMilter,
            server_port=args.server_port,
            network_transport=args.network_transport
        )

        # Mails are not modified, so no flags.
        Milter.set_flags(0)
        Milter.set_exception_policy(MILTER_CONTINUE)
        Milter.runmilter('log_milter', args.socket_path, args.timeout)
    except:
        LOG.exception(msg='An unexpected exception occurred.')


if __name__ == '__main__':
    main()

#!/usr/bin/env python

from logging import INFO
from logging.handlers import TimedRotatingFileHandler
from re import compile as re_compile, Pattern as RePattern
from typing import Type, Final
from socket import AddressFamily
from collections import defaultdict
from email import message_from_bytes as email_message_from_bytes
from email.utils import parseaddr as email_util_parseaddr, parsedate as email_utils_parsedate
from functools import partial
from time import mktime
from datetime import datetime
from io import BytesIO

import Milter
from Milter import noreply as milter_noreply, CONTINUE as MILTER_CONTINUE, Base as MilterBase, \
    uniqueID as milter_unique_id
from ecs_py import Email, BCC, CC, From, To, ReplyTo, RcptTo, SMTP, Sender, Base, Server, Network, Client, TLS, \
    EmailAttachment
from ecs_tools_py import make_log_handler, email_file_attachments_from_email_message

from log_milter import LOG, decode_address, decode_address_line
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

        self._ecs_base: Base = Base(email=Email(smtp=SMTP(), direction='inbound'))

        if server_port:
            self._ecs_base.server = Server(port=server_port)
            
        if network_transport:
            self._ecs_base.network = Network(transport=network_transport)

        self._headers: defaultdict[str, list[str]] = defaultdict(list)
        self._message: BytesIO = BytesIO()

    @milter_noreply
    def connect(self, hostname, family, hostaddr):
        try:
            server: Server = self._ecs_base.get_field_value(field_name='server', create_namespaces=True)
            server.address = self.getsymval(sym='j')
            server.ip = self.getsymval(sym='{daemon_addr}')

            match family:
                case AddressFamily.AF_INET:
                    network_type = 'ipv4'
                case AddressFamily.AF_INET6:
                    network_type = 'ipv6'
                case _:
                    network_type = None

            if network_type:
                network: Network = self._ecs_base.get_field_value(field_name='network', create_namespaces=True)
                network.type = network_type
                self._ecs_base.client = Client(ip=hostaddr[0], port=hostaddr[1])
        except:
            LOG.exception(msg='An unexpected exception occurred in connect.')

        return MILTER_CONTINUE

    @milter_noreply
    def hello(self, hostname: str):
        try:
            self._ecs_base.email.smtp.ehlo = hostname

            if cipher := self.getsymval(sym='{cipher}'):
                tls: TLS = self._ecs_base.get_field_value(field_name='tls', create_namespaces=True)
                tls.cipher = cipher

            if tls_version := self.getsymval(sym='{tls_version}'):
                if match := TLS_VERSION_PATTERN.match(string=tls_version):
                    tls: TLS = self._ecs_base.get_field_value(field_name='tls', create_namespaces=True)
                    match_groupdict: dict[str, str] = match.groupdict()
                    tls.version_protocol = match_groupdict['protocol'].lower()
                    tls.version = match_groupdict['number']
        except:
            LOG.exception(msg='An unexpected exception occurred in hello.')

        return MILTER_CONTINUE

    @milter_noreply
    def envfrom(self, f: str, *args):
        try:
            address_name, real_address = decode_address(address=f)
            self._ecs_base.email.sender = Sender(name=address_name, address=real_address, original=f)
        except:
            LOG.exception(msg='An unexpected exception occurred in envfrom.')

        return MILTER_CONTINUE

    @milter_noreply
    def envrcpt(self, to: str, *args):
        try:
            address_name, real_address = decode_address(address=to)
            self._ecs_base.email.smtp.rcpt_to = RcptTo(name=address_name, address=real_address, original=to)
        except:
            LOG.exception(msg='An unexpected exception occurred in envrcpt.')

        return MILTER_CONTINUE

    def header_bytes(self, fld: str, val: bytes):
        self._message.write(fld.encode(encoding='ascii') + b': ' + val + b'\n')

        return MILTER_CONTINUE

    @milter_noreply
    def header(self, field: str, value: str):
        try:
            fixed_field = field.replace('-', '_').lower()

            match fixed_field:
                case 'x_mailer':
                    self._ecs_base.email.x_mailer = value
                case 'x_original_ip':
                    self._ecs_base.email.x_original_ip = value
                case 'x_user_agent':
                    self._ecs_base.email.x_user_agent = value
                case 'message_id':
                    self._ecs_base.email.message_id = email_util_parseaddr(addr=value)[1]
                case 'subject':
                    self._ecs_base.email.subject = value
                case 'date':
                    self._ecs_base.email.origination_timestamp = datetime.fromtimestamp(
                        mktime(email_utils_parsedate(data=value))
                    )
                case 'content_type':
                    self._ecs_base.email.content_type = value
                case 'bcc' | 'cc' | 'from' | 'to' | 'reply_to':
                    name_list: list[str | None] = []
                    address_list: list[str] = []

                    for name, address in decode_address_line(line=value):
                        name_list.append(name)
                        address_list.append(address)

                    setattr_field: str = fixed_field

                    constructor = None

                    match fixed_field:
                        case 'bcc':
                            constructor = BCC
                        case 'cc':
                            constructor = CC
                        case 'from':
                            constructor = From
                            setattr_field = 'from_'
                        case 'to':
                            constructor = To
                        case 'reply_to':
                            constructor = ReplyTo
                        case _:
                            LOG.warning(
                                msg='An unexpected fixed field value was encountered.',
                                extra=dict(
                                    error=dict(input=fixed_field),
                                    _ecs_logger_handler_options=dict(merge_extra=True)
                                )
                            )

                    if constructor:
                        setattr(self._ecs_base.email, setattr_field, constructor(name=name_list, address=address_list))

            self._headers[fixed_field].append(value)
        except:
            LOG.exception(msg='An unexpected exception occurred in header.')

        return MILTER_CONTINUE

    @milter_noreply
    def eoh(self):
        try:
            self._message.write('\n')
            self._ecs_base.email.headers = dict(self._headers)
        except:
            LOG.exception(msg='An unexpected exception occurred in eoh.')

        return MILTER_CONTINUE

    @milter_noreply
    def body(self, blk: bytes):
        self._message.write(blk)
        return MILTER_CONTINUE

    def eom(self):
        try:
            email_attachment_file_list = email_file_attachments_from_email_message(
                email_message=email_message_from_bytes(self._message.getvalue())
            )
            if email_attachment_file_list:
                self._ecs_base.email.attachments = [
                    EmailAttachment(file=email_attachment_file)
                    for email_attachment_file in email_attachment_file_list
                ]
            LOG.info(
                msg='An incoming email was logged.',
                extra=dict(self._ecs_base) | dict(_ecs_logger_handler_options=dict(merge_extra=True))
            )
        except:
            LOG.exception(msg='An unexpected exception occurred in eom.')

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

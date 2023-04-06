#!/usr/bin/env python

from logging import Logger, getLogger, INFO
from logging.handlers import TimedRotatingFileHandler
from typing import Type
from multiprocessing import Process
from socket import AddressFamily
from collections import defaultdict
from email.utils import parseaddr as email_util_parseaddr, parsedate as email_utils_parsedate
from functools import partial

import Milter
from Milter import noreply as milter_noreply, CONTINUE as MILTER_CONTINUE, Base as MilterBase, \
    uniqueID as milter_unique_id
from ecs_py import Email, BCC, CC, From, To, ReplyTo, RcptTo, SMTP, Sender, Base, Server, Network, Client
from ecs_tools_py import make_log_handler

from log_milter import decode_address, decode_address_line
from log_milter.cli import LogMilterArgumentParser

LOG: Logger = getLogger(__name__)
log_handler = make_log_handler(
    base_class=TimedRotatingFileHandler,
    provider_name='tshark_ecs',
    generate_field_names=('event.timezone', 'host.name', 'host.hostname')
)(filename='log_milter.log', when='D')

LOG.addHandler(hdlr=log_handler)
LOG.setLevel(level=INFO)


class LogMilter(MilterBase):

    def __init__(self, server_port: int | None = None, network_transport: str | None = None):
        self.id = milter_unique_id()

        self._ecs_base: Base = Base(email=Email(smtp=SMTP(), direction='inbound'))

        if server_port:
            self._ecs_base.server = Server(port=server_port)
            
        if network_transport:
            self._ecs_base.network = Network(transport=network_transport)

        self._headers: defaultdict[str, list[str]] = defaultdict(list)

    @milter_noreply
    def connect(self, hostname, family, hostaddr):
        server: Server = self._ecs_base.get_field_value(field_name='server', create_namespaces=True)
        server.address = self.getsymval(sym='{daemon_name}')

        match family:
            case AddressFamily.AF_INET:
                network_type = 'ipv4'
            case AddressFamily.AF_INET6:
                network_type = 'ipv6'
            case _:
                network_type = None

        if network_type:
            self._ecs_base.client = Client(
                ip=hostaddr[0],
                port=hostaddr[1]
            )

        return MILTER_CONTINUE

    @milter_noreply
    def hello(self, hostname: str):
        self._ecs_base.email.smtp.ehlo = hostname
        return MILTER_CONTINUE

    @milter_noreply
    def envfrom(self, f: str, *args):
        address_name, real_address = decode_address(address=f)
        self._ecs_base.email.sender = Sender(name=address_name, address=real_address, original=f)
        return MILTER_CONTINUE

    @milter_noreply
    def envrcpt(self, to: str, *args):
        address_name, real_address = decode_address(address=to)
        self._ecs_base.email.smtp.rcpt_to = RcptTo(name=address_name, address=real_address, original=to)
        return MILTER_CONTINUE

    @milter_noreply
    def header(self, field, value):
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
                self._ecs_base.email.origination_timestamp = email_utils_parsedate(data=value)
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

        return MILTER_CONTINUE

    @milter_noreply
    def eoh(self):
        self._ecs_base.email.headers = dict(self._headers)
        return MILTER_CONTINUE

    def eom(self):
        LOG.info(
            msg='An incoming email was logged.',
            extra=dict(self._ecs_base) | dict(_ecs_logger_handler_options=dict(merge_extra=True))
        )
        return MILTER_CONTINUE


def main():
    args: Type[LogMilterArgumentParser.Namespace] = LogMilterArgumentParser().parse_args()

    job = Process()
    job.start()

    Milter.factory = partial(
        LogMilter,
        server_port=args.server_port,
        network_transport=args.network_transport
    )

    # Mails are not modified, so no flags.
    Milter.set_flags(0)
    Milter.set_exception_policy(MILTER_CONTINUE)
    Milter.runmilter('log_milter', args.socket_path, args.timeout)
    job.join()


if __name__ == '__main__':
    main()

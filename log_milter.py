#!/usr/bin/env python

from logging import INFO, DEBUG, StreamHandler
from logging.handlers import TimedRotatingFileHandler
from asyncio import run as asyncio_run
from re import compile as re_compile, Pattern as RePattern
from typing import Final
from socket import AddressFamily
from email import message_from_bytes as email_message_from_bytes
from email.utils import parseaddr as email_util_parseaddr
from functools import partial
from io import BytesIO
from time import sleep
from pathlib import Path
from os import umask as os_umask

import Milter
from Milter import noreply as milter_noreply, CONTINUE as MILTER_CONTINUE, Base as MilterBase, \
    uniqueID as milter_unique_id, decode as milter_decode
from ecs_py import SMTP, Sender, Base, Server, Network, Client, TLS, SMTPTranscript, Error
from ecs_tools_py import make_log_handler, email_from_email_message, user_from_smtp_to_from, related_from_ecs_email
from smtp_lib.parse.transcript import parse_transcript

from log_milter import LOG
from log_milter.cli import LogMilterOptionParser


SLEEP_SECONDS: Final[float] = 0.5

TLS_VERSION_PATTERN: Final[RePattern] = re_compile(pattern=r'^(?P<protocol>.+)v(?P<number>[0-9.]+)$')


class LogMilter(MilterBase):
    def __init__(self, transcript_directory: Path | str | None = None):
        self.id = milter_unique_id()

        self._transcript_directory: Path | None = Path(transcript_directory) if transcript_directory else None

        self._ecs_base: Base = Base(error=Error(), smtp=SMTP(), tls=TLS())

        self._message: BytesIO = BytesIO()

    @milter_noreply
    def connect(self, hostname, family, hostaddr):
        try:
            LOG.debug(msg=f'{id(self)}: Entering connect')
            self._ecs_base.server = Server(address=self.getsymval(sym='j'))
            self._ecs_base.network = Network(transport='tcp')

            client_addr = self.getsymval(sym='{client_addr}')
            client_port = int(self.getsymval(sym='{client_port}'))
            client_name = self.getsymval(sym='{client_name}')

            if client_port != 0:
                self._ecs_base.client = Client(
                    address=client_name if client_name and client_name != 'unknown' else client_addr,
                    ip=client_addr,
                    port=client_port
                )

            daemon_addr = self.getsymval(sym='{daemon_addr}')
            daemon_port = int(self.getsymval(sym='{daemon_port}'))

            if daemon_port != 0:
                self._ecs_base.server.ip = daemon_addr
                self._ecs_base.server.port = daemon_port

            match family:
                case AddressFamily.AF_INET:
                    network_type = 'ipv4'
                case AddressFamily.AF_INET6:
                    network_type = 'ipv6'
                case _:
                    network_type = None

            self._ecs_base.network.type = network_type
        except:
            LOG.exception(msg='An unexpected exception occurred in connect.')

        return MILTER_CONTINUE

    @milter_noreply
    def hello(self, hostname: str):
        try:
            LOG.debug(msg=f'{id(self)}: Entering hello')
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
            LOG.debug(msg=f'{id(self)}: Entering envfrom')
            self._ecs_base.smtp.mail_from = email_util_parseaddr(addr=f)[1]
        except:
            LOG.exception(msg='An unexpected exception occurred in envfrom.')

        return MILTER_CONTINUE

    @milter_noreply
    def envrcpt(self, to: str, *args):
        try:
            LOG.debug(msg=f'{id(self)}: Entering envrcpt')
            self._ecs_base.smtp.rcpt_to = email_util_parseaddr(addr=to)[1]
        except:
            LOG.exception(msg='An unexpected exception occurred in envrcpt.')

        return MILTER_CONTINUE

    @milter_noreply
    @milter_decode('bytes')
    def header(self, fld: str, val: bytes):
        try:
            LOG.debug(msg=f'{id(self)}: Entering header')
            self._message.write(fld.encode(encoding='ascii') + b': ' + val + b'\r\n')
        except:
            LOG.exception(msg='An unexpected exception occurred in header_bytes.')

        return MILTER_CONTINUE

    @milter_noreply
    def eoh(self):
        try:
            LOG.debug(msg=f'{id(self)}: Entering eoh')
            self._message.write(b'\r\n')
        except:
            LOG.exception(msg='An unexpected exception occurred in eoh.')

        return MILTER_CONTINUE

    @milter_noreply
    def body(self, blk: bytes):
        LOG.debug(msg=f'{id(self)}: Entering body')
        self._message.write(blk)
        return MILTER_CONTINUE

    def close(self):
        try:
            LOG.debug(msg=f'{id(self)}: Entering close')
            try:
                if message_bytes := self._message.getvalue():
                    self._ecs_base.email = email_from_email_message(
                        email_message=email_message_from_bytes(message_bytes),
                        include_raw_headers=True,
                        extract_attachments=True,
                        extract_bodies=True,
                        extract_attachment_contents=False,
                        extract_body_content=True
                    )

                    if mail_from := self._ecs_base.smtp.mail_from:
                        self._ecs_base.email.sender = Sender(address=mail_from)

                    if bodies := self._ecs_base.email.bodies:
                        if any(body.content_type == 'text/plain' for body in bodies):
                            for body in bodies:
                                if body.content_type != 'text/plain':
                                    body.content = None
            except:
                LOG.exception(
                    msg='An unexpected exception occurred when attempting to create a email.message.Message from bytes.'
                )

            if ecs_email := self._ecs_base.email:
                try:
                    self._ecs_base.related = related_from_ecs_email(ecs_email=ecs_email)
                except:
                    LOG.exception(
                        msg='An unexpected exception occurred when attempting to create related information.'
                    )

            try:
                ecs_from, ecs_to = (
                    (ecs_email.from_, ecs_email.to)
                    if (ecs_email := self._ecs_base.email) else (None, None)
                )

                self._ecs_base.user = user_from_smtp_to_from(
                    ecs_smtp=self._ecs_base.smtp,
                    ecs_from=ecs_from,
                    ecs_to=ecs_to
                )
            except:
                LOG.exception(
                    msg='An unexpected exception occurred when create user information from an SMTP entry.'
                )

            if self._transcript_directory and self._ecs_base.client and self._ecs_base.server:
                try:
                    client_ip = self._ecs_base.client.ip
                    client_port = self._ecs_base.client.port
                    server_ip = self._ecs_base.server.ip
                    server_port = self._ecs_base.server.port
                    # NOTE: I don't like to use sleep at all... Affects mail server throughput?
                    sleep(SLEEP_SECONDS)

                    transcript_path = self._transcript_directory / f'{server_ip}_{server_port}_{client_ip}_{client_port}'
                    transcript_data: str = transcript_path.read_text()

                    try:
                        transcript_path.unlink()
                    except:
                        LOG.exception(msg='An error occurred when attempting to unlink a transcript path.')

                    self._ecs_base.smtp.transcript = SMTPTranscript(original=transcript_data)

                    exchange, extra_exchange_data = parse_transcript(transcript_data=transcript_data)
                    self._ecs_base.smtp.transcript.exchange = exchange
                    if local_id := extra_exchange_data.queue_id:
                        self._ecs_base.email.local_id = local_id

                    if error_message := extra_exchange_data.error_message:
                        self._ecs_base.error.message = error_message

                    if error_code := extra_exchange_data.error_code:
                        self._ecs_base.error.code = error_code

                    if error_type := extra_exchange_data.error_type:
                        self._ecs_base.error.type = error_type
                except Exception:
                    LOG.exception(
                        msg='An error occurred when attempting to obtain SMTP transcript information.'
                    )

            LOG.info(
                msg='SMTP traffic was observed.',
                extra=dict(self._ecs_base) | dict(_ecs_logger_handler_options=dict(merge_extra=True))
            )
        except:
            LOG.exception(msg='An unexpected exception occurred in close.')

        return MILTER_CONTINUE


async def main():
    try:
        args: LogMilterOptionParser.Namespace = LogMilterOptionParser().parse_options(
            read_config_options=dict(raise_exception=False)
        )

        log_handler_args = dict(
            provider_name='log_milter',
            generate_field_names=('event.timezone', 'host.name', 'host.hostname')
        )
        if args.log_path:
            log_handler = make_log_handler(
                base_class=TimedRotatingFileHandler,
                **log_handler_args
            )(filename=args.log_path, when='D')
        else:
            log_handler = make_log_handler(
                base_class=StreamHandler,
                **log_handler_args
            )()

        LOG.addHandler(hdlr=log_handler)
        LOG.setLevel(level=DEBUG if args.verbose else INFO)

        Milter.factory = partial(LogMilter, transcript_directory=args.transcript_directory)

        # Make the socket that `Milter.runmilter` creates writable.
        # Not nice to do it globally liske this, but the socket cannot already exist and must be created by
        # `Milter.runmilter`.
        os_umask(0o011)

        # Mails are not modified, so no flags.
        Milter.set_flags(0)
        Milter.set_exception_policy(MILTER_CONTINUE)
        Milter.runmilter('log_milter', args.socket_path, args.timeout)
    except KeyboardInterrupt:
        pass
    except Exception:
        LOG.exception(msg='An unexpected exception occurred.')


if __name__ == '__main__':
    asyncio_run(main())

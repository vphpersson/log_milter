#!/usr/bin/env python

from logging import INFO
from logging.handlers import TimedRotatingFileHandler
from asyncio import run as asyncio_run
from re import compile as re_compile, Pattern as RePattern
from typing import Type, Final
from dataclasses import dataclass
from socket import AddressFamily
from email import message_from_bytes as email_message_from_bytes
from email.utils import parseaddr as email_util_parseaddr
from functools import partial
from io import BytesIO
from time import sleep
from pathlib import Path


import Milter
from Milter import noreply as milter_noreply, CONTINUE as MILTER_CONTINUE, Base as MilterBase, \
    uniqueID as milter_unique_id, decode as milter_decode
from ecs_py import SMTP, Sender, Base, Server, Network, Client, TLS, SMTPTranscript, SMTPExchange, SMTPRequest, \
    SMTPResponse, SMTPEnhancedStatusCode, Error
from ecs_tools_py import make_log_handler, email_from_email_message, user_from_smtp_to_from, related_from_ecs_email

from log_milter import LOG
from log_milter.cli import LogMilterArgumentParser


SLEEP_SECONDS: Final[float] = 0.5

TLS_VERSION_PATTERN: Final[RePattern] = re_compile(pattern=r'^(?P<protocol>.+)v(?P<number>[0-9.]+)$')

_SMTP_RESPONSE_PATTERN: Final[RePattern] = re_compile(
    pattern=r'^(?P<status_code>[0-9]{3})(\s(?P<enhanced_status_code>[0-9]\.[0-9]\.[0-9]))?\s(?P<text>.+)$'
)

_SMTP_MULTILINE_RESPONSE_PATTERN: Final[RePattern] = re_compile(
    pattern=r'^(?P<status_code>[0-9]{3})(-(?P<enhanced_status_code>[0-9]\.[0-9]{1,3}\.[0-9]{1,3}))?-(?P<text>.+)$'
)

_SMTP_COMMAND_PATTERN: Final[RePattern] = re_compile(
    pattern=r'^(?P<command>[^ ]+)( (?P<arguments>.+))?$'
)

_SMTP_QUEUED_AS_PATTERN: Final[RePattern] = re_compile(
    pattern=r'^250( 2\.0\.0)? Ok: ([0-9]+ bytes )?queued as (?P<queue_id>.+)$'
)

_ENHANCED_STATUS_CODE_PATTERN: Final[RePattern] = re_compile(
    pattern='^(?P<class>[0-9]{1,3})\.(?P<subject>[0-9]{1,3})\.(?P<detail>[0-9]{1,3})$'
)


@dataclass
class ExtraExchangeData:
    queue_id: str | None = None
    error_message: str | None = None
    error_code: str | None = None
    error_type: str | None = None


CLASS_TO_TEXT: Final[dict[str, str]] = {
    "2": 'Success',
    "4": 'Persistent Transient Failure',
    "5": 'Permanent Failure'
}

SUBJECT_TO_TEXT: Final[dict[str, str]] = {
    # "0": 'Other or Undefined Status',
    "1": 'Addressing Status',
    "2": 'Mailbox Status',
    "3": 'Mail System Status',
    "4": 'Network and Routing Status',
    "5": 'Mail Delivery Protocol Status',
    "6": 'Message Content or Media Status',
    "7": 'Security or Policy Status'
}

SUBJECT_DETAIL_TO_TEXT: Final[dict[tuple[str, str], str]] = {
    # ("0", "0"): "Other undefined Status",
    # ("1", "0"): "Other address status",
    ("1", "1"): "Bad destination mailbox address",
    ("1", "2"): "Bad destination system address",
    ("1", "3"): "Bad destination mailbox address syntax",
    ("1", "4"): "Destination mailbox address ambiguous",
    ("1", "5"): "Destination address valid",
    ("1", "6"): "Destination mailbox has moved, No forwarding address",
    ("1", "7"): "Bad sender's mailbox address syntax",
    ("1", "8"): "Bad sender's system address",
    ("1", "9"): "Message relayed to non-compliant mailer",
    ("1", "10"): "Recipient address has null MX",
    ("2", "0"): "Other or undefined mailbox status",
    ("2", "1"): "Mailbox disabled, not accepting messages",
    ("2", "2"): "Mailbox full",
    ("2", "3"): "Message length exceeds administrative limit",
    ("2", "4"): "Mailing list expansion problem",
    ("3", "0"): "Other or undefined mail system status",
    ("3", "1"): "Mail system full",
    ("3", "2"): "System not accepting network messages",
    ("3", "3"): "System not capable of selected features",
    ("3", "4"): "Message too big for system",
    ("3", "5"): "System incorrectly configured",
    ("3", "6"): "Requested priority was changed",
    ("4", "0"): "Other or undefined network or routing status",
    ("4", "1"): "No answer from host",
    ("4", "2"): "Bad connection",
    ("4", "3"): "Directory server failure",
    ("4", "4"): "Unable to route",
    ("4", "5"): "Mail system congestion",
    ("4", "6"): "Routing loop detected",
    ("4", "7"): "Delivery time expired",
    ("5", "0"): "Other or undefined protocol status",
    ("5", "1"): "Invalid command",
    ("5", "2"): "Syntax error",
    ("5", "3"): "Too many recipients",
    ("5", "4"): "Invalid command arguments",
    ("5", "5"): "Wrong protocol version",
    ("5", "6"): "Authentication Exchange line is too long",
    ("6", "0"): "Other or undefined media error",
    ("6", "1"): "Media not supported",
    ("6", "2"): "Conversion required and prohibited",
    ("6", "3"): "Conversion required but not supported",
    ("6", "4"): "Conversion with loss performed",
    ("6", "5"): "Conversion Failed",
    ("6", "6"): "Message content not available",
    ("6", "7"): "Non-ASCII addresses not permitted for that sender/recipient",
    ("6", "8"): "UTF-8 string reply is required, but not permitted by the SMTP client",
    ("6", "9"): "UTF-8 header message cannot be transferred to one or more recipients, so the message must be rejected",
    # ("6", "10"): None,
    ("7", "0"): "Other or undefined security status",
    ("7", "1"): "Delivery not authorized, message refused",
    ("7", "2"): "Mailing list expansion prohibited",
    ("7", "3"): "Security conversion required but not possible",
    ("7", "4"): "Security features not supported",
    ("7", "5"): "Cryptographic failure",
    ("7", "6"): "Cryptographic algorithm not supported",
    ("7", "7"): "Message integrity failure",
    ("7", "8"): "Authentication credentials invalid",
    ("7", "9"): "Authentication mechanism is too weak",
    ("7", "10"): "Encryption Needed",
    ("7", "11"): "Encryption required for requested authentication mechanism",
    ("7", "12"): "A password transition is needed",
    ("7", "13"): "User Account Disabled",
    ("7", "14"): "Trust relationship required",
    ("7", "15"): "Priority Level is too low",
    ("7", "16"): "Message is too big for the specified priority",
    ("7", "17"): "Mailbox owner has changed",
    ("7", "18"): "Domain owner has changed",
    ("7", "19"): "RRVS test cannot be completed",
    ("7", "20"): "No passing DKIM signature found",
    ("7", "21"): "No acceptable DKIM signature found",
    ("7", "22"): "No valid author-matched DKIM signature found",
    ("7", "23"): "SPF validation failed",
    ("7", "24"): "SPF validation error",
    ("7", "25"): "Reverse DNS validation failed",
    ("7", "26"): "Multiple authentication checks failed",
    ("7", "27"): "Sender address has null MX",
    ("7", "28"): "Mail flood detected",
    ("7", "29"): "ARC validation failure",
    ("7", "30"): "REQUIRETLS support required"
}


def _parse_transcript(transcript_data: str) -> tuple[list[SMTPExchange], ExtraExchangeData | None]:

    extra_exchange_data = ExtraExchangeData()

    transcript_data_lines = transcript_data.splitlines()
    if not transcript_data_lines:
        return [], extra_exchange_data

    smtp_exchange_list: list[SMTPExchange] = []
    smtp_request: SMTPRequest | None = None
    response_lines: list[str] = []

    for line in transcript_data_lines:
        if match := _SMTP_RESPONSE_PATTERN.match(string=line):
            group_dict: dict[str, str] = match.groupdict()

            response_lines.append(group_dict['text'])

            enhanced_status_code_ecs: SMTPEnhancedStatusCode | None = None

            if enhanced_status_code := group_dict.get('enhanced_status_code'):
                enhanced_status_code_ecs = SMTPEnhancedStatusCode(original=enhanced_status_code)
                if enhanced_status_code_match := _ENHANCED_STATUS_CODE_PATTERN.match(string=enhanced_status_code):
                    enhanced_status_code_group_dict: dict[str, str] = enhanced_status_code_match.groupdict()

                    class_: str = enhanced_status_code_group_dict['class']
                    enhanced_status_code_ecs.class_ = class_
                    enhanced_status_code_ecs.class_text = CLASS_TO_TEXT.get(class_)

                    subject: str = enhanced_status_code_group_dict['subject']
                    enhanced_status_code_ecs.subject = subject
                    enhanced_status_code_ecs.subject_text = SUBJECT_TO_TEXT.get(subject)

                    detail: str = enhanced_status_code_group_dict['detail']
                    enhanced_status_code_ecs.detail = detail
                    enhanced_status_code_ecs.detail_text = SUBJECT_DETAIL_TO_TEXT.get((subject, detail))

            smtp_exchange_list.append(
                SMTPExchange(
                    request=smtp_request,
                    response=SMTPResponse(
                        status_code=group_dict['status_code'],
                        enhanced_status_code=enhanced_status_code_ecs,
                        lines=response_lines
                    )
                )
            )

            smtp_request = None
            response_lines = []

            if match := _SMTP_QUEUED_AS_PATTERN.match(string=line):
                extra_exchange_data.queue_id = match.groupdict()['queue_id']

        elif match := _SMTP_MULTILINE_RESPONSE_PATTERN.match(string=line):
            response_lines.append(match.groupdict()['text'])
        elif match := _SMTP_COMMAND_PATTERN.match(string=line):
            group_dict = match.groupdict()
            smtp_request = SMTPRequest(
                command=group_dict['command'],
                arguments_string=group_dict['arguments']
            )
        else:
            raise ValueError(f'Malformed SMTP line?: {line}')

    if not extra_exchange_data.queue_id:
        for smtp_exchange in reversed(smtp_exchange_list):
            if response := smtp_exchange.response:
                response_text: str | None = ' '.join(response.lines) if response.lines else None

                if enhanced_status_code_ecs := response.enhanced_status_code:
                    if (class_ := enhanced_status_code_ecs.class_) and class_ in {'4', '5'}:
                        extra_exchange_data.error_code = enhanced_status_code_ecs.original
                        extra_exchange_data.error_message = response_text or enhanced_status_code_ecs.detail_text
                        extra_exchange_data.error_type = 'No message was queued.'
                        break

                if (status_code := response.status_code) and status_code[0] in {'4', '5'}:
                    extra_exchange_data.error_code = status_code
                    extra_exchange_data.error_message = response_text
                    extra_exchange_data.error_type = 'No message was queued.'
                    break

    return smtp_exchange_list, extra_exchange_data


class LogMilter(MilterBase):
    def __init__(self, server_port: int | None = None, transcript_directory: Path | None = None):
        self.id = milter_unique_id()

        self._transcript_directory: Path = transcript_directory

        self._ecs_base: Base = Base(
            client=Client(),
            error=Error(),
            network=Network(transport='tcp'),
            server=Server(),
            smtp=SMTP(),
            tls=TLS()
        )

        # TODO: It would be nice if I could retrieve this via `getsymval`.
        if server_port:
            self._ecs_base.server.port = server_port
            
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
                self._ecs_base.client.address = hostaddr[0]
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

    def close(self):
        try:
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

            if self._transcript_directory and self._ecs_base.client:
                try:
                    client_address = self._ecs_base.client.address
                    client_port = self._ecs_base.client.port
                    # NOTE: I don't like to use sleep at all... Affects mail server throughput?
                    sleep(SLEEP_SECONDS)

                    transcript_data: str = (self._transcript_directory / f'{client_address}_{client_port}').read_text()

                    self._ecs_base.smtp.transcript = SMTPTranscript(original=transcript_data)

                    exchange, extra_exchange_data = _parse_transcript(transcript_data=transcript_data)
                    self._ecs_base.smtp.transcript.exchange = exchange
                    if local_id := extra_exchange_data.queue_id:
                        self._ecs_base.email.local_id = local_id

                    if error_message := extra_exchange_data.error_message:
                        self._ecs_base.error.message = error_message

                    if error_code := extra_exchange_data.error_code:
                        self._ecs_base.error.code = error_code

                    if error_type := extra_exchange_data.error_type:
                        self._ecs_base.error.type = error_type
                except:
                    LOG.exception(
                        msg='An error occurred when attempting to obtain SMTP transcript information.'
                    )

            LOG.info(
                msg='An incoming email was logged.',
                extra=dict(self._ecs_base) | dict(_ecs_logger_handler_options=dict(merge_extra=True))
            )
        except:
            LOG.exception(msg='An unexpected exception occurred in close.')

        return MILTER_CONTINUE


async def main():
    try:
        args: LogMilterArgumentParser.Namespace = LogMilterArgumentParser().parse_options(
            read_config_options=dict(raise_exception=False)
        )

        log_handler = make_log_handler(
            base_class=TimedRotatingFileHandler,
            provider_name='log_milter',
            generate_field_names=('event.timezone', 'host.name', 'host.hostname')
        )(filename=args.log_path, when='D')

        LOG.addHandler(hdlr=log_handler)
        LOG.setLevel(level=INFO)

        Milter.factory = partial(
            LogMilter,
            server_port=args.server_port,
            transcript_directory=args.transcript_directory
        )

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

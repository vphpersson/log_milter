from logging import getLogger, Logger
from typing import Final
from sys import exc_info

from email.header import decode_header
from email import message_from_string as email_message_from_string
from email.utils import parseaddr as email_util_parseaddr, getaddresses as email_utils_getaddresses


LOG: Final[Logger] = getLogger(__name__)


def decode_address_name(address_name: str) -> str | None:
    if not address_name:
        return None

    value: bytes
    encoding: str | None
    try:
        value, encoding = decode_header(header=address_name)
    except:
        LOG.warning(
            msg='An error occurred when decoding an address name.',
            extra=dict(
                error=dict(input=address_name),
                _ecs_logger_handler_options=dict(merge_extra=True)
            ),
            exc_info=exc_info()
        )
        return address_name

    return value.decode(encoding=encoding) if encoding else address_name


def decode_address(address: str) -> tuple[str | None, str]:
    address_name: str | None
    real_address: str
    address_name, real_address = email_util_parseaddr(addr=address)

    address_name = decode_address_name(address_name=address_name)

    return address_name, real_address


def decode_address_line(line: str) -> list[tuple[str | None, str]]:
    return [
        (
            decode_address_name(address_name=address_name),
            real_address
        )
        for address_name, real_address in email_utils_getaddresses(
            email_message_from_string(f'To: {line}').get_all('To', [])
        )
    ]

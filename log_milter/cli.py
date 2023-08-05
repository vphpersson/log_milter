from option_parser import OptionParser
from ecs_tools_py import make_log_action

from log_milter import LOG


class LogMilterOptionParser(OptionParser):
    class Namespace:
        socket_path: str
        timeout: int
        server_port: int | None
        transcript_directory: str | None = None
        verbose: bool = False

    def __init__(self, *args, **kwargs):
        super().__init__(
            *args,
            **(
                dict(description='Run a milter that performs logging.') | kwargs
            )
        )

        self.add_argument(
            'socket_path',
            help='The path of the socket on which the milter will listen..'
        )

        self.add_argument(
            '--timeout',
            help='The number of seconds to wait before considering the milter dead.',
            type=int,
            default=30
        )

        self.add_argument(
            '--transcript-directory',
            default='.',
            help='The path of a directory from which to read transcripts.'
        )

        self.add_argument(
            '--log',
            help='A log specifier specifying how logging is to be performed.',
            action=make_log_action(event_provider='log_milter', log=LOG)
        )

        self.add_argument(
            '-v', '--verbose',
            help='Log in verbose mode.',
            action='store_true'
        )

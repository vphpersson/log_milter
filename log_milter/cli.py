from pathlib import Path
from option_parser import OptionParser


class LogMilterArgumentParser(OptionParser):
    class Namespace:
        socket_path: str
        timeout: int
        server_port: int | None
        transcript_directory: Path | None = None

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
            '--server-port',
            type=int,
            help='The port on which the mail server receiving incoming email.'
        )

        self.add_argument(
            '--transcript-directory',
            type=Path,
            default='.',
            help='The path of a directory from which to read transcripts.'
        )

from typed_argument_parser import TypedArgumentParser


class LogMilterArgumentParser(TypedArgumentParser):
    class Namespace:
        socket_path: str
        timeout: int
        server_port: int | None
        network_transport: str | None

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
            '--network-transport',
            help='The network transport that is used for receiving incoming email.'
        )
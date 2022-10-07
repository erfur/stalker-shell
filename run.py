import frida
import sys
from loguru import logger
import pprint
import json
import binascii
import time
from prompt_toolkit import prompt, PromptSession, print_formatted_text, ANSI
from prompt_toolkit.completion import WordCompleter, NestedCompleter, Completer, Completion

pp = pprint.PrettyPrinter(width=120)

# set severity to INFO
logger.remove()
logger.add(lambda msg: print_formatted_text(ANSI(msg), end=''),
           colorize=True, level="INFO")


def on_message(message, data):
    if not message['type'] == 'send':
        return

    t = message['payload']['type']
    p = message['payload']['payload']

    match t:
        case 'error':
            logger.warning(p)
        case 'info':
            logger.info(p)
        case 'blob':
            logger.info(binascii.hexlify(message['data']))
        case 'json':
            logger.info(pp.pformat(p))
        case _:
            logger.info('unknown message type: %s' % pp.pformat(message))


def save_binary(data, maps):
    logger.debug(pp.pformat(data))
    final_data = {}
    for tid, cache in data:
        final_data[tid] = []
        for blob in cache:
            for (src, dst, _) in blob:
                final_data[tid].append((src, dst))

    timestamp = time.strftime("%Y%m%d-%H%M%S")
    fname_trace = f'stalker-{timestamp}-trace.json'
    fname_maps = f'stalker-{timestamp}-maps.json'

    with open(fname_trace, 'w') as f:
        json.dump(final_data, f)
        logger.info(f"saved in file {fname_trace}")

    with open(fname_maps, 'w') as f:
        json.dump(maps, f)
        logger.info(f'saved maps in file {fname_maps}')


class StalkerApi:

    api_prefix = '_cmd_'

    def __init__(self, api):
        self.api = api

    @property
    def cmds(self) -> list[str]:
        return [cmd[len(self.api_prefix):] for cmd in self.__class__.__dict__.keys()
                if cmd.startswith(self.api_prefix)]

    def __call__(self, *args: any, **kwargs: any) -> any:
        if args and args[0] in self.cmds:
            self.__class__.__dict__[self.api_prefix+args[0]](self, *args[1:])
        else:
            logger.warning("invalid cmd")

    def _cmd_logaddr(self, *args):
        match args:
            case [addr]:
                self.api.logaddr(addr)
            case _:
                logger.warning("need address to intercept")

    def _cmd_logmodule(self, *args):
        match args:
            case [filename]:
                with open(filename) as f:
                    self.api.logmodule(f.read())
            case _:
                logger.warning("need json file")

    def _cmd_maps(self, *args):
        logger.info(pp.pformat(self.api.maps()))

    def _cmd_threads(self, *args):
        logger.info(pp.pformat(self.api.threads()))

    def _cmd_stalk(self, *args):
        match args:
            case ['thread', thread_no]:
                self.api.stalk(int(thread_no))
            case _:
                self.api.stalk()

    def _cmd_stalkinterval(self, delay, interval, *args):
        self.api.stalkinterval(float(delay), float(interval))
    
    def _cmd_stalkaddr(self, addr, *args):
        if '+' in addr:
            module, addr = addr.split('+')
            self.api.stalkaddr(addr, module)
        else:
            self.api.stalkaddr(addr)

    def _cmd_unstalk(self, *args):
        match args:
            case ['thread', thread_no]:
                self.api.unstalk(int(thread_no))
            case _:
                self.api.unstalk()

    def _cmd_save(self, *args):
        save_binary(self.api.results(), self.api.maps())

    def _cmd_reset(self, *args):
        self.api.reset()

    def _cmd_exit(self, *args):
        raise EOFError


def main(target_process):
    device = frida.get_local_device()

    try:
        is_spawn = False
        pid = int(target_process)
    except ValueError:
        is_spawn = True
        pid = device.spawn(target_process)
        logger.info('spawned app with pid %d' % pid)

    session = device.attach(pid)

    # this directly calls the given entrypoint, not what we want
    # device.inject_library_file(pid, "./custom-blitter/stretch.dll", "entry0", "test")

    with open('_agent.js') as f:
        script = session.create_script(f.read(), runtime='v8')

    script.on('message', on_message)
    script.load()

    api = StalkerApi(script.exports)

    if is_spawn:
        device.resume(pid)

    repl(api)

    # session.detach()
    try:
        device.kill(pid)
    except frida.NotSupportedError:
        logger.info("process is already dead.")


def repl(api: StalkerApi):
    session = PromptSession()
    # simple completion
    cmd_completer = WordCompleter(api.cmds)

    # nested completion
    # completer = NestedCompleter.from_nested_dict({
    #     'stalk': {
    #         'function': None,
    #         'module': None,
    #     },
    #     'unstalk': None,
    #     'exit': None,
    # })

    # custom completion
    # class MyCustomCompleter(Completer):
    #     def get_completions(self, document, complete_event):
    #         yield Completion('completion', start_position=0)

    try:
        while True:
            text = session.prompt('>> ', completer=cmd_completer)
            # text = input('>> ')
            # logger.debug(f"You entered {text}")
            api(*text.split())
    except (KeyboardInterrupt, EOFError):
        logger.info('exiting.')
    except Exception as e:
        logger.error('exception: %s' % e)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: %s <process name or PID>" % __file__)
        sys.exit(1)

    main(sys.argv[1])

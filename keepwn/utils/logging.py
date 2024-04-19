from itertools import cycle
from shutil import get_terminal_size
from threading import Thread
from time import sleep

# TODO: replace termcolor with colorama (active, with unit tests)
from termcolor import cprint, colored


def print_success(string):
    cprint("[", attrs=["bold"], end="")
    cprint("+", "green", attrs=["bold"], end="")
    cprint("]", attrs=["bold"], end=" ")
    print(string)

def print_success_target(target, string):
    cprint("[", attrs=["bold"], end="")
    cprint(target, "green", attrs=["bold"], end="")
    cprint("]", attrs=["bold"], end=" ")
    print(string)

def print_error(string):
    cprint("[", attrs=["bold"], end="")
    cprint("-", "red", attrs=["bold"], end="")
    cprint("]", attrs=["bold"], end=" ")
    print(string)

def print_error_target(target, string):
    cprint("[", attrs=["bold"], end="")
    cprint(target, "red", attrs=["bold"], end="")
    cprint("]", attrs=["bold"], end=" ")
    print(string)

def print_info(string):
    cprint("[", attrs=["bold"], end="")
    cprint("*", "blue", attrs=["bold"], end="")
    cprint("]", attrs=["bold"], end=" ")
    print(string)

def print_info_target(target, string):
    cprint("[", attrs=["bold"], end="")
    cprint(target, "blue", attrs=["bold"], end="")
    cprint("]", attrs=["bold"], end=" ")
    print(string)

def print_warning(string):
    cprint("[", attrs=["bold"], end="")
    cprint("!", "yellow", attrs=["bold"], end="")
    cprint("]", attrs=["bold"], end=" ")
    print(string)

def print_warning_target(target, string):
    cprint("[", attrs=["bold"], end="")
    cprint(target, "blue", attrs=["bold"], end="")
    cprint("]", attrs=["bold"], end=" ")
    print(string)

def print_debug(string):
    cprint("[", attrs=["bold"], end="")
    cprint("#", "grey", attrs=["bold"], end="")
    cprint("]", attrs=["bold"], end=" ")
    print(string)

def print_debug_target(target, string):
    cprint("[", attrs=["bold"], end="")
    cprint(target, "grey", attrs=["bold"], end="")
    cprint("]", attrs=["bold"], end=" ")
    print(string)

def print_found_plugins(plugins, share, plugin_folder_path):
    if plugins:
        message = 'Found '
        for i, plugin in enumerate(plugins):
            message += colored(plugin, 'yellow')
            if len(plugin) > 1 and i < len(plugins)-1:
                message += ', '
        message += ' in folder {}'.format(format_path('\\\\{}{}'.format(share, plugin_folder_path)))
        print_info(message)
    else:
        print_info("No plugin found in {}".format(format_path('\\\\{}{}'.format(share, plugin_folder_path))))


def format_path(path):
    return colored("'" + path + "'", "blue")


def display_smb_error(error, target, multiple_display=False):
    str_error = str(error)
    if 'Errno' in str_error:
        print_error_target(target, str_error.split('] ')[-1].capitalize())
    elif 'SMB' in str_error:
        if 'STATUS_ACCESS_DENIED' in str_error:
            if multiple_display:
                print_error_target(target, str_error.split('(')[0] + ', are you sure that you have admin rights on the host?')
            else:
                print_error(str_error.split('(')[0] + ', are you sure that you have admin rights on the host?')
        else:
            if multiple_display:
                print_error_target(target, str_error.split('(')[0])
            else:
                print_error(str_error.split('(')[0])
    else:
        if multiple_display:
            print_error_target(target, "Unknown error while connecting to target: {}".format(str_error))
        else:
            print_error("Unknown error while connecting to target: {}".format(str_error))
    return

class Loader: # taken from https://stackoverflow.com/questions/22029562/python-how-to-make-simple-animated-loading-while-process-is-running
    def __init__(self, desc="", end="", timeout=0.05):
        """
        A loader-like context manager

        Args:
            desc (str, optional): The loader's description. Defaults to "Loading...".
            end (str, optional): Final print. Defaults to "Done!".
            timeout (float, optional): Sleep time between prints. Defaults to 0.1.
        """
        self.desc = desc
        self.end = end
        self.timeout = timeout

        self._thread = Thread(target=self._animate, daemon=True)
        self.steps = ["[⠋]", "[⠙]", "[⠹]", "[⠸]", "[⠼]", "[⠴]", "[⠦]", "[⠧]", "[⠇]", "[⠏]"]
        self.done = False

    def start(self):
        self._thread.start()
        return self

    def _animate(self):
        for c in cycle(self.steps):
            if self.done:
                break
            print(f"\r{c} {self.desc}", flush=True, end="")
            sleep(self.timeout)

    def __enter__(self):
        self.start()

    def stop(self):
        self.done = True
        cols = get_terminal_size((80, 20)).columns
        print("\r" + " " * cols, end="", flush=True)
        print(f"\r{'[' + colored('*', 'blue') + '] ' + self.end}", flush=True)

    def __exit__(self, exc_type, exc_value, tb):
        # handle exceptions with those variables ^
        self.stop()
from itertools import cycle
from shutil import get_terminal_size
from threading import Thread
from time import sleep

from termcolor import cprint

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

def print_alert(string):
    cprint("[", attrs=["bold"], end="")
    cprint("!", "yellow", attrs=["bold"], end="")
    cprint("]", attrs=["bold"], end=" ")
    print(string)

def print_alert_target(target, string):
    cprint("[", attrs=["bold"], end="")
    cprint(target, "blue", attrs=["bold"], end="")
    cprint("]", attrs=["bold"], end=" ")
    print(string)

def print_found_cache(target, folders_list):
    cprint("[", attrs=["bold"], end="")
    cprint(target, "green", attrs=["bold"], end="")
    cprint("]", attrs=["bold"], end=" ")

    for folder in folders_list:
        cprint("Found ", end="")
        cprint("'{}' ".format(folder), "blue", end="")
        cprint("(cache folder)", "red")

def print_not_found_cache(target):
    cprint("[", attrs=["bold"], end="")
    cprint(target, "grey", attrs=["bold"], end="")
    cprint("]", attrs=["bold"], end=" ")
    cprint("No plugin cache folder found")


def print_found_keepass(target, path, last_access_message, highlight_priority):
    cprint("[", attrs=["bold"], end="")
    cprint(target, "green", attrs=["bold"], end="")
    cprint("]", attrs=["bold"], end=" ")
    cprint("Found ", end="")
    cprint("'{}'".format(path), "blue", end="")
    cprint(" (LastAccessTime:", "cyan", end=" ")
    if highlight_priority == 'LOW':
        cprint(last_access_message, "yellow", end="")
    elif highlight_priority == 'MEDIUM':
        cprint(last_access_message, "yellow", attrs=["bold"], end="")
    elif highlight_priority == 'HIGH':
        cprint(last_access_message, "yellow", "on_red", attrs=["bold"], end="")
    cprint(")", "cyan")

def print_not_found_keepass(target):
    cprint("[", attrs=["bold"], end="")
    cprint(target, "grey", attrs=["bold"], end="")
    cprint("]", attrs=["bold"], end=" ")
    cprint("No KeePass-related file found")

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
        self.steps = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        self.done = False

    def start(self):
        self._thread.start()
        return self

    def _animate(self):
        for c in cycle(self.steps):
            if self.done:
                break
            print(f"\r{self.desc} {c}", flush=True, end="")
            sleep(self.timeout)

    def __enter__(self):
        self.start()

    def stop(self):
        self.done = True
        cols = get_terminal_size((80, 20)).columns
        print("\r" + " " * cols, end="", flush=True)
        print(f"\r{self.end}", flush=True)

    def __exit__(self, exc_type, exc_value, tb):
        # handle exceptions with those variables ^
        self.stop()

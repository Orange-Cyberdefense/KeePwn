import os

from keepwn.core.parse_dump import parse_dump
from keepwn.core.convert import convert
from keepwn.core.plugin import check_plugin, add_plugin, clean_plugin, poll_plugin
from keepwn.core.search import search
from keepwn.core.trigger import check_trigger, add_trigger, clean_trigger, poll_trigger
from keepwn.utils.parser import parse_args

VERSION = "0.4"
banner = "KeePwn v{} - by Julien BEDEL (@d3lb3_)\n".format(VERSION)

def main():
    if os.name == 'nt':
        os.system('color')  # to make termcolor work on Windows

    options = parse_args()

    if not options.no_banner:
        print(banner)

    # calls the appropriate core function
    if options.mode == 'search':
        search(options)
    if options.mode == 'trigger':
        if options.trigger_mode == 'check':
            check_trigger(options)
        if options.trigger_mode == 'add':
            add_trigger(options)
        if options.trigger_mode == 'remove':
            clean_trigger(options)
        if options.trigger_mode == 'poll':
            poll_trigger(options)
    if options.mode == 'plugin':
        if options.plugin_mode == 'check':
            check_plugin(options)
        if options.plugin_mode == 'add':
            add_plugin(options)
        if options.plugin_mode == 'remove':
            clean_plugin(options)
        if options.plugin_mode == 'poll':
            poll_plugin(options)
    if options.mode == 'parse_dump':
        parse_dump(options)
    if options.mode == 'convert':
        convert(options)

if __name__ == '__main__':
    main()
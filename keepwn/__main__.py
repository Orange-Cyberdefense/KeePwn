from keepwn.core.search import search
from keepwn.core.trigger import check, add, clean, poll
from keepwn.utils.parser import parse_args


VERSION = "0.1"
banner = "KeePwn v{} - by Julien BEDEL (@d3lb3_)\n".format(VERSION)

def main():
    print(banner)
    options = parse_args()
    # calls the appropriate core function
    if options.mode == 'search':
        search(options)
    if options.mode == 'trigger':
        if options.trigger_mode == 'check':
            check(options)
        if options.trigger_mode == 'add':
            add(options)
        if options.trigger_mode == 'remove':
            clean(options)
        if options.trigger_mode == 'poll':
            poll(options)

if __name__ == '__main__':
    main()
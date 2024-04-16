import os

from keepwn.utils.logging import print_info, print_error, print_success
from keepwn.utils.keepass2john import process_database

def convert(options):

    if not os.path.isfile(options.database_path):
        database_name = os.path.basename(options.database_path)
        print_error('{} file not found'.format(database_name))
        exit()

    if options.hash_type == 'john':
        hash = process_database(options.database_path)
    elif options.hash_type == 'hashcat':
        hash = process_database(options.database_path).split(':')[1]
    else:
        print_error("Incorrect hash type, please sepcify 'john' or 'hashcat'")
        exit()

    if hash is not None:
        crack_hint = {'john': 'john --format=keepass', 'hashcat': 'hashcat -m 13400'}
        if options.output_file is not None:
            with open(options.output_file, "w") as f:
                f.write(hash)
            print_success('Hash written to {}, happy cracking! (\x1B[3m{}\x1B[0m)'.format(options.output_file, crack_hint[options.hash_type]))
        else:
            print_success("Happy cracking! (\x1B[3m{}\x1B[0m)".format(crack_hint[options.hash_type]))
            print(hash)
    else:
        print_error('Unknown error during hash extraction')
        exit()
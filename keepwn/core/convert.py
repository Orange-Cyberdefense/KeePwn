from keepwn.utils.logging import print_info, print_error, print_success
from keepwn.utils.keepass2john import process_database

def write_hash(hash, output_file):
    print_info('Writing converted hash in {} file'.format(output_file))
    
    with open(output_file ,"w") as f:
        f.write(hash)

    print_success('Hash written in destination file. Ready to crack.')

def convert(options):
    if options.output_file is None:
        options.output_file = "keepass.hash"
    
    if options.convert_type == 'john':
        print_info('Converting {} in john format'.format(options.database_path))
        hash = process_database(options.database_path)

    elif options.convert_type == 'hashcat':
        print_info('Converting {} in hashcat format'.format(options.database_path))
        hash = process_database(options.database_path).split(':')[1]
    else:
        print_error('Uncorrect convert type, please choose john or hashcat')

    if hash is not None:
        print(hash)
        write_hash(hash, options.output_file)
    else:
        print_error('Error during hash extraction. Aborting')
        exit(0)
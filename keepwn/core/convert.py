from os import popen
from keepwn.utils.logging import print_info, print_error

def write_hash(hash, output_file):
    print_info('Writing converted hash in {} file'.format(output_file))
    
    with open(output_file ,"a") as f:
        f.write(hash)

def convert(options):
    cmd = '~/john/run/keepass2john {}'.format(options.database_path)
    if options.output_file is None:
        options.output_file = "keepass.hash"

    if options.convert_type == 'john':
        print_info('Converting {} in john format'.format(options.database_path))
        hash = popen(cmd).read()

    elif options.convert_type == 'hashcat':
        print_info('Converting {} in hashcat format'.format(options.database_path))
        hash = popen(cmd).read().split(':')[1]
    else:
        print_error('Uncorrect convert type, please choose john or hashcat')

    if hash is not None:
        write_hash(hash, options.output_file)
from os import popen
from keepwn.utils.logging import print_info, print_error

def write_hash(hash):
    filename = "keepass.hash"
    print_info('Writing converted hash in {} file'.format(filename))
    
    with open(filename ,"a") as f:
        f.write(hash)

def convert(convert_type, database_name) -> str:
    if convert_type == 'john':
        print_info('Converting {} in john format'.format(database_name))
        hash = popen('john/run/keepass2john').read()

    elif convert_type == 'hashcat':
        print_info('Converting {} in hashcat format'.format(database_name))
        hash = popen('john/run/keepass2john').read().strip(':')[1]
    else:
        print_error('Uncorrect convert type, please choose john or hashcat')

    if hash is not None:
        write_hash(hash)
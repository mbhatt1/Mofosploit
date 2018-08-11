from util.util import Utilty
from lib import * 
from CreateReport import CreateReport

def show_banner(util, delay_time=2.0):
    banner = u"""
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
███╗   ███╗ ██████╗ ███████╗ ██████╗ ███████╗██████╗ ██╗      ██████╗ ██╗████████╗
████╗ ████║██╔═══██╗██╔════╝██╔═══██╗██╔════╝██╔══██╗██║     ██╔═══██╗██║╚══██╔══╝
██╔████╔██║██║   ██║█████╗  ██║   ██║███████╗██████╔╝██║     ██║   ██║██║   ██║   
██║╚██╔╝██║██║   ██║██╔══╝  ██║   ██║╚════██║██╔═══╝ ██║     ██║   ██║██║   ██║   
██║ ╚═╝ ██║╚██████╔╝██║     ╚██████╔╝███████║██║     ███████╗╚██████╔╝██║   ██║   
╚═╝     ╚═╝ ╚═════╝ ╚═╝      ╚═════╝ ╚══════╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝   ╚═╝   
                                                                                                                      
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    """
    util.print_message(NONE, banner)
    show_credit(util)
    time.sleep(delay_time)


def is_valid_ip(rhost):
    try:
        ipaddress.ip_address(rhost)
        return True
    except ValueError:
        return False


# Define command option.
__doc__ = """{f}
Usage:
    {f} (-t <ip_addr> | --target <ip_addr>) (-m <mode> | --mode <mode>)
    {f} (-t <ip_addr> | --target <ip_addr>) [(-p <port> | --port <port>)] [(-s <product> | --service <product>)]
    {f} -h | --help
Options:
    -t --target   Require  : IP address of target server.
    -m --mode     Require  : Execution mode "train/test".
    -p --port     Optional : Indicate port number of target server.
    -s --service  Optional : Indicate product name of target server.
    -h --help     Optional : Show this screen and exit.
""".format(f=__file__)


# Parse command arguments.
def command_parse():
    args = docopt(__doc__)
    ip_addr = args['<ip_addr>']
    mode = args['<mode>']
    port = args['<port>']
    service = args['<product>']
    return ip_addr, mode, port, service


# Check parameter values.
def check_port_value(port=None, service=None):
    if port is not None:
        if port.isdigit() is False:
            Utilty().print_message(OK, 'Invalid port number: {}'.format(port))
            return False
        elif (int(port) < 1) or (int(port) > 65535):
            Utilty().print_message(OK, 'Invalid port number: {}'.format(port))
            return False
        elif port not in com_port_list:
            Utilty().print_message(OK , 'Not open port number: {}'.format(port))
            return False
        elif service is None:
            Utilty().print_message(OK, 'Invalid service name: {}'.format(str(service)))
            return False
        elif type(service) == 'int':
            Utilty().print_message(OK, 'Invalid service name: {}'.format(str(service)))
            return False
        else:
            return True
    else:
        return False

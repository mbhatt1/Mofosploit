from lib.Util.util import *
from lib import * 
from lib.CreateReport import CreateReport

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


# Common list of all threads.
com_port_list = []
com_exploit_list = []
com_payload_list = []
com_indicate_flag = False


if __name__ == '__main__':
    util = Utilty()

    # Get command arguments.
    rhost, mode, port, service = command_parse()
    if is_valid_ip(rhost) is False:
        util.print_message(FAIL, 'Invalid IP address: {}'.format(rhost))
        exit(1)
    if mode not in ['train', 'test']:
        util.print_message(FAIL, 'Invalid mode: {}'.format(mode))
        exit(1)

    # Show initial banner.
    show_banner(util, 0.1)

    # Initialization of Metasploit.
    env = Metasploit(rhost)
    if rhost in env.prohibited_list:
        util.print_message(FAIL, 'Target IP={} is prohibited.\n'
                                 '    Please check "config.ini"'.format(rhost))
        exit(1)
    nmap_result = 'nmap_result_' + env.rhost + '.xml'
    nmap_command = env.nmap_command + ' ' + nmap_result + ' ' + env.rhost + '\n'
    env.execute_nmap(env.rhost, nmap_command, env.nmap_timeout)
    com_port_list, proto_list, info_list = env.get_port_list(nmap_result, env.rhost)
    com_exploit_list = env.get_exploit_list()
    com_payload_list = env.get_payload_list()
    com_payload_list.append('no payload')

    # Create exploit tree.
    exploit_tree = env.get_exploit_tree()

    # Create target host information.
    com_indicate_flag = check_port_value(port, service)
    if com_indicate_flag:
        target_tree, com_port_list = env.get_target_info_indicate(rhost, proto_list, info_list, port, service)
    else:
        target_tree = env.get_target_info(rhost, proto_list, info_list)

    # Initialization of global option.
    TRAIN_WORKERS = env.train_worker_num
    TEST_WORKER = env.test_worker_num
    MAX_STEPS = env.train_max_steps
    MAX_TRAIN_NUM = env.train_max_num
    Tmax = env.train_tmax

    env.client.termination(env.client.console_id)  # Disconnect common MSFconsole.
    NUM_ACTIONS = len(com_payload_list)  # Set action number.
    NONE_STATE = np.zeros(NUM_STATES)  # Initialize state (s).

    # Define global variable, start TensorFlow session.
    frames = 0                # All trial number of all threads.
    isFinish = False          # Finishing learning/testing flag.
    post_exploit_count = 0    # Number of successful post-exploitation.
    exploit_count = 0         # Number of successful exploitation.
    plot_count = [0]          # Exploitation count list for plot.
    plot_pcount = [0]         # Post-exploit count list for plot.
    SESS = tf.Session()       # Start TensorFlow session.

    with tf.device("/cpu:0"):
        parameter_server = ParameterServer()
        threads = []

        if mode == 'train':
            # Create learning thread.
            for idx in range(TRAIN_WORKERS):
                thread_name = 'local_thread' + str(idx + 1)
                threads.append(Worker_thread(thread_name=thread_name,
                                             thread_type="learning",
                                             parameter_server=parameter_server,
                                             rhost=rhost))
        else:
            # Create testing thread.
            for idx in range(TEST_WORKER):
                thread_name = 'local_thread1'
                threads.append(Worker_thread(thread_name=thread_name,
                                             thread_type="test",
                                             parameter_server=parameter_server,
                                             rhost=rhost))

    # Define saver.
    saver = tf.train.Saver()

    # Execute TensorFlow with multi-thread.
    COORD = tf.train.Coordinator()  # Prepare of TensorFlow with multi-thread.
    SESS.run(tf.global_variables_initializer())  # Initialize variable.

    running_threads = []
    if mode == 'train':
        # Load past learned data.
        if os.path.exists(env.save_file) is True:
            # Restore learned model from local file.
            util.print_message(OK, 'Restore learned data.')
            saver.restore(SESS, env.save_file)

        # Execute learning.
        for worker in threads:
            job = lambda: worker.run(exploit_tree, target_tree, saver, env.save_file)
            t = threading.Thread(target=job)
            t.start()
    else:
        # Execute testing.
        # Restore learned model from local file.
        util.print_message(OK, 'Restore learned data.')
        saver.restore(SESS, env.save_file)
        for worker in threads:
            job = lambda: worker.run(exploit_tree, target_tree)
            t = threading.Thread(target=job)
            t.start()

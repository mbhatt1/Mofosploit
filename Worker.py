
from lib.Util.util import Utilty
from lib import *
from lib.CreateReport import CreateReport
from lib.parameter_server import Server as ParameterServer
from lib.Environment import *


class Worker_thread:
    def __init__(self, thread_name, thread_type, parameter_server, rhost):
        self.environment = Environment(
            thread_name, thread_type, parameter_server, rhost)
        self.thread_name = thread_name
        self.thread_type = thread_type
        self.util = Utilty()

    # Execute learning or testing.
    def run(self, exploit_tree, target_tree, saver=None, train_path=None):
        self.util.print_message(
            NOTE, 'Executing start: {}'.format(self.thread_name))
        while True:
            if self.thread_type == 'learning':
                # Execute learning thread.
                self.environment.run(exploit_tree, target_tree)

                # Stop learning thread.
                if isFinish:
                    self.util.print_message(
                        OK, 'Finish train: {}'.format(self.thread_name))
                    time.sleep(3.0)

                    # Finally save learned weights.
                    self.util.print_message(
                        OK, 'Save learned data: {}'.format(self.thread_name))
                    saver.save(SESS, train_path)

                    # Disconnection RPC Server.
                    self.environment.env.client.termination(
                        self.environment.env.client.console_id)

                    if self.thread_name == 'local_thread1':
                        # Create plot.
                        df_plot = pd.DataFrame({'exploitation': plot_count,
                                                'post-exploitation': plot_pcount})
                        df_plot.to_csv(os.path.join(
                            self.environment.env.data_path, 'experiment.csv'))
                        # df_plot.plot(kind='line', title='Training result.', legend=True)
                        # plt.savefig(self.environment.env.plot_file)
                        # plt.close('all')

                        # Create report.
                        report = CreateReport()
                        report.create_report('train', pd.to_datetime(
                            self.environment.env.scan_start_time))
                    break
            else:
                # Execute testing thread.
                self.environment.run(exploit_tree, target_tree)

                # Stop testing thread.
                if isFinish:
                    self.util.print_message(OK, 'Finish test.')
                    time.sleep(3.0)

                    # Disconnection RPC Server.
                    self.environment.env.client.termination(
                        self.environment.env.client.console_id)

                    # Create report.
                    report = CreateReport()
                    report.create_report('test', pd.to_datetime(
                        self.environment.env.scan_start_time))
                    break

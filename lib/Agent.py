
from lib.imports import *
from lib.Constants import *
from lib.Environment import *
from lib.ML_Modules import ML_Nnet
from lib.parameter_server import Server as ParameterServer
'''
Single Agent
'''


class Agent:
    def __init__(self, name, parameter_server):
        self.brain = ML_NNet(name, parameter_server)
        self.memory = []  # Memory of s,a,r,s_
        self.R = 0.  # Time discounted total reward.

    def act(self, s, available_action_list, eps_steps):
        # Decide action using epsilon greedy.
        if frames >= eps_steps:
            eps = EPS_END
        else:
            # Linearly interpolate
            eps = EPS_START + frames * (EPS_END - EPS_START) / eps_steps

        if random.random() < eps:
            # Randomly select action.
            if len(available_action_list) != 0:
                return available_action_list[random.randint(0, len(available_action_list) - 1)], None, None
            else:
                return 'no payload', None, None
        else:
            # Select action according to probability p[0] (greedy).
            s = np.array([s])
            p = self.brain.predict_p(s)
            if len(available_action_list) != 0:
                prob = []
                for action in available_action_list:
                    prob.append([action, p[0][action]])
                prob.sort(key=lambda s: -s[1])
                return prob[0][0], prob[0][1], prob
            else:
                return 'no payload', p[0][len(p[0]) - 1], None

    # Push s,a,r,s considering advantage to LocalBrain.
    def advantage_push_local_brain(self, s, a, r, s_):
        def get_sample(memory, n):
            s, a, _, _ = memory[0]
            _, _, _, s_ = memory[n - 1]
            return s, a, self.R, s_

        # Create a_cats (one-hot encoding)
        a_cats = np.zeros(NUM_ACTIONS)
        a_cats[a] = 1
        self.memory.append((s, a_cats, r, s_))

        # Calculate R using previous time discounted total reward.
        self.R = (self.R + r * GAMMA_N) / GAMMA

        # Input experience considering advantage to LocalBrain.
        if s_ is None:
            while len(self.memory) > 0:
                n = len(self.memory)
                s, a, r, s_ = get_sample(self.memory, n)
                self.brain.train_push(s, a, r, s_)
                self.R = (self.R - self.memory[0][2]) / GAMMA
                self.memory.pop(0)

            self.R = 0

        if len(self.memory) >= N_STEP_RETURN:
            s, a, r, s_ = get_sample(self.memory, N_STEP_RETURN)
            self.brain.train_push(s, a, r, s_)
            self.R = self.R - self.memory[0][2]
            self.memory.pop(0)

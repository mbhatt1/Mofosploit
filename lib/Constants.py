MIN_BATCH = 5
LOSS_V = .5  # v loss coefficient
LOSS_ENTROPY = .01  # entropy coefficient
LEARNING_RATE = 5e-3
RMSPropDecaly = 0.99

# Params of advantage (Bellman equation)
GAMMA = 0.99
N_STEP_RETURN = 5
GAMMA_N = GAMMA ** N_STEP_RETURN

TRAIN_WORKERS = 10  # Thread number of learning.
TEST_WORKER = 1  # Thread number of testing (default 1)
MAX_STEPS = 20  # Maximum step number.
MAX_TRAIN_NUM = 5000  # Learning number of each thread.
Tmax = 5  # Updating step period of each thread.

# Params of epsilon greedy
EPS_START = 0.5
EPS_END = 0.0
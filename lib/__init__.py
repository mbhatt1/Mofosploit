import sys
import os
import time
import re
import copy
import json
import csv
import codecs
import random
import ipaddress
import configparser
import msgpack
import http.client
import threading
import numpy as np
import pandas as pd
import tensorflow as tf
from bs4 import BeautifulSoup
from docopt import docopt
from keras.models import *
from keras.layers import *
from keras import backend as K



# Warnning for TensorFlow acceleration is not shown.
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'

# Index of target host's state (s).
ST_OS_TYPE = 0    # OS types (unix, linux, windows, osx..).
ST_SERV_NAME = 1  # Product name on Port.
ST_SERV_VER = 2   # Product version.
ST_MODULE = 3     # Exploit module types.
ST_TARGET = 4     # target types (0, 1, 2..).
# ST_STAGE = 5      # exploit's stage (normal, exploitation, post-exploitation).
NUM_STATES = 5    # Size of state.
NONE_STATE = None
NUM_ACTIONS = 0

# Reward
R_GREAT = 100  # Successful of Stager/Stage payload.
R_GOOD = 1     # Successful of Single payload.
R_BAD = -1     # Failure of payload.

# Stage of exploitation
S_NORMAL = -1
S_EXPLOIT = 0
S_PEXPLOIT = 1

# Label type of printing.
OK = 'ok'         # [*]
NOTE = 'note'     # [+]
FAIL = 'fail'     # [-]
WARNING = 'warn'  # [!]
NONE = 'none'     # No label.
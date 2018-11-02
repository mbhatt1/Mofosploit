from lib.imports import *

from lib.Constants import *
from lib.imports import *
class Server:
    def __init__(self):
        # Identify by name to weights by the thread name (Name Space).
        with tf.variable_scope("parameter_server"):
            # Define neural network.
            self.model = self._build_model()

        # Declare server params.
        self.weights_params = tf.get_collection(tf.GraphKeys.TRAINABLE_VARIABLES, scope="parameter_server")
        # Define optimizer.
        self.optimizer = tf.train.RMSPropOptimizer(LEARNING_RATE, RMSPropDecaly)

    # Define neural network.
    def _build_model(self):
        l_input = Input(batch_shape=(None, NUM_STATES))
        l_dense1 = Dense(50, activation='relu')(l_input)
        l_dense2 = Dense(100, activation='relu')(l_dense1)
        l_dense3 = Dense(200, activation='relu')(l_dense2)
        l_dense4 = Dense(400, activation='relu')(l_dense3)
        l_dense5 = Dense(500, activation='relu')(l_dense4)
        out_actions = Dense(NUM_ACTIONS, activation='softmax')(l_dense4)
        out_value = Dense(1, activation='linear')(l_dense4)
        model = Model(inputs=[l_input], outputs=[out_actions, out_value])
        return model

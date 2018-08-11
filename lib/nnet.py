

class Nnet:
    def __init__(self, name, parameter_server):
        self.util = Utilty()
        with tf.name_scope(name):
            # s, a, r, s', s' terminal mask
            self.train_queue = [[], [], [], [], []]
            K.set_session(SESS)

            # Define neural network.
            self.model = self._build_model()
            # Define learning method.
            self._build_graph(name, parameter_server)

    # Define neural network.
    def _build_model(self):
        l_input = Input(batch_shape=(None, NUM_STATES))
        l_dense1 = Dense(50, activation='relu')(l_input)
        l_dense2 = Dense(100, activation='relu')(l_dense1)
        l_dense3 = Dense(200, activation='relu')(l_dense2)
        l_dense4 = Dense(400, activation='relu')(l_dense3)
        out_actions = Dense(NUM_ACTIONS, activation='softmax')(l_dense4)
        out_value = Dense(1, activation='linear')(l_dense4)
        model = Model(inputs=[l_input], outputs=[out_actions, out_value])
        # Have to initialize before threading
        model._make_predict_function()
        return model

    # Define learning method by TensorFlow.
    def _build_graph(self, name, parameter_server):
        self.s_t = tf.placeholder(tf.float32, shape=(None, NUM_STATES))
        self.a_t = tf.placeholder(tf.float32, shape=(None, NUM_ACTIONS))
        # Not immediate, but discounted n step reward
        self.r_t = tf.placeholder(tf.float32, shape=(None, 1))

        p, v = self.model(self.s_t)

        # Define loss function.
        log_prob = tf.log(tf.reduce_sum(p * self.a_t, axis=1, keepdims=True) + 1e-10)
        advantage = self.r_t - v
        loss_policy = - log_prob * tf.stop_gradient(advantage)
        # Minimize value error
        loss_value = LOSS_V * tf.square(advantage)
        # Maximize entropy (regularization)
        entropy = LOSS_ENTROPY * tf.reduce_sum(p * tf.log(p + 1e-10), axis=1, keepdims=True)
        self.loss_total = tf.reduce_mean(loss_policy + loss_value + entropy)

        # Define weight.
        self.weights_params = tf.get_collection(tf.GraphKeys.TRAINABLE_VARIABLES, scope=name)
        # Define grads.
        self.grads = tf.gradients(self.loss_total, self.weights_params)

        # Define updating weight of ParameterServe
        self.update_global_weight_params = \
            parameter_server.optimizer.apply_gradients(zip(self.grads, parameter_server.weights_params))

        # Define copying weight of ParameterServer to LocalBrain.
        self.pull_global_weight_params = [l_p.assign(g_p)
                                          for l_p, g_p in zip(self.weights_params, parameter_server.weights_params)]

        # Define copying weight of LocalBrain to ParameterServer.
        self.push_local_weight_params = [g_p.assign(l_p)
                                         for g_p, l_p in zip(parameter_server.weights_params, self.weights_params)]

    # Pull ParameterServer weight to local thread.
    def pull_parameter_server(self):
        SESS.run(self.pull_global_weight_params)

    # Push local thread weight to ParameterServer.
    def push_parameter_server(self):
        SESS.run(self.push_local_weight_params)

    # Updating weight using grads of LocalBrain (learning).
    def update_parameter_server(self):
        if len(self.train_queue[0]) < MIN_BATCH:
            return

        self.util.print_message(NOTE, 'Update LocalBrain weight to ParameterServer.')
        s, a, r, s_, s_mask = self.train_queue
        self.train_queue = [[], [], [], [], []]
        s = np.vstack(s)
        a = np.vstack(a)
        r = np.vstack(r)
        s_ = np.vstack(s_)
        s_mask = np.vstack(s_mask)
        _, v = self.model.predict(s_)

        # Set v to 0 where s_ is terminal state
        r = r + GAMMA_N * v * s_mask
        feed_dict = {self.s_t: s, self.a_t: a, self.r_t: r}  # data of updating weight.
        SESS.run(self.update_global_weight_params, feed_dict)  # Update ParameterServer weight.

    # Return probability of action usin state (s).
    def predict_p(self, s):
        p, v = self.model.predict(s)
        return p

    def train_push(self, s, a, r, s_):
        self.train_queue[0].append(s)
        self.train_queue[1].append(a)
        self.train_queue[2].append(r)

        if s_ is None:
            self.train_queue[3].append(NONE_STATE)
            self.train_queue[4].append(0.)
        else:
            self.train_queue[3].append(s_)
            self.train_queue[4].append(1.)
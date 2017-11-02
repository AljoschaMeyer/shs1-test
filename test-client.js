#!/usr/bin/env node
const {spawn} = require('child_process');

const sodium = require('chloride');

const {verifyMsg1, createMsg2, verifyMsg3, createMsg4, serverOutcome} = require('./crypto-server');
const randomBytes = require('./random-bytes');
const runTests = require('./run-tests');

const clientPath = process.argv[2];
const seed = process.argv[3];

const generateServerStartState = rnd => {
  const server_longterm = sodium.crypto_sign_seed_keypair(randomBytes(rnd, 32));
  const server_ephemeral = sodium.crypto_sign_seed_keypair(randomBytes(rnd, 32));
  const network_identifier = randomBytes(rnd, 32);

  return {
    server_longterm_sk: server_longterm.secretKey,
    server_longterm_pk: server_longterm.publicKey,
    server_ephemeral_sk: sodium.crypto_sign_ed25519_sk_to_curve25519(server_ephemeral.secretKey),
    server_ephemeral_pk: sodium.crypto_sign_ed25519_pk_to_curve25519(server_ephemeral.publicKey),
    network_identifier
  };
};

const startClient = serverState => {
  return spawn(clientPath, [
    serverState.network_identifier.toString('hex'),
    serverState.server_longterm_pk.toString('hex')
  ]);
};

const interact = (serverState, client, faults, cb) => {
  let once = true;
  const done = err => {
    if (once) {
      once = false;

      client.kill();
      return cb(err);
    }
  };

  client.on('error', err => {
    done({
      description: 'client child_process emitted error event',
      err
    });
  });

  client.stderr.on('data', data => process.stderr.write(data));

  const trace = {
    server_longterm_sk: Buffer.alloc(64),
    server_longterm_pk: Buffer.alloc(32),
    server_ephemeral_sk: Buffer.alloc(32),
    server_ephemeral_pk: Buffer.alloc(32),
    network_identifier: Buffer.alloc(32)
  };
  serverState.server_longterm_sk.copy(trace.server_longterm_sk);
  serverState.server_longterm_pk.copy(trace.server_longterm_pk);
  serverState.server_ephemeral_sk.copy(trace.server_ephemeral_sk);
  serverState.server_ephemeral_pk.copy(trace.server_ephemeral_pk);
  serverState.network_identifier.copy(trace.network_identifier);

  let state = 'waiting_for_msg1';

  client.stdout.on('data', data => {
    switch (state) {
      case 'waiting_for_msg1':
        if (!verifyMsg1(serverState, data)) {
          return done({
            description: 'Client wrote invalid msg1',
            trace,
            incorrectMsgFromClient: data
          });
        }

        trace.msg1 = data;
        trace.client_ephemeral_pk = serverState.client_ephemeral_pk;

        if (faults.msg2) {
          const msg2 = faults.msg2(serverState);

          trace.invalidMsg2 = Buffer.alloc(64);
          msg2.copy(trace.invalidMsg2);

          client.stdin.write(msg2);
          state = 'sent_invalid_msg2';
        } else {
          const msg2 = createMsg2(serverState);

          trace.msg2 = Buffer.alloc(64);
          msg2.copy(trace.msg2);

          client.stdin.write(msg2);
          state = 'sent_valid_msg2';
        }
        return;
      case 'sent_invalid_msg2':
        return done({
          description: 'Client must stop writing after receiving invalid msg2',
          trace
        });
      case 'sent_valid_msg2':
        if (!verifyMsg3(serverState, data)) {
          return done({
            description: 'Client wrote invalid msg3',
            trace,
            incorrectMsgFromClient: data
          });
        }

        trace.msg3 = data;
        trace.client_longterm_pk = serverState.client_longterm_pk;
        trace.shared_secret_ab = serverState.shared_secret_ab;
        trace.msg3_plaintext = serverState.msg3_plaintext;
        trace.msg4_secretbox_key = serverState.msg4_secretbox_key;

        if (faults.msg4) {
          const msg4 = faults.msg4(serverState);

          trace.invalidMsg4 = Buffer.alloc(80);
          msg4.copy(trace.invalidMsg4);

          client.stdin.write(msg4);
          state = 'sent_invalid_msg4';
        } else {
          const msg4 = createMsg4(serverState);

          trace.msg4 = Buffer.alloc(80);
          msg4.copy(trace.msg4);

          client.stdin.write(msg4);
          state = 'sent_valid_msg4';
        }
        return;
      case 'sent_invalid_msg4':
        return done({
          description: 'Client must stop writing after receiving invalid msg4',
          trace
        });
      case 'sent_valid_msg4':
        {
          const expectedOutcome = serverOutcome(serverState);
          if (data.equals(Buffer.concat([
            expectedOutcome.decryption_key,
            expectedOutcome.decryption_nonce,
            expectedOutcome.encryption_key,
            expectedOutcome.encryption_nonce
          ]))) {
            return done();
          }

          trace.expected_outcome = Buffer.concat([
            expectedOutcome.decryption_key,
            expectedOutcome.decryption_nonce,
            expectedOutcome.encryption_key,
            expectedOutcome.encryption_nonce
          ]);

          return done({
            description: 'Client wrote incorrect outcome',
            trace,
            incorrectMsgFromClient: data
          });
        }
      default: throw new Error('The test suite messed up.'); // Never happens (we have control over the state machine)
    }
  });

  client.on('close', code => {
    switch (state) {
      case 'sent_invalid_msg2':
        if (code === 0) {
          return done({
            description: 'Client must exit with nonzero exit code upon receiving a faulty msg2, but the client exited with code 0.',
            trace
          });
        }
        return done();
      case 'sent_invalid_msg4':
        if (code === 0) {
          return done({
            description: 'Client must exit with nonzero exit code upon receiving a faulty msg4, but the client exited with code 0.',
            trace
          });
        }
        return done();
      default: return done({
        description: 'Client closed although the server was well-behaved.',
        trace
      });
    }
  });
};

/*
 * Tests
 */
// Well-behaved server.
const testSuccess = (serverState, cb) => {
  const client = startClient(serverState);
  interact(serverState, client, {}, cb);
};

// Server sends a random msg2.
const testMsg2FullyRandom = (serverState, cb, rnd) => {
  const invalidMsg2 = randomBytes(rnd, 64);

  const client = startClient(serverState);
  interact(serverState, client, {
    msg2: () => invalidMsg2
  }, cb);
};

// Server uses a random network_identifier to compute msg2.
const testMsg2NetworkIdentifierRandom = (serverState, cb, rnd) => {
  const random_network_identifier = randomBytes(rnd, 32);

  const client = startClient(serverState);
  interact(serverState, client, {
    msg2: serverState => {
      const hmac = sodium.crypto_auth(serverState.server_ephemeral_pk, random_network_identifier);
      return Buffer.concat([hmac, serverState.server_ephemeral_pk]);
    }
  }, cb);
};

// Server sends a random msg4.
const testMsg4FullyRandom = (serverState, cb, rnd) => {
  const invalidMsg4 = randomBytes(rnd, 80);

  const client = startClient(serverState);
  interact(serverState, client, {
    msg4: () => invalidMsg4
  }, cb);
};

// Server uses a random msg4_secretbox_key to sign msg4.
const testMsg4SecretboxKeyRandom = (serverState, cb, rnd) => {
  const random_msg4_secretbox_key = randomBytes(rnd, 32);

  const zeros = Buffer.alloc(24);
  zeros.fill(0);

  const client = startClient(serverState);
  interact(serverState, client, {
    msg4: serverState => {
      const shared_secret_ab_hashed = sodium.crypto_hash_sha256(serverState.shared_secret_ab); // Same as in verifyMsg3().

      // The signature of this is the plaintext for msg4.
      const signed = Buffer.concat([
        serverState.network_identifier,
        serverState.msg3_plaintext,
        shared_secret_ab_hashed
      ]);
      const msg4_plaintext = sodium.crypto_sign_detached(signed, serverState.server_longterm_sk);

      return sodium.crypto_secretbox_easy(msg4_plaintext, zeros, random_msg4_secretbox_key);
    }
  }, cb);
};

// Server uses a random msg4_secretbox_key to sign msg4.
const testMsg4PlaintextRandom = (serverState, cb, rnd) => {
  const random_msg4_plaintext = randomBytes(rnd, 80);

  const zeros = Buffer.alloc(24);
  zeros.fill(0);

  const client = startClient(serverState);
  interact(serverState, client, {
    msg4: serverState => {
      return sodium.crypto_secretbox_easy(random_msg4_plaintext, zeros, serverState.msg4_secretbox_key);
    }
  }, cb);
};

const tests = [].concat(
  Array(5).fill(testMsg4PlaintextRandom),
  Array(5).fill(testMsg4SecretboxKeyRandom),
  Array(5).fill(testMsg4FullyRandom),
  Array(5).fill(testMsg2NetworkIdentifierRandom),
  Array(5).fill(testMsg2FullyRandom),
  Array(20).fill(testSuccess)
);

/*
 * Run tests
 */

runTests(tests, generateServerStartState, seed, failedTests => process.exit(failedTests));

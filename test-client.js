const sodium = require('chloride');
const gen = require('random-seed');

const {logSuccess, logFailure} = require('./logging');
const randomBytes = require('./random-bytes');

// const crypto_sign_PUBLICKEYBYTES = 32;
// const crypto_sign_SECRETKEYBYTES = 64;
// const crypto_auth_BYTES = 32;
// const crypto_scalarmult_BYTES = 32;
//
// const shs_NETWORKIDENTIFIERBYTES = 32;

const generateStartingKeys = seed => {
  const rnd = gen(seed);

  const server_longterm = sodium.crypto_sign_seed_keypair(randomBytes(rnd, 32));
  const server_ephemeral = sodium.crypto_sign_seed_keypair(randomBytes(rnd, 32));
  const network_identifier = randomBytes(rnd, 32);

  rnd.done();

  return {
    server_longterm_sk: server_longterm.secretKey,
    server_longterm_pk: server_longterm.publicKey,
    server_ephemeral_sk: sodium.crypto_sign_ed25519_sk_to_curve25519(server_ephemeral.secretKey),
    server_ephemeral_pk: sodium.crypto_sign_ed25519_pk_to_curve25519(server_ephemeral.publicKey),
    network_identifier
  };
};

// `client` is path of the server executable to test.
// `cb` must be called when all tests are done. Invoking it with an argument
// makes the testsuite fail (should be done if any client test fails).
module.exports = (client, seed, cb) => {
  logSuccess({name: 'Foo'});
  const {app, publicKey} = initClientTest('foo');
  // logFailure(test);
  console.log(app);
  console.log(publicKey);
  console.log(publicKey.toString());
  setTimeout(() => cb(1), 200);
};

// createMsg1
// TODO invalid behaviour to test for:
// - send random msg1
// - use correct msg3_plaintext but random msg3_secretbox_key
// - use correct msg3_secretbox_key but random msg3_plaintext

// createMsg3
// TODO invalid behaviour to test for:
// - send random msg1
// - use correct client_ephemeral_pk but random network_identifier
// - use correct network_identifier but random client_ephemeral_pk

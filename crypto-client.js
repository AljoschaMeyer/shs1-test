const {
  crypto_auth_verify,
  crypto_auth,
  crypto_scalarmult,
  crypto_hash_sha256,
  crypto_sign_ed25519_sk_to_curve25519,
  crypto_sign_ed25519_pk_to_curve25519,
  crypto_secretbox_open_easy,
  crypto_sign_verify_detached,
  crypto_sign_detached,
  crypto_secretbox_easy
} = require('chloride');

/*
 * Implementation of the crypto the client needs to perform.
 *
 * Note that the initial keys have different formats, ephemeral keys are curvified:
 *   - `client_longterm_sk`: crypto_sign_PUBLICKEYBYTES
 *   - `client_longterm_pk`: crypto_sign_SECRETKEYBYTES
 *   - `client_ephemeral_sk`: crypto_scalarmult_curve25519_BYTES (the result of crypto_sign_ed25519_sk_to_curve25519 on crypto_sign_SECRETKEYBYTES)
 *   - `client_ephemeral_pk`: crypto_scalarmult_curve25519_BYTES (the result of crypto_sign_ed25519_pk_to_curve25519 on crypto_sign_PUBLICKEYBYTES)
 *   - `server_longterm_pk`: crypto_sign_PUBLICKEYBYTES
 */

// At some points, the protocol needs 24 zero bytes in place of a nonce.
const zeros = Buffer.alloc(24);
zeros.fill(0);

// Returns a Buffer<64 bytes> containing a valid msg1.
//
// `state` is an object with (at least) the fields
//   - `network_identifier`: Buffer<32 bytes> // shs_NETWORKIDENTIFIERBYTES
//   - `client_ephemeral_pk`: Buffer<32 bytes> // crypto_scalarmult_curve25519_BYTES
module.exports.createMsg1 = state => {
  const hmac = crypto_auth(state.client_ephemeral_pk, state.network_identifier);
  return Buffer.concat([hmac, state.client_ephemeral_pk]);
};

// Returns true iff `msg: Buffer<64 bytes>` is a valid msg2 for the given state.
// Also updates state if msg was valid.
//
// `state` is an object with (at least) the fields
//   - `network_identifier`: Buffer<32 bytes> // shs_NETWORKIDENTIFIERBYTES
//
// After successfully validating, this adds a field to `state`:
//   - `server_ephemeral_pk`: Buffer<32 bytes> // crypto_scalarmult_curve25519_BYTES
module.exports.verifyMsg2 = (state, msg) => {
  const hmac = msg.slice(0, 32);
  const server_ephemeral_pk = msg.slice(32, 64);

  if (crypto_auth_verify(hmac, server_ephemeral_pk, state.network_identifier) !== 0) {
    return false;
  }

  state.server_ephemeral_pk = server_ephemeral_pk;

  return true;
};

// Returns a Buffer<112 bytes> containing a valid msg3.
// Also updates state.
//
// `state` is an object with (at least) the fields
//   - `network_identifier`: Buffer<32 bytes> // shs_NETWORKIDENTIFIERBYTES
//   - `client_longterm_sk`: Buffer<64 bytes> // crypto_sign_SECRETKEYBYTES
//   - `client_longterm_pk`: Buffer<32 bytes> // crypto_sign_PUBLICKEYBYTES
//   - `client_ephemeral_sk`: Buffer<32 bytes> // crypto_scalarmult_curve25519_BYTES
//   - `server_longterm_pk`: Buffer<32 bytes> // crypto_sign_PUBLICKEYBYTES
//   - `server_ephemeral_pk`: Buffer<32 bytes> // crypto_scalarmult_curve25519_BYTES
//
// This function adds the following fields to `state`:
//   - `shared_secret_ab`: Buffer<32 bytes> // crypto_scalarmult_curve25519_BYTES
//   - `shared_secret_aB`: Buffer<32 bytes> // crypto_scalarmult_curve25519_BYTES
//   - `msg3_plaintext`: Buffer<96 bytes> // crypto_sign_BYTES + crypto_sign_PUBLICKEYBYTES
module.exports.createMsg3 = state => {
  const shared_secret_ab = crypto_scalarmult(state.client_ephemeral_sk, state.server_ephemeral_pk);
  const shared_secret_ab_hashed = crypto_hash_sha256(shared_secret_ab);

  const shared_secret_aB = crypto_scalarmult(
    state.client_ephemeral_sk,
    crypto_sign_ed25519_pk_to_curve25519(state.server_longterm_pk)
  );

  const signed = Buffer.concat([
    state.network_identifier,
    state.server_longterm_pk,
    shared_secret_ab_hashed
  ]);

  const inner_signature = crypto_sign_detached(signed, state.client_longterm_sk);

  const msg3_plaintext = Buffer.concat([inner_signature, state.client_longterm_pk]);

  const msg3_secretbox_key = crypto_hash_sha256(Buffer.concat([
    state.network_identifier,
    shared_secret_ab,
    shared_secret_aB
  ]));

  state.msg3_plaintext = msg3_plaintext;
  state.shared_secret_ab = shared_secret_ab;
  state.shared_secret_aB = shared_secret_aB;

  return crypto_secretbox_easy(msg3_plaintext, zeros, msg3_secretbox_key);
};

// Returns true iff `msg: Buffer<80 bytes>` is a valid msg4 for the given state.
// Also updates state if msg was valid.
//
// `state` is an object with (at least) the fields
//   - `network_identifier`: Buffer<32 bytes> // shs_NETWORKIDENTIFIERBYTES
//   - `client_longterm_sk`: Buffer<64 bytes> // crypto_sign_SECRETKEYBYTES
//   - `server_longterm_pk`: Buffer<32 bytes> // crypto_sign_PUBLICKEYBYTES
//   - `server_ephemeral_pk`: Buffer<32 bytes> // crypto_scalarmult_curve25519_BYTES
//   - `shared_secret_ab`: Buffer<32 bytes> // crypto_scalarmult_curve25519_BYTES
//   - `shared_secret_aB`: Buffer<32 bytes> // crypto_scalarmult_curve25519_BYTES
//   - `msg3_plaintext`: Buffer<96 bytes> // crypto_sign_BYTES + crypto_sign_PUBLICKEYBYTES
//
// This function adds a field to `state`:
//   - `msg4_secretbox_key_hash`: Buffer<32 bytes> // crypto_hash_sha256_BYTES
module.exports.verifyMsg4 = (state, msg) => {
  const shared_secret_Ab = crypto_scalarmult(
    crypto_sign_ed25519_sk_to_curve25519(state.client_longterm_sk),
    state.server_ephemeral_pk
  );

  const msg4_secretbox_key = crypto_hash_sha256(Buffer.concat([
    state.network_identifier,
    state.shared_secret_ab,
    state.shared_secret_aB,
    shared_secret_Ab
  ]));

  const msg4_plaintext = crypto_secretbox_open_easy(msg, zeros, msg4_secretbox_key);

  if (!msg4_plaintext) {
    // Server did not correctly encrypt msg4.
    return false;
  }

  const shared_secret_ab_hashed = crypto_hash_sha256(state.shared_secret_ab); // Same as in createMsg3().

  // This is what the server must have used to obtain `msg4_plaintext`, the signature for `signed`.
  const signed = Buffer.concat([
    state.network_identifier,
    state.msg3_plaintext,
    shared_secret_ab_hashed
  ]);

  if (!crypto_sign_verify_detached(msg4_plaintext, signed, state.server_longterm_pk)) {
    // Server did not sign correctly.
    return false;
  }

  state.msg4_secretbox_key_hash = crypto_hash_sha256(msg4_secretbox_key);

  return true;
};

// Takes the state after a successful handshake and returns the outcome data.
//
// `state` is an object with (at least) the fields
//   - `network_identifier`: Buffer<32 bytes> // shs_NETWORKIDENTIFIERBYTES
//   - `client_longterm_pk`: Buffer<32 bytes> // crypto_sign_PUBLICKEYBYTES
//   - `client_ephemeral_pk`: Buffer<32 bytes> // crypto_scalarmult_curve25519_BYTES
//   - `server_longterm_pk`: Buffer<32 bytes> // crypto_sign_PUBLICKEYBYTES
//   - `server_ephemeral_pk`: Buffer<32 bytes> // crypto_scalarmult_curve25519_BYTES
//   - `msg4_secretbox_key_hash`: Buffer<32 bytes> // crypto_hash_sha256_BYTES
//
// The returned outcome object has the fields
//   - `encryption_key`: Buffer<32 bytes> // crypto_hash_sha256_BYTES
//   - `encryption_nonce`: Buffer<24 bytes> // crypto_box_NONCEBYTES
//   - `decryption_key`: Buffer<32 bytes> // crypto_hash_sha256_BYTES
//   - `decryption_nonce`: Buffer<24 bytes> // crypto_box_NONCEBYTES
module.exports.clientOutcome = state => {
  const encryption_key = crypto_hash_sha256(Buffer.concat([
    state.msg4_secretbox_key_hash,
    state.server_longterm_pk
  ]));

  // Same as `hmac` in `verifyMsg2()`.
  const server_hmac = crypto_auth(state.server_ephemeral_pk, state.network_identifier);
  const encryption_nonce = server_hmac.slice(0, 24);

  const decryption_key = crypto_hash_sha256(Buffer.concat([
    state.msg4_secretbox_key_hash,
    state.client_longterm_pk
  ]));

  // Same as `hmac` in `createMsg1()`.
  const client_hmac = crypto_auth(state.client_ephemeral_pk, state.network_identifier);
  const decryption_nonce = client_hmac.slice(0, 24);

  return {
    encryption_key,
    encryption_nonce,
    decryption_key,
    decryption_nonce
  };
};

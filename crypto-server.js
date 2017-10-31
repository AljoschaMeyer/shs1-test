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
 * Implementation of the crypto the server needs to perform.
 *
 * Note that the initial keys have different formats, ephemeral keys are curvified:
 *   - `server_longterm_sk`: crypto_sign_PUBLICKEYBYTES
 *   - `server_longterm_pk`: crypto_sign_SECRETKEYBYTES
 *   - `server_ephemeral_sk`: crypto_scalarmult_curve25519_BYTES (the result of crypto_sign_ed25519_sk_to_curve25519 on crypto_sign_SECRETKEYBYTES)
 *   - `server_ephemeral_pk`: crypto_scalarmult_curve25519_BYTES (the result of crypto_sign_ed25519_pk_to_curve25519 on crypto_sign_PUBLICKEYBYTES)
 */

// At some points, the protocol needs 24 zero bytes in place of a nonce.
const zeros = Buffer.alloc(24);
zeros.fill(0);

// Returns true iff `msg: Buffer<64 bytes>` is a valid msg1 for the given state.
// Also updates state if msg was valid.
//
// `state` is an object with (at least) the fields
//   - `network_identifier`: Buffer<32 bytes> // shs_NETWORKIDENTIFIERBYTES
//
// After successfully validating, this adds a field to `state`:
//   - `client_ephemeral_pk`: Buffer<32 bytes> // crypto_scalarmult_curve25519_BYTES
module.exports.verifyMsg1 = (state, msg) => {
  const hmac = msg.slice(0, 32);
  const client_ephemeral_pk = msg.slice(32, 64);

  if (crypto_auth_verify(hmac, client_ephemeral_pk, state.network_identifier) !== 0) {
    return false;
  }

  state.client_ephemeral_pk = client_ephemeral_pk;

  return true;
};

// Returns a Buffer<64 bytes> containing a valid msg2.
//
// `state` is an object with (at least) the fields
//   - `network_identifier`: Buffer<32 bytes> // shs_NETWORKIDENTIFIERBYTES
//   - `server_ephemeral_pk`: Buffer<32 bytes> // crypto_scalarmult_curve25519_BYTES
module.exports.createMsg2 = state => {
  const hmac = crypto_auth(state.server_ephemeral_pk, state.network_identifier);
  return Buffer.concat([hmac, state.server_ephemeral_pk]);
};

// Returns true iff `msg: Buffer<112 bytes>` is a valid msg3 for the given state.
// Also updates state.
//
// `state` is an object with (at least) the fields
//   - `network_identifier`: Buffer<32 bytes> // shs_NETWORKIDENTIFIERBYTES
//   - `server_longterm_sk`: Buffer<64 bytes> // crypto_sign_SECRETKEYBYTES
//   - `server_longterm_pk`: Buffer<32 bytes> // crypto_sign_PUBLICKEYBYTES
//   - `server_ephemeral_sk`: Buffer<32 bytes> // crypto_scalarmult_curve25519_BYTES
//   - `client_ephemeral_pk`: Buffer<32 bytes> // crypto_scalarmult_curve25519_BYTES
//
// This function adds the following fields to `state`:
//   - `client_longterm_pk`: Buffer<32 bytes> // crypto_sign_PUBLICKEYBYTES
//   - `shared_secret_ab`: Buffer<32 bytes> // crypto_scalarmult_curve25519_BYTES
//   - `msg3_plaintext`: Buffer<96 bytes> // crypto_sign_BYTES + crypto_sign_PUBLICKEYBYTES
//   - `msg4_secretbox_key`: Buffer<32 bytes> // crypto_hash_sha256_BYTES
module.exports.verifyMsg3 = (state, msg) => {
  const shared_secret_ab = crypto_scalarmult(state.server_ephemeral_sk, state.client_ephemeral_pk);
  const shared_secret_ab_hashed = crypto_hash_sha256(shared_secret_ab);

  const shared_secret_aB = crypto_scalarmult(
    crypto_sign_ed25519_sk_to_curve25519(state.server_longterm_sk),
    state.client_ephemeral_pk
  );

  const msg3_secretbox_key = crypto_hash_sha256(Buffer.concat([
    state.network_identifier,
    shared_secret_ab,
    shared_secret_aB
  ]));

  const msg3_plaintext = crypto_secretbox_open_easy(msg, zeros, msg3_secretbox_key);
  if (!msg3_plaintext) {
    // Could not open the box.
    return false;
  }

  const inner_signature = msg3_plaintext.slice(0, 64);
  const client_longterm_pk = msg3_plaintext.slice(64, 96);

  // This is what the client must have used to obtain `inner_signature`.
  const signed = Buffer.concat([
    state.network_identifier,
    state.server_longterm_pk,
    shared_secret_ab_hashed
  ]);

  if (!crypto_sign_verify_detached(inner_signature, signed, client_longterm_pk)) {
    // Client did not sign correctly.
    return false;
  }

  const shared_secret_Ab = crypto_scalarmult(
    state.server_ephemeral_sk,
    crypto_sign_ed25519_pk_to_curve25519(client_longterm_pk)
  );
  const msg4_secretbox_key = crypto_hash_sha256(Buffer.concat([
    state.network_identifier,
    shared_secret_ab,
    shared_secret_aB,
    shared_secret_Ab
  ]));

  state.client_longterm_pk = client_longterm_pk;
  state.msg3_plaintext = msg3_plaintext;
  state.shared_secret_ab = shared_secret_ab;
  state.msg4_secretbox_key = msg4_secretbox_key;

  return true;
};

// Returns a Buffer<80 bytes> containing a valid msg4.
//
// `state` is an object with (at least) the fields
//   - `network_identifier`: Buffer<32 bytes> // shs_NETWORKIDENTIFIERBYTES
//   - `server_longterm_sk`: Buffer<64 bytes> // crypto_sign_SECRETKEYBYTES
//   - `shared_secret_ab`: Buffer<32 bytes> // crypto_scalarmult_curve25519_BYTES
//   - `msg3_plaintext`: Buffer<96 bytes> // crypto_sign_BYTES + crypto_sign_PUBLICKEYBYTES
//   - `msg4_secretbox_key`: Buffer<32 bytes> // crypto_hash_sha256_BYTES
module.exports.createMsg4 = state => {
  const shared_secret_ab_hashed = crypto_hash_sha256(state.shared_secret_ab); // Same as in verifyMsg3().

  // The signature of this is the plaintext for msg4.
  const signed = Buffer.concat([
    state.network_identifier,
    state.msg3_plaintext,
    shared_secret_ab_hashed
  ]);
  const msg4_plaintext = crypto_sign_detached(signed, state.server_longterm_sk);

  return crypto_secretbox_easy(msg4_plaintext, zeros, state.msg4_secretbox_key);
};

// Takes the state after a successful handshake and returns the outcome data.
//
// `state` is an object with (at least) the fields
//   - `network_identifier`: Buffer<32 bytes> // shs_NETWORKIDENTIFIERBYTES
//   - `server_longterm_pk`: Buffer<32 bytes> // crypto_sign_PUBLICKEYBYTES
//   - `server_ephemeral_pk`: Buffer<32 bytes> // crypto_scalarmult_curve25519_BYTES
//   - `client_longterm_pk`: Buffer<32 bytes> // crypto_sign_PUBLICKEYBYTES
//   - `client_ephemeral_pk`: Buffer<32 bytes> // crypto_scalarmult_curve25519_BYTES
//   - `msg4_secretbox_key`: Buffer<32 bytes> // crypto_hash_sha256_BYTES
//
// The returned outcome object has the fields
//   - `encryption_key`: Buffer<32 bytes> // crypto_hash_sha256_BYTES
//   - `encryption_nonce`: Buffer<24 bytes> // crypto_box_NONCEBYTES
//   - `decryption_key`: Buffer<32 bytes> // crypto_hash_sha256_BYTES
//   - `decryption_nonce`: Buffer<24 bytes> // crypto_box_NONCEBYTES
module.exports.serverOutcome = state => {
  const msg4_secretbox_key_hash = crypto_hash_sha256(state.msg4_secretbox_key);

  const encryption_key = crypto_hash_sha256(Buffer.concat([
    msg4_secretbox_key_hash,
    state.client_longterm_pk
  ]));

  // Same as `hmac` in `verifyMsg1()`.
  const client_hmac = crypto_auth(state.client_ephemeral_pk, state.network_identifier);
  const encryption_nonce = client_hmac.slice(0, 24);

  const decryption_key = crypto_hash_sha256(Buffer.concat([
    msg4_secretbox_key_hash,
    state.server_longterm_pk
  ]));

  // Same as `hmac` in `createMsg2()`.
  const server_hmac = crypto_auth(state.server_ephemeral_pk, state.network_identifier);
  const decryption_nonce = server_hmac.slice(0, 24);

  return {
    encryption_key,
    encryption_nonce,
    decryption_key,
    decryption_nonce
  };
};

const {logSuccess, logFailure} = require('./logging');

// `server` is path of the server executable to test.
// `cb` must be called when all tests are done. Invoking it with an argument
// makes the testsuite fail (should be done if any server test fails).
module.exports = (server, seed, cb) => {
  cb(0);
};

// createMsg2:
// TODO invalid behaviour to test for:
// - send random msg2
// - use correct server_ephemeral_pk but random network_identifier
// - use correct network_identifier but random server_ephemeral_pk

// createMsg4
// TODO invalid behaviour to test for:
// - random msg4
// - use correct msg4_plaintext but random msg4_secretbox_key
// - use correct msg4_secretbox_key but random msg4_plaintext

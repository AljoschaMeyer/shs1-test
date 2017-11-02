const {inspect} = require('util');

const gen = require('random-seed');
const {reflect, parallel} = require('async');
const chalk = require('chalk');

const logFailure = failure => {
  console.log(chalk.red(`Failed: ${failure.description}`));
  if (failure.err) {
    console.log(inspect(failure.err));
  }
  if (failure.trace) {
    console.log('Trace:');
    console.log(failure.trace);
  }
  if (failure.incorrectMsgFromServer) {
    console.log('Server incorrectly sent:');
    console.log(failure.incorrectMsgFromServer.toString('hex'));
  }
  if (failure.incorrectMsgFromClient) {
    console.log('Client incorrectly sent:');
    console.log(failure.incorrectMsgFromClient.toString('hex'));
  }
  console.log();
};

module.exports = (tests, generateStartState, seed, cb) => {
  const rnd = gen(seed);
  const startStates = tests.map(() => generateStartState(rnd));

  parallel(
    tests.map((test, i) => reflect(cb => test(startStates[i], cb, rnd))),
    (never, results) => {
      rnd.done();

      const failures = results.filter(result => result.error).map(result => result.error);

      failures.forEach(failure => {
        logFailure(failure);
      });

      return cb(failures.length);
    }
  );
};

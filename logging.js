const {inspect} = require('util');

const chalk = require('chalk');

module.exports = failure => {
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
  console.log();
};

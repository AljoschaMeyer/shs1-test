const chalk = require('chalk');

module.exports.logSuccess = test => console.log(chalk.green(`Passed: ${test.name}\n`));
module.exports.logFailure = test => {
  console.log(chalk.red(`Failed: ${test.name}`));
  console.log(chalk.red(JSON.stringify(test.details, null, 2)));
  console.log();
};

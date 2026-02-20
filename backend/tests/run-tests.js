const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');

const testsDir = path.join(process.cwd(), 'tests');
const files = fs
  .readdirSync(testsDir)
  .filter((f) => f.endsWith('.test.js'))
  .sort();

function runOne(file) {
  return new Promise((resolve) => {
    const fullPath = path.join('tests', file);
    console.log(`\n=== Running ${fullPath} ===`);
    const child = spawn(process.execPath, ['--test', fullPath], {
      stdio: 'inherit',
      shell: false,
    });
    child.on('exit', (code) => {
      resolve({ file: fullPath, code: code || 0 });
    });
  });
}

(async () => {
  const results = [];
  for (const file of files) {
    // eslint-disable-next-line no-await-in-loop
    const result = await runOne(file);
    results.push(result);
  }

  const failed = results.filter((r) => r.code !== 0);
  if (failed.length) {
    console.error('\nTest files failed:');
    for (const fail of failed) {
      console.error(`- ${fail.file}`);
    }
    process.exit(1);
  }

  console.log('\nAll test files passed.');
  process.exit(0);
})();

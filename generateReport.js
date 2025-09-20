const fs = require('fs');

// Read Jest JSON report
const data = JSON.parse(fs.readFileSync('firestore-vuln-report.json', 'utf8'));

let report = `Firestore Security Rules Vulnerability Report\nProject: firestonesecuritytest\n\n`;

data.testResults.forEach(testFile => {
  report += `Test File: ${testFile.name}\n`;

  testFile.assertionResults.forEach(test => {
    const status = test.status.toUpperCase();
    report += `  [${status}] ${test.fullName}\n`;
    if (test.failureMessages.length > 0) {
      report += `    Errors:\n`;
      test.failureMessages.forEach(msg => {
        const formatted = msg.replace(/\n/g, '\n      ');
        report += `      ${formatted}\n`;
      });
    }
  });

  report += '\n';
});

// Write readable text report
fs.writeFileSync('firestore-vuln-report.txt', report, 'utf8');
console.log('Readable report written to firestore-vuln-report.txt');
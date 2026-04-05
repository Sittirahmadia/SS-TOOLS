/**
 * Scanner Index — exports all scanner modules
 */

const modScanner = require('./mod-scanner');
const logScanner = require('./log-scanner');
const processScanner = require('./process-scanner');
const deletedFileScanner = require('./deleted-file-scanner');
const launcherDetector = require('./launcher-detector');
const stringScanner = require('./string-scanner');

module.exports = {
  modScanner,
  logScanner,
  processScanner,
  deletedFileScanner,
  launcherDetector,
  stringScanner
};

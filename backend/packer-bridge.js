const { spawn } = require('child_process');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const zlib = require('zlib');
const validate = require('./validate');

const BASE_BINARIES = {
  pro: '/srv/base/obsidian-pro-base.exe',
  commercial: '/srv/base/obsidian-commercial-base.exe'
};

function generateRandomFilename() {
  return 'obsidian.pro.' + crypto.randomBytes(7).toString('hex') + '.exe';
}

function createPackedBinary(licenseType, hwid, licenseId, callback) {
  const basePath = BASE_BINARIES[licenseType];
  
  if (!basePath) {
    return callback(new Error('Invalid license type'));
  }
  
  if (!fs.existsSync(basePath)) {
    return callback(new Error('Base binary not found'));
  }
  
  const packerPath = '/srv/internal/obsidian.internal.exe';
  const outputDir = '/tmp/packer-output-' + crypto.randomBytes(12).toString('hex'); 
  
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }

  const randomName = generateRandomFilename();
  const outputPath = path.join(outputDir, randomName);
  
  const args = ['--compress', '--fix'];
  
  if (hwid) {
    const sanitizedHwid = validate.sanitizeHwid(hwid);
    if (!sanitizedHwid) {
      return callback(new Error('Invalid HWID format'));
    }
    args.push('--link-hwid', sanitizedHwid);
  }
  
  if (licenseId) {
    const sanitizedLicenseId = validate.sanitizeLicenseId(licenseId);
    if (!sanitizedLicenseId) {
      return callback(new Error('Invalid LicenseId'));
    }
    args.push('--link-license', sanitizedLicenseId);
  }

  args.push(basePath, outputPath);
  
  console.log('Packing binary:', packerPath, args.join(' '));
  
  const proc = spawn('wine', [packerPath, ...args]);
  
  let stdout = '';
  let stderr = '';
  
  proc.stdout.on('data', (data) => {
    stdout += data.toString();
  });
  
  proc.stderr.on('data', (data) => {
    stderr += data.toString();
  });
  
  proc.on('close', (code) => {
    if (code !== 0) {
      return callback(new Error('Packer exited with code ' + code + ': ' + stderr));
    }
    
    let packerOutput;
    const jsonStart = stderr.indexOf('{');
    try {
      if (jsonStart !== -1) {
        packerOutput = JSON.parse(stderr.substring(jsonStart));
      }
    } catch (e) {
      console.error('packer stderr:', JSON.stringify(stderr));
      return callback(new Error('Invalid JSON output from packer'));
    }

    const mac = packerOutput.mac;
    const key = packerOutput.key;
    const integrity = packerOutput.integrityKey;
    
    if (!mac || mac.length !== 32) {
      return callback(new Error('Invalid MAC in packer output'));
    }
    
    if (!key || key.length !== 32) {
      return callback(new Error('Invalid key in packer output'));
    }
    
    if (!fs.existsSync(outputPath)) {
      return callback(new Error('Packer did not produce output file'));
    }

    if (!integrity) {
      return callback(new Error('Packer did not produce integrity key'));
    } 
    
    const binaryData = fs.readFileSync(outputPath);
    fs.rm(outputDir, { recursive: true }, () => {});
    
    callback(null, {
      mac: mac,
      key: key,
      hwid: null,
      integrity: integrity,
      filename: randomName,
      data: binaryData
    });
  });
  
  proc.on('error', (err) => {
    fs.rm(outputDir, { recursive: true }, () => {});
    callback(err);
  });
}

module.exports = { createPackedBinary };

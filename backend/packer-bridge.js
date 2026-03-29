const { spawn } = require('child_process');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const zlib = require('zlib');
const validate = require('./validate');

const BASE_BINARIES = {
  pro: '/srv/builds/obsidian-pro-base.exe',
  commercial: '/srv/builds/obsidian-commercial-base.exe'
};

function generateRandomFilename() {
  return 'obisidan_pro_' + crypto.randomBytes(6).toString('hex');
}

function createPackedBinary(licenseType, hwid, callback) {
  const basePath = BASE_BINARIES[licenseType];
  
  if (!basePath) {
    return callback(new Error('Invalid license type'));
  }
  
  if (!fs.existsSync(basePath)) {
    return callback(new Error('Base binary not found'));
  }
  
  const packerPath = path.join(__dirname, 'packer', 'packer');
  const outputDir = '/tmp/packer-output';
  
  if (!fs.existsSync(outputDir)) {
    fs.mkdirSync(outputDir, { recursive: true });
  }

  const outputPath = path.join(outputDir, randomName + '.exe');
  
  const args = ['--compress', '--ultra', '--fix'];
  
  if (hwid) {
    const sanitizedHwid = validate.sanitizeHwid(hwid);
    if (!sanitizedHwid) {
      return callback(new Error('Invalid HWID format'));
    }
    args.push('--link-to-hwid', sanitizedHwid);
  }
  args.push(basePath, outputPath);
  
  console.log('Packing binary:', args.join(' '));
  
  const proc = spawn(packerPath, args);
  
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
    try {
      packerOutput = JSON.parse(stdout.trim());
    } catch (e) {
      return callback(new Error('Invalid JSON output from packer: ' + stdout));
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
    fs.unlink(outputPath, () => {});

    const randomName = generateRandomFilename();
    const gzipName = randomName + '.gz';
    const gzipBuffer = zlib.gzipSync(binaryData);
    
    callback(null, {
      mac: mac,
      key: key,
      hwid: null,
      integrity: integrity,
      filename: gzipName,
      data: gzipBuffer
    });
  });
  
  proc.on('error', (err) => {
    callback(err);
  });
}

module.exports = { createPackedBinary };
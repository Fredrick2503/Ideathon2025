/*
 * Ideathon 2026 registration endpoint.
 * Configure the Script Properties documented in README-security.md before deployment.
 */

var CONFIG = {
  MAX_BODY_BYTES: 15 * 1024 * 1024,
  MAX_FILE_BYTES: 10 * 1024 * 1024,
  RATE_LIMIT_SECONDS: 3600,
  MAX_REQUESTS_PER_WINDOW: 3,
  MAX_TEXT_LENGTH: 120,
  MAX_TEAM_NAME_LENGTH: 100,
  MAX_COLLEGE_LENGTH: 180,
  MAX_MEMBER_NAME_LENGTH: 120,
  ALLOWED_DEGREES: ['B.E. / B.Tech', 'M.E. / M.Tech', 'BCA / MCA', 'Other'],
  ALLOWED_TRACKS: ['Track 1', 'Track 2', 'Track 3', 'Track 4'],
  ALLOWED_FILES: {
    pdf: { mime: 'application/pdf', extension: 'pdf' },
    jpg: { mime: 'image/jpeg', extension: 'jpg' },
    jpeg: { mime: 'image/jpeg', extension: 'jpg' },
    png: { mime: 'image/png', extension: 'png' }
  }
};

function doGet() {
  return jsonResponse_({ ok: false, error: 'Method not allowed.' });
}

function doPost(e) {
  var requestId = Utilities.getUuid();

  try {
    if (!e || !e.postData || e.postData.type !== 'text/plain') {
      throw new PublicError_('Invalid request.');
    }

    var raw = String(e.postData.contents || '');
    if (Utilities.newBlob(raw).getBytes().length > CONFIG.MAX_BODY_BYTES) {
      throw new PublicError_('Request is too large.');
    }

    var payload = JSON.parse(raw);
    validatePayload_(payload);
    verifyTurnstile_(payload.turnstileToken);

    var identity = normalize_(payload.teamLeader.email) + ':' +
      normalize_(payload.teamLeader.phone);
    enforceRateLimit_(identity);

    var lock = LockService.getScriptLock();
    lock.waitLock(15000);
    try {
      var registrationId = findDuplicate_(payload) ? null : createRegistrationId_();
      if (!registrationId) {
        throw new PublicError_('A registration already exists.');
      }

      var file = savePaymentProof_(payload.paymentProof, registrationId);
      writeRegistration_(payload, registrationId, file.getId());
    } finally {
      lock.releaseLock();
    }

    return jsonResponse_({ ok: true, registrationId: registrationId });
  } catch (error) {
    logPrivateError_(requestId, error);
    if (error instanceof PublicError_) {
      return jsonResponse_({ ok: false, error: error.message });
    }
    return jsonResponse_({ ok: false, error: 'Registration could not be completed.' });
  }
}

function validatePayload_(payload) {
  requireKeys_(payload, [
    'teamLeader', 'college', 'degreeProgram', 'teamSize', 'teamName',
    'members', 'innovationTrack', 'paymentProof'
  ], ['turnstileToken']);
  requireExactKeys_(payload.teamLeader, ['fullName', 'email', 'phone']);
  requireExactKeys_(payload.paymentProof, ['name', 'mimeType', 'base64']);

  requireText_(payload.teamLeader.fullName, 'fullName', CONFIG.MAX_TEXT_LENGTH);
  requireText_(payload.teamLeader.email, 'email', 254);
  requireText_(payload.teamLeader.phone, 'phone', 32);
  requireText_(payload.college, 'college', CONFIG.MAX_COLLEGE_LENGTH);
  requireText_(payload.teamName, 'teamName', CONFIG.MAX_TEAM_NAME_LENGTH);
  requireText_(payload.degreeProgram, 'degreeProgram', 40);
  requireText_(payload.innovationTrack, 'innovationTrack', 40);
  requireText_(payload.paymentProof.name, 'paymentProof.name', 255);
  requireText_(payload.paymentProof.mimeType, 'paymentProof.mimeType', 80);
  requireText_(payload.paymentProof.base64, 'paymentProof.base64', 15 * 1024 * 1024);
  if (payload.turnstileToken !== undefined) {
    requireText_(payload.turnstileToken, 'turnstileToken', 4096);
  }

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(payload.teamLeader.email)) {
    throw new PublicError_('Invalid email address.');
  }
  if (!/^\+?[0-9 ()-]{10,20}$/.test(payload.teamLeader.phone)) {
    throw new PublicError_('Invalid phone number.');
  }
  if (!Number.isInteger(payload.teamSize) || payload.teamSize < 1 || payload.teamSize > 6) {
    throw new PublicError_('Invalid team size.');
  }
  if (!Array.isArray(payload.members) || payload.members.length !== payload.teamSize - 1) {
    throw new PublicError_('Invalid team members.');
  }
  payload.members.forEach(function (member) {
    requireText_(member, 'member', CONFIG.MAX_MEMBER_NAME_LENGTH);
  });
  if (CONFIG.ALLOWED_DEGREES.indexOf(payload.degreeProgram) === -1 ||
      CONFIG.ALLOWED_TRACKS.indexOf(payload.innovationTrack) === -1) {
    throw new PublicError_('Invalid registration selection.');
  }
  validatePaymentProof_(payload.paymentProof);
}

function validatePaymentProof_(proof) {
  var extension = String(proof.name).toLowerCase().split('.').pop();
  var rule = CONFIG.ALLOWED_FILES[extension];
  if (!rule || proof.mimeType.toLowerCase() !== rule.mime) {
    throw new PublicError_('Invalid payment proof.');
  }
  if (!/^[A-Za-z0-9+/=]+$/.test(proof.base64) || proof.base64.length % 4 !== 0) {
    throw new PublicError_('Invalid payment proof.');
  }

  var bytes;
  try {
    bytes = Utilities.base64Decode(proof.base64);
  } catch (error) {
    throw new PublicError_('Invalid payment proof.');
  }
  if (!bytes.length || bytes.length > CONFIG.MAX_FILE_BYTES || !hasMagicBytes_(bytes, extension)) {
    throw new PublicError_('Invalid payment proof.');
  }
}

function hasMagicBytes_(bytes, extension) {
  if (extension === 'pdf') return bytes.length >= 5 && bytes.slice(0, 5).map(String.fromCharCode).join('') === '%PDF-';
  if (extension === 'png') return bytes.slice(0, 8).join(',') === '137,80,78,71,13,10,26,10';
  return bytes.length >= 3 && bytes[0] === 255 && bytes[1] === 216 && bytes[2] === 255;
}

function savePaymentProof_(proof, registrationId) {
  var folder = DriveApp.getFolderById(requiredProperty_('PAYMENT_FOLDER_ID'));
  var extension = CONFIG.ALLOWED_FILES[String(proof.name).toLowerCase().split('.').pop()].extension;
  var blob = Utilities.newBlob(Utilities.base64Decode(proof.base64), proof.mimeType,
    registrationId + '.' + extension);
  var file = folder.createFile(blob);
  file.setName(registrationId + '.' + extension);
  file.setSharing(DriveApp.Access.PRIVATE, DriveApp.Permission.NONE);
  return file;
}

function writeRegistration_(payload, registrationId, fileId) {
  var sheet = SpreadsheetApp.openById(requiredProperty_('REGISTRATION_SHEET_ID'))
    .getSheetByName(requiredProperty_('REGISTRATION_SHEET_NAME'));
  sheet.appendRow([
    registrationId, new Date(), payload.teamLeader.fullName, payload.teamLeader.email,
    payload.teamLeader.phone, payload.college, payload.degreeProgram, payload.teamSize,
    payload.teamName, JSON.stringify(payload.members), payload.innovationTrack, fileId
  ]);
}

function findDuplicate_(payload) {
  var sheet = SpreadsheetApp.openById(requiredProperty_('REGISTRATION_SHEET_ID'))
    .getSheetByName(requiredProperty_('REGISTRATION_SHEET_NAME'));
  var values = sheet.getDataRange().getValues();
  var email = normalize_(payload.teamLeader.email);
  var phone = normalize_(payload.teamLeader.phone).replace(/\D/g, '');
  return values.some(function (row, index) {
    if (index === 0) return false;
    return normalize_(row[3]) === email || normalize_(row[4]).replace(/\D/g, '') === phone;
  });
}

function createRegistrationId_() {
  return 'IDE26-' + Utilities.formatDate(new Date(), 'Etc/UTC', 'yyyyMMdd') + '-' +
    Utilities.getUuid().replace(/-/g, '').slice(0, 10).toUpperCase();
}

function enforceRateLimit_(identity) {
  var digest = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, identity);
  var key = 'rate:' + Utilities.base64EncodeWebSafe(digest);
  var cache = CacheService.getScriptCache();
  var count = Number(cache.get(key) || 0);
  if (count >= CONFIG.MAX_REQUESTS_PER_WINDOW) throw new PublicError_('Too many attempts. Try again later.');
  cache.put(key, String(count + 1), CONFIG.RATE_LIMIT_SECONDS);
}

function verifyTurnstile_(token) {
  var secret = PropertiesService.getScriptProperties().getProperty('TURNSTILE_SECRET_KEY');
  if (!secret) return;
  if (typeof token !== 'string' || !token) throw new PublicError_('Human verification failed.');
  var response = UrlFetchApp.fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
    method: 'post', payload: { secret: secret, response: token }, muteHttpExceptions: true
  });
  var result = JSON.parse(response.getContentText());
  if (!result.success) throw new PublicError_('Human verification failed.');
}

function requireExactKeys_(object, expected) {
  requireKeys_(object, expected, []);
}

function requireKeys_(object, required, optional) {
  var allowed = required.concat(optional || []).sort();
  var actual = object && typeof object === 'object' && !Array.isArray(object) ? Object.keys(object).sort() : [];
  if (actual.some(function (key) { return allowed.indexOf(key) === -1; }) ||
      required.some(function (key) { return actual.indexOf(key) === -1; })) {
    throw new PublicError_('Invalid request.');
  }
}

function requireText_(value, name, maxLength) {
  if (typeof value !== 'string' || !value.trim() || value.length > maxLength) {
    throw new PublicError_('Invalid ' + name + '.');
  }
}

function normalize_(value) { return String(value).trim().toLowerCase(); }

function requiredProperty_(name) {
  var value = PropertiesService.getScriptProperties().getProperty(name);
  if (!value) throw new Error('Missing required Script Property: ' + name);
  return value;
}

function jsonResponse_(body) {
  return ContentService.createTextOutput(JSON.stringify(body))
    .setMimeType(ContentService.MimeType.JSON);
}

function logPrivateError_(requestId, error) {
  console.error(JSON.stringify({ requestId: requestId, message: String(error && error.stack || error) }));
}

function PublicError_(message) {
  this.name = 'PublicError';
  this.message = message;
  this.stack = (new Error()).stack;
}
PublicError_.prototype = Object.create(Error.prototype);
PublicError_.prototype.constructor = PublicError_;
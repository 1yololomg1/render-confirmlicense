import express from 'express';
import cors from 'cors';
import admin from 'firebase-admin';
import crypto from 'crypto';

const app = express();

// Enable CORS for all origins
app.use(cors());
app.use(express.json());

// Initialize Firebase Admin SDK
const serviceAccount = {
  type: 'service_account',
  project_id: process.env.FIREBASE_PROJECT_ID,
  private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
  private_key: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
  client_email: process.env.FIREBASE_CLIENT_EMAIL,
  client_id: process.env.FIREBASE_CLIENT_ID,
  auth_uri: 'https://accounts.google.com/o/oauth2/auth',
  token_uri: 'https://oauth2.googleapis.com/token',
  auth_provider_x509_cert_url: 'https://www.googleapis.com/oauth2/v1/certs',
};

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: process.env.FIREBASE_DATABASE_URL || 'https://confirm-license-manager-default-rtdb.firebaseio.com'
});

const db = admin.database();

console.log('Using admin secret:', process.env.ADMIN_SECRET?.substring(0, 10) + '...');
console.log('Using license secret:', process.env.LICENSE_SECRET?.substring(0, 8) + '...');
console.log('Firebase initialized:', !!admin.apps.length);

const PORT = process.env.PORT || 10000;

// Health check endpoint
app.get('/', (req, res) => {
  res.json({
    status: 'online',
    service: 'CONFIRM License Validation Server',
    version: '2.0.0',
    endpoints: [
      '/validate (Firebase token required)',
      '/validate-traditional (Professional licensing)',
      '/admin (License management)'
    ]
  });
});

// EXISTING: Firebase token-based validation (keep for compatibility)
app.post('/validate', async (req, res) => {
  try {
    // Check for Firebase authentication token
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        valid: false,
        error: 'Authentication required',
        hint: 'Use /validate-traditional for modern licensing'
      });
    }

    const token = authHeader.split('Bearer ')[1];
    
    // Verify Firebase token
    await admin.auth().verifyIdToken(token);

    const { licenseKey, machineId } = req.body;

    if (!licenseKey || !machineId) {
      return res.status(400).json({
        valid: false,
        error: 'Missing licenseKey or machineId'
      });
    }

    // Parse license key format: licenseId:expiryDate:hash
    const parts = licenseKey.split(':');
    if (parts.length !== 3) {
      return res.status(400).json({
        valid: false,
        error: 'Invalid license key format'
      });
    }

    const [licenseId, expiresAt, hash] = parts;

    // Check Firebase database
    const licenseRef = db.ref(`licenses/${licenseId}`);
    const snapshot = await licenseRef.once('value');

    if (!snapshot.exists()) {
      return res.json({
        valid: false,
        error: 'License not found'
      });
    }

    // Check expiration
    if (new Date() > new Date(expiresAt)) {
      return res.json({
        valid: false,
        error: 'License expired'
      });
    }

    // Verify hash (basic integrity check)
    const expectedHash = crypto
      .createHash('md5')
      .update(licenseId + expiresAt + process.env.LICENSE_SECRET)
      .digest('hex')
      .substring(0, 16);

    if (hash !== expectedHash) {
      return res.json({
        valid: false,
        error: 'Invalid license signature'
      });
    }

    res.json({
      valid: true,
      licenseId,
      expiresAt,
      machineId
    });

  } catch (error) {
    console.error('Validation error:', error);
    res.status(500).json({
      valid: false,
      error: 'Validation failed'
    });
  }
});

// NEW: Professional traditional validation (no Firebase tokens required)
app.post('/validate-traditional', async (req, res) => {
  try {
    const { licenseKey, machineId } = req.body;

    console.log(`Traditional validation for machine: ${machineId?.substring(0, 8)}...`);

    if (!licenseKey || !machineId) {
      return res.status(400).json({
        valid: false,
        error: 'Missing licenseKey or machineId'
      });
    }

    // Parse license key format: licenseId:expiryDate:hash
    const parts = licenseKey.split(':');
    if (parts.length !== 3) {
      return res.status(400).json({
        valid: false,
        error: 'Invalid license key format'
      });
    }

    const [licenseId, expiresAt, hash] = parts;

    // Check Firebase database (same as existing system)
    const licenseRef = db.ref(`licenses/${licenseId}`);
    const snapshot = await licenseRef.once('value');

    if (!snapshot.exists()) {
      return res.json({
        valid: false,
        error: 'License not found'
      });
    }

    const licenseData = snapshot.val();

    // Check expiration
    if (new Date() > new Date(expiresAt)) {
      return res.json({
        valid: false,
        error: 'License expired'
      });
    }

    // Verify hash (same integrity check)
    const expectedHash = crypto
      .createHash('md5')
      .update(licenseId + expiresAt + process.env.LICENSE_SECRET)
      .digest('hex')
      .substring(0, 16);

    if (hash !== expectedHash) {
      return res.json({
        valid: false,
        error: 'Invalid license signature'
      });
    }

    // PROFESSIONAL RESPONSE: Cache validation for 7 days
    const now = new Date();
    const cacheUntil = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000); // 7 days from now

    // Log successful validation (optional: track machine bindings)
    console.log(`✅ License ${licenseId} validated for machine ${machineId.substring(0, 8)}...`);

    // Return professional license validation response
    res.json({
      valid: true,
      licenseId: licenseId,
      expiresAt: expiresAt,
      features: licenseData.features || ['basic'],
      machineId: machineId,
      cacheUntil: cacheUntil.toISOString(),
      serverTime: now.toISOString(),
      validationMethod: 'traditional'
    });

  } catch (error) {
    console.error('Traditional validation error:', error);
    res.status(500).json({
      valid: false,
      error: 'Validation failed'
    });
  }
});

// EXISTING: Admin panel (keep unchanged)
app.get('/admin', (req, res) => {
  if (req.query.secret !== process.env.ADMIN_SECRET) {
    return res.status(403).send('Access denied');
  }

  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
        <title>License Admin</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
            .container { background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            .license-item { background: #f8f9fa; padding: 15px; margin: 10px 0; border-radius: 5px; border-left: 4px solid #007bff; }
            .expired { border-left-color: #dc3545; }
            button { background: #007bff; color: white; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer; }
            button:hover { background: #0056b3; }
            .danger { background: #dc3545; }
            .danger:hover { background: #c82333; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔐 CONFIRM License Manager</h1>
            <p>Professional licensing system with traditional validation</p>
            
            <h2>📊 Server Status</h2>
            <p>✅ Server: Online</p>
            <p>✅ Firebase: Connected</p>
            <p>✅ Traditional Validation: Active</p>
            
            <h2>➕ Create New License</h2>
            <button onclick="createLicense()">Generate License</button>
            
            <h2>📋 Active Licenses</h2>
            <div id="licensesList">Loading...</div>
            
            <script>
                async function createLicense() {
                    const response = await fetch('/api/create-license', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({
                            secret: '${process.env.ADMIN_SECRET}',
                            days: 30
                        })
                    });
                    const result = await response.json();
                    if (result.success) {
                        alert('License created: ' + result.licenseKey);
                        loadLicenses();
                    }
                }
                
                async function loadLicenses() {
                    const response = await fetch('/api/list-licenses?secret=${process.env.ADMIN_SECRET}');
                    const licenses = await response.json();
                    
                    const html = licenses.map(license => {
                        const expired = new Date() > new Date(license.expiresAt);
                        return \`
                            <div class="license-item \${expired ? 'expired' : ''}">
                                <strong>\${license.licenseKey}</strong><br>
                                Expires: \${new Date(license.expiresAt).toLocaleDateString()}<br>
                                Status: \${expired ? '❌ Expired' : '✅ Active'}
                                <button class="danger" onclick="revokeLicense('\${license.licenseId}')">Revoke</button>
                            </div>
                        \`;
                    }).join('');
                    
                    document.getElementById('licensesList').innerHTML = html;
                }
                
                async function revokeLicense(licenseId) {
                    if (confirm('Revoke this license?')) {
                        await fetch('/api/revoke-license', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({
                                secret: '${process.env.ADMIN_SECRET}',
                                licenseId: licenseId
                            })
                        });
                        loadLicenses();
                    }
                }
                
                loadLicenses();
            </script>
        </div>
    </body>
    </html>
  `);
});

// API: Create license
app.post('/api/create-license', async (req, res) => {
  try {
    if (req.body.secret !== process.env.ADMIN_SECRET) {
      return res.status(403).json({ error: 'Access denied' });
    }

    const licenseId = crypto.randomBytes(8).toString('hex');
    const days = req.body.days || 30;
    const expiresAt = new Date(Date.now() + days * 24 * 60 * 60 * 1000).toISOString();
    
    const hash = crypto
      .createHash('md5')
      .update(licenseId + expiresAt + process.env.LICENSE_SECRET)
      .digest('hex')
      .substring(0, 16);

    const licenseKey = `${licenseId}:${expiresAt}:${hash}`;

    // Save to Firebase
    await db.ref(`licenses/${licenseId}`).set({
      licenseId,
      expiresAt,
      createdAt: new Date().toISOString(),
      features: ['basic'],
      active: true
    });

    res.json({
      success: true,
      licenseKey,
      licenseId,
      expiresAt
    });

  } catch (error) {
    console.error('Create license error:', error);
    res.status(500).json({ error: 'Failed to create license' });
  }
});

// API: List licenses
app.get('/api/list-licenses', async (req, res) => {
  try {
    if (req.query.secret !== process.env.ADMIN_SECRET) {
      return res.status(403).json({ error: 'Access denied' });
    }

    const snapshot = await db.ref('licenses').once('value');
    const licenses = snapshot.val() || {};

    const licenseList = Object.values(licenses).map(license => {
      const hash = crypto
        .createHash('md5')
        .update(license.licenseId + license.expiresAt + process.env.LICENSE_SECRET)
        .digest('hex')
        .substring(0, 16);

      return {
        licenseId: license.licenseId,
        licenseKey: `${license.licenseId}:${license.expiresAt}:${hash}`,
        expiresAt: license.expiresAt,
        createdAt: license.createdAt
      };
    });

    res.json(licenseList);

  } catch (error) {
    console.error('List licenses error:', error);
    res.status(500).json({ error: 'Failed to list licenses' });
  }
});

// API: Revoke license
app.post('/api/revoke-license', async (req, res) => {
  try {
    if (req.body.secret !== process.env.ADMIN_SECRET) {
      return res.status(403).json({ error: 'Access denied' });
    }

    await db.ref(`licenses/${req.body.licenseId}`).remove();

    res.json({ success: true });

  } catch (error) {
    console.error('Revoke license error:', error);
    res.status(500).json({ error: 'Failed to revoke license' });
  }
});

app.listen(PORT, () => {
  console.log(`License server on ${PORT}`);
});

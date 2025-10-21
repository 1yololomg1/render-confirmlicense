import express from "express";
import crypto from "crypto";
import admin from "firebase-admin";
import Stripe from "stripe";
import sgMail from "@sendgrid/mail";

const app = express();
app.use(express.json());

// Environment variable validation
const requiredEnvVars = [
  'type', 'project_id', 'private_key_id', 'private_key', 'client_email',
  'client_id', 'auth_uri', 'token_uri', 'auth_provider_x509_cert_url',
  'client_x509_cert_url', 'universe_domain', 'SHARED_SECRET', 'LICENSE_SECRET'
];

const missingVars = requiredEnvVars.filter(varName => !process.env[varName]);

if (missingVars.length > 0) {
  console.error('Missing required environment variables:', missingVars);
  console.error('Please set all Firebase service account environment variables');
  process.exit(1);
}

// Security Headers Middleware
app.use((req, res, next) => {
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Content-Security-Policy', 
    "default-src 'self'; " +
    "script-src 'self' 'unsafe-inline'; " +
    "style-src 'self' 'unsafe-inline'; " +
    "img-src 'self' data: https:; " +
    "font-src 'self' data: https:; " +
    "connect-src 'self'; " +
    "frame-ancestors 'none'; " +
    "base-uri 'self'; " +
    "form-action 'self'"
  );
  res.setHeader('Permissions-Policy', 
    'geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), speaker=()'
  );
  res.setHeader('Expect-CT', 'max-age=86400, enforce');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  res.removeHeader('X-Powered-By');
  next();
});

// Initialize Firebase with error handling
let db;
try {
  const serviceAccount = {
    type: process.env.type,
    project_id: process.env.project_id,
    private_key_id: process.env.private_key_id,
    private_key: process.env.private_key?.replace(/\\n/g, '\n'),
    client_email: process.env.client_email,
    client_id: process.env.client_id,
    auth_uri: process.env.auth_uri,
    token_uri: process.env.token_uri,
    auth_provider_x509_cert_url: process.env.auth_provider_x509_cert_url,
    client_x509_cert_url: process.env.client_x509_cert_url,
    universe_domain: process.env.universe_domain
  };

  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: "https://confirm-license-manager-default-rtdb.firebaseio.com"
  });

  db = admin.database();
  console.log('Firebase Realtime Database initialized successfully');
} catch (error) {
  console.error('Failed to initialize Firebase:', error);
  process.exit(1);
}

// Initialize other services with error handling
let stripe, sgMailInstance;
try {
  if (process.env.STRIPE_SECRET_KEY) {
    stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
    console.log('Stripe initialized successfully');
  }
  
  if (process.env.SENDGRID_API_KEY) {
    sgMail.setApiKey(process.env.SENDGRID_API_KEY);
    sgMailInstance = sgMail;
    console.log('SendGrid initialized successfully');
  }
} catch (error) {
  console.warn('Optional services failed to initialize:', error.message);
}

const sharedSecret = process.env.SHARED_SECRET;
const LICENSE_SECRET = process.env.LICENSE_SECRET;

console.log(`Using admin secret: ${sharedSecret?.substring(0, 8)}...`);
console.log(`Using license secret: ${LICENSE_SECRET?.substring(0, 8)}...`);

// License generation helper
function generateLicense(email, durationDays) {
  const licenseId = crypto.randomBytes(8).toString('hex');
  const expiry = new Date(Date.now() + durationDays * 24 * 60 * 60 * 1000).toISOString();
  const signature = crypto.createHmac('sha256', LICENSE_SECRET)
    .update(`${licenseId}:${expiry}`)
    .digest('hex')
    .substring(0, 16);
  
  const licenseKey = `${licenseId}:${expiry}:${signature}`;
  return { licenseKey, licenseId, expiry };
}

// License verification helper
function verifyLicense(licenseKey) {
  try {
    const parts = licenseKey.split(':');
    if (parts.length !== 3) return null;
    
    const [licenseId, expiry, signature] = parts;
    const expectedSignature = crypto.createHmac('sha256', LICENSE_SECRET)
      .update(`${licenseId}:${expiry}`)
      .digest('hex')
      .substring(0, 16);
    
    if (signature !== expectedSignature) return null;
    
    return { licenseId, expiry };
  } catch (error) {
    return null;
  }
}

// Helper function to migrate old license formats to new format
async function migrateOldLicense(oldLicenseKey, machineId) {
  console.log(`Attempting to migrate license: ${oldLicenseKey}`);
  
  try {
    // Look up the old license
    const oldLicenseSnapshot = await db.ref('license').orderByChild('license_key')
      .equalTo(oldLicenseKey).once('value');
    
    if (!oldLicenseSnapshot.exists()) {
      console.log(`Migration failed: License not found: ${oldLicenseKey}`);
      return { success: false, error: 'License not found' };
    }
    
    // Get the first matching license
    const licenseData = oldLicenseSnapshot.val();
    const oldLicenseId = Object.keys(licenseData)[0];
    const oldLicense = licenseData[oldLicenseId];
    
    // Check if this license was already migrated
    if (oldLicense.migrated_to) {
      console.log(`License already migrated: ${oldLicenseKey} → ${oldLicense.migrated_to}`);
      
      // Return the new license key that replaced this one
      const newLicenseSnapshot = await db.ref(`license/${oldLicense.migrated_to}`).once('value');
      const newLicense = newLicenseSnapshot.val();
      
      return {
        success: true,
        message: 'License was already migrated',
        newLicenseKey: newLicense.license_key,
        licenseData: newLicense
      };
    }
    
    // Extract expiry year from old license if available, or use default
    let expiryYear = new Date().getFullYear() + 1; // Default to 1 year from now
    if (oldLicenseKey.includes('2025')) expiryYear = 2025;
    else if (oldLicenseKey.includes('2026')) expiryYear = 2026;
    else if (oldLicenseKey.match(/\d{4}/)) {
      expiryYear = parseInt(oldLicenseKey.match(/\d{4}/)[0], 10);
    }
    
    // Create a new license with the same permissions but secure format
    const expiry = new Date(expiryYear, 11, 31).toISOString(); // December 31 of the year
    const licenseId = crypto.randomBytes(8).toString('hex');
    const signature = crypto.createHmac('sha256', LICENSE_SECRET)
      .update(`${licenseId}:${expiry}`)
      .digest('hex')
      .substring(0, 16);
    
    const newLicenseKey = `${licenseId}:${expiry}:${signature}`;
    
    // Create the new license
    await db.ref(`license/${licenseId}`).set({
      ...oldLicense,
      license_key: newLicenseKey,
      old_license_key: oldLicense.license_key,
      expires: expiry,
      migrated_at: new Date().toISOString(),
      migrated_from: oldLicenseId,
      computer_id: machineId || oldLicense.computer_id
    });
    
    // Update the old license to reference the new one
    await db.ref(`license/${oldLicenseId}`).update({
      migrated_to: licenseId,
      migrated_at: new Date().toISOString(),
      status: 'migrated'
    });
    
    console.log(`License migrated successfully: ${oldLicenseKey} → ${newLicenseKey}`);
    
    return {
      success: true,
      message: 'License migrated successfully',
      newLicenseKey,
      licenseId
    };
  } catch (error) {
    console.error('Migration error:', error);
    return { success: false, error: error.message };
  }
}

// VALIDATE LICENSE - Main endpoint for Python client
app.post('/validate', async (req, res) => {
  try {
    const { license_key, machine_id } = req.body;
    
    if (!license_key || !machine_id) {
      return res.status(400).json({ error: 'License key and machine ID are required' });
    }
    
    console.log(`Validating license for machine: ${machine_id?.substring(0, 8)}...`);
    
    // If this is an old-format license, suggest migration
    if (license_key.includes('-')) {
      return res.status(400).json({ 
        error: 'Invalid license key format',
        message: 'This appears to be an old-format license. Please use the /migrate-license endpoint to migrate this license to the new format.',
        needs_migration: true
      });
    }
    
    const verified = verifyLicense(license_key);
    if (!verified) {
      return res.status(400).json({ error: 'Invalid license key format' });
    }
    
    const { licenseId, expiry } = verified;
    
    // Get license from Realtime Database using licenseId only
    const snapshot = await db.ref(`license/${licenseId}`).once('value');
    const data = snapshot.val();
    
    if (!data) {
      return res.status(404).json({ error: 'License not found' });
    }
    
    // Check if license is revoked
    if (data.revoked) {
      return res.status(403).json({ error: 'License has been revoked' });
    }
    
    // Check expiry
    if (new Date() > new Date(expiry)) {
      return res.status(403).json({ error: 'License expired' });
    }
    
    // Check if already activated on different machine
    if (data.computer_id && data.computer_id !== machine_id) {
      return res.status(403).json({ error: 'License already activated on another machine' });
    }
    
    // If not yet bound, bind it now
    if (!data.computer_id) {
      await db.ref(`license/${licenseId}`).update({
        computer_id: machine_id,
        bound_at: new Date().toISOString(),
        binding_method: 'automatic'
      });
      console.log(`License ${licenseId} bound to machine ${machine_id?.substring(0, 8)}...`);
    }
    
    res.json({ 
      valid: true, 
      expiry,
      machineId: machine_id,
      tier: data.tier || 'professional',
      status: data.status || 'active'
    });
    
  } catch (error) {
    console.error('Validation error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Migration endpoint
app.post('/migrate-license', async (req, res) => {
  try {
    const { license_key, machine_id } = req.body;
    
    if (!license_key) {
      return res.status(400).json({ error: 'License key is required' });
    }
    
    // Only allow migrating old-format licenses
    if (!license_key.includes('-')) {
      return res.status(400).json({ 
        error: 'Not an old-format license',
        message: 'This license is already in the new format or invalid'
      });
    }
    
    const result = await migrateOldLicense(license_key, machine_id);
    
    if (!result.success) {
      return res.status(404).json({ error: result.error });
    }
    
    res.json({
      success: true,
      message: result.message,
      new_license_key: result.newLicenseKey
    });
    
  } catch (error) {
    console.error('Migration error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ACTIVATE LICENSE
app.post('/activate', async (req, res) => {
  try {
    const { license_key, machine_id, email } = req.body;
    
    if (!license_key || !machine_id) {
      return res.status(400).json({ error: 'License key and machine ID are required' });
    }
    
    const verified = verifyLicense(license_key);
    if (!verified) {
      return res.status(400).json({ error: 'Invalid license key' });
    }
    
    const { licenseId, expiry } = verified;
    
    const snapshot = await db.ref(`license/${licenseId}`).once('value');
    const data = snapshot.val();
    
    if (!data) {
      return res.status(404).json({ error: 'License not found' });
    }
    
    // Check if already activated on different machine
    if (data.computer_id && data.computer_id !== machine_id) {
      return res.status(403).json({ 
        error: 'License already activated on another machine' 
      });
    }
    
    // Check expiry
    if (new Date() > new Date(expiry)) {
      return res.status(403).json({ error: 'License expired' });
    }
    
    // Activate
    await db.ref(`license/${licenseId}`).update({
      computer_id: machine_id,
      bound_at: new Date().toISOString(),
      status: 'active'
    });
    
    res.json({ success: true, expiry, machineId: machine_id });
    
  } catch (error) {
    console.error('Activation error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Admin endpoints
app.post('/admin/create-license', async (req, res) => {
  if (!sharedSecret || req.get('x-app-secret') !== sharedSecret) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  
  const { email, productType, durationDays, notes } = req.body;
  
  if (!email || !productType || !durationDays) {
    return res.status(400).json({ error: 'Email, product type, and duration are required' });
  }
  
  try {
    const { licenseKey, licenseId, expiry } = generateLicense(email, durationDays);
    
    await db.ref(`license/${licenseId}`).set({
      license_key: licenseKey,
      email,
      tier: productType,
      expires: expiry,
      status: 'active',
      created_at: new Date().toISOString(),
      computer_id: null,
      notes: notes || '',
      admin_created: true
    });
    
    res.json({ 
      success: true, 
      message: 'License created successfully',
      license: {
        licenseKey,
        email,
        productType,
        expiry
      }
    });
    
  } catch (error) {
    console.error('Failed to create license:', error);
    res.status(500).json({ error: 'Failed to create license' });
  }
});

// Admin API endpoints for the admin interface
app.post('/admin/search-licenses', async (req, res) => {
  if (!sharedSecret || req.get('x-app-secret') !== sharedSecret) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  
  try {
    const { field, value } = req.body;
    
    if (!field || !value) {
      return res.status(400).json({ error: 'Field and value are required' });
    }
    
    // Determine how to query based on the field
    let snapshot;
    
    // Different query strategy based on field
    if (field === 'email') {
      snapshot = await db.ref('license').orderByChild('email').equalTo(value).once('value');
    } else if (field === 'license_key') {
      snapshot = await db.ref('license').orderByChild('license_key').startAt(value).endAt(value + '\uf8ff').once('value');
    } else if (field === 'computer_id') {
      snapshot = await db.ref('license').orderByChild('computer_id').equalTo(value).once('value');
    } else if (field === 'status') {
      snapshot = await db.ref('license').orderByChild('status').equalTo(value).once('value');
    } else {
      return res.status(400).json({ error: 'Invalid search field' });
    }
    
    const licenses = [];
    snapshot.forEach(child => {
      licenses.push({
        id: child.key,
        ...child.val()
      });
    });
    
    res.json({ licenses });
  } catch (error) {
    console.error('Search error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/admin/update-license', async (req, res) => {
  if (!sharedSecret || req.get('x-app-secret') !== sharedSecret) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  
  try {
    const { licenseId, status, extendDays, notes, unbindMachine } = req.body;
    
    if (!licenseId) {
      return res.status(400).json({ error: 'License ID is required' });
    }
    
    // Get the current license data
    const snapshot = await db.ref(`license/${licenseId}`).once('value');
    const license = snapshot.val();
    
    if (!license) {
      return res.status(404).json({ error: 'License not found' });
    }
    
    // Prepare updates
    const updates = {};
    
    // Update status if provided
    if (status) {
      updates.status = status;
    }
    
    // Extend expiry if days provided
    if (extendDays && extendDays > 0) {
      const currentExpiry = new Date(license.expires);
      const newExpiry = new Date(currentExpiry.getTime() + (extendDays * 24 * 60 * 60 * 1000));
      updates.expires = newExpiry.toISOString();
    }
    
    // Add notes if provided
    if (notes) {
      updates.admin_notes = license.admin_notes 
        ? `${license.admin_notes}\n${new Date().toISOString()}: ${notes}` 
        : `${new Date().toISOString()}: ${notes}`;
    }
    
    // Unbind machine if requested
    if (unbindMachine) {
      updates.computer_id = null;
      updates.bound_at = null;
      updates.binding_method = null;
    }
    
    // Add last updated timestamp
    updates.last_updated = new Date().toISOString();
    updates.updated_by = 'admin';
    
    // Apply updates
    await db.ref(`license/${licenseId}`).update(updates);
    
    res.json({ 
      success: true, 
      message: 'License updated successfully',
      updates
    });
    
  } catch (error) {
    console.error('Update error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Admin endpoint to migrate all old licenses
app.post('/admin/migrate-all-licenses', async (req, res) => {
  if (!sharedSecret || req.get('x-app-secret') !== sharedSecret) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  
  try {
    // Fetch all licenses
    const snapshot = await db.ref('license').once('value');
    const allLicenses = snapshot.val() || {};
    
    const oldFormatLicenses = [];
    
    // Find all licenses with old format keys
    for (const [key, license] of Object.entries(allLicenses)) {
      if (license.license_key && license.license_key.includes('-') && !license.migrated_to) {
        oldFormatLicenses.push({ key, license });
      }
    }
    
    console.log(`Found ${oldFormatLicenses.length} old-format licenses to migrate`);
    
    // Migrate each old license
    const results = [];
    for (const { key, license } of oldFormatLicenses) {
      try {
        const result = await migrateOldLicense(license.license_key, license.computer_id);
        results.push({
          oldKey: license.license_key,
          newKey: result.newLicenseKey,
          success: result.success
        });
      } catch (error) {
        console.error(`Failed to migrate license ${license.license_key}:`, error);
        results.push({
          oldKey: license.license_key,
          success: false,
          error: error.message
        });
      }
    }
    
    res.json({
      totalLicenses: oldFormatLicenses.length,
      results
    });
    
  } catch (error) {
    console.error('Mass migration error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/admin/license-stats', async (req, res) => {
  if (!sharedSecret || req.get('x-app-secret') !== sharedSecret) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  
  try {
    // Fetch all licenses
    const snapshot = await db.ref('license').once('value');
    const allLicenses = snapshot.val() || {};
    
    // Count metrics
    let activeLicenses = 0;
    let inactiveLicenses = 0;
    let revokedLicenses = 0;
    let expiredLicenses = 0;
    let migratedLicenses = 0;
    
    const licenseTypes = {};
    const recentActivity = [];
    
    const now = new Date();
    
    // Process each license
    Object.entries(allLicenses).forEach(([id, license]) => {
      // Count by status
      if (license.status === 'active') {
        activeLicenses++;
      } else if (license.status === 'inactive') {
        inactiveLicenses++;
      } else if (license.status === 'revoked') {
        revokedLicenses++;
        inactiveLicenses++; // Count revoked as inactive
      } else if (license.status === 'migrated') {
        migratedLicenses++;
      }
      
      // Check if expired
      if (license.expires && new Date(license.expires) < now) {
        expiredLicenses++;
      }
      
      // Count by type
      const type = license.tier || 'unknown';
      licenseTypes[type] = (licenseTypes[type] || 0) + 1;
      
      // Recent activity
      if (license.last_updated && new Date(license.last_updated) > new Date(now - 7 * 24 * 60 * 60 * 1000)) {
        recentActivity.push({
          licenseId: id,
          timestamp: license.last_updated,
          action: 'Updated',
          details: `Status: ${license.status}, Updated by: ${license.updated_by || 'system'}`
        });
      }
      
      if (license.created_at && new Date(license.created_at) > new Date(now - 7 * 24 * 60 * 60 * 1000)) {
        recentActivity.push({
          licenseId: id,
          timestamp: license.created_at,
          action: 'Created',
          details: license.admin_created ? 'Created by admin' : 'Created by system'
        });
      }
      
      if (license.migrated_at && new Date(license.migrated_at) > new Date(now - 7 * 24 * 60 * 60 * 1000)) {
        recentActivity.push({
          licenseId: id,
          timestamp: license.migrated_at,
          action: 'Migrated',
          details: `From: ${license.old_license_key || 'unknown'}`
        });
      }
    });
    
    // Sort recent activity by timestamp (newest first)
    recentActivity.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    
    res.json({
      totalLicenses: Object.keys(allLicenses).length,
      activeLicenses,
      inactiveLicenses,
      revokedLicenses,
      expiredLicenses,
      migratedLicenses,
      licenseTypes,
      recentActivity: recentActivity.slice(0, 10) // Just return the 10 most recent activities
    });
    
  } catch (error) {
    console.error('Stats error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    services: {
      firebase: 'connected',
      stripe: stripe ? 'connected' : 'not configured',
      sendgrid: sgMailInstance ? 'connected' : 'not configured'
    }
  });
});

app.get('/favicon.ico', (req, res) => res.status(204).end());
app.get('/', (req, res) => res.send('CONFIRM License Server Running'));

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Unhandled error:', error);
  res.status(500).json({ error: 'Internal server error' });
});

// Graceful shutdown handling
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('SIGINT received, shutting down gracefully');
  process.exit(0);
});

const port = process.env.PORT || 10000;
app.listen(port, () => {
  console.log(`License server running on port ${port}`);
  console.log(`Health check: http://localhost:${port}/health`);
});
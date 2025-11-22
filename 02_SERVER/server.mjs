/*
 * Copyright (c) 2024 TraceSeis, Inc.
 * All rights reserved.
 * 
 * This software and associated documentation files (the "Software") are proprietary
 * and confidential to TraceSeis, Inc. and its affiliates. The Software is protected
 * by copyright laws and international copyright treaties, as well as other intellectual
 * property laws and treaties.
 * 
 * Contact Information:
 * - Email: info@traceseis.com or alvarochf@traceseis.com
 * - Created by: Alvaro Chaveste (deltaV solutions)
 * 
 * Unauthorized copying, distribution, or modification of this Software is strictly
 * prohibited and may result in severe civil and criminal penalties.
 */

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

// CORS Middleware - Allow admin panel to connect
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-app-secret');
  res.setHeader('Access-Control-Max-Age', '86400');
  
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }
  
  next();
});

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
    'geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=()'
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

function verifyLicense(licenseKey) {
  try {
    const parts = licenseKey.split(':');
    if (parts.length < 3) return null;
    
    // Handle colons in ISO timestamp: first part is licenseId, last is signature, middle is expiry
    const licenseId = parts[0];
    const signature = parts[parts.length - 1];
    const expiry = parts.slice(1, -1).join(':');
    
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
    
  // ADD DEBUG LOGGING:
    const parts = license_key.split(':');
    console.log('License parts:', parts);
    if (parts.length >= 3) {
      const licenseId = parts[0];
      const signature = parts[parts.length - 1];
      const expiry = parts.slice(1, -1).join(':');
      
      const expectedSignature = crypto.createHmac('sha256', LICENSE_SECRET)
        .update(`${licenseId}:${expiry}`)
        .digest('hex')
        .substring(0, 16);
      console.log('Expected signature:', expectedSignature);
      console.log('Actual signature:', signature);
      console.log('Signatures match:', signature === expectedSignature);
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

// Comprehensive admin interface
app.get('/admin', (req, res) => {
  // Check for admin secret in header or query parameter for browser access
  const authSecret = req.get('x-app-secret') || req.query.secret;
  if (!sharedSecret || authSecret !== sharedSecret) {
    return res.status(403).send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Admin Access Required</title>
        <style>
          body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }
          .error { background: #f8d7da; color: #721c24; padding: 15px; border-radius: 4px; border: 1px solid #f5c6cb; }
          .info { background: #d1ecf1; color: #0c5460; padding: 15px; border-radius: 4px; border: 1px solid #bee5eb; margin-top: 20px; }
        </style>
      </head>
      <body>
        <h1>Admin Access Required</h1>
        <div class="error">
          <p><strong>Access Denied</strong></p>
          <p>Admin access requires proper authentication. Please provide the admin secret.</p>
        </div>
        <div class="info">
          <p><strong>How to access:</strong></p>
          <p>Add your admin secret as a query parameter: <code>?secret=YOUR_SECRET</code></p>
          <p>Or use the x-app-secret header when making API requests.</p>
        </div>
      </body>
      </html>
    `);
  }
  
  // Return full admin interface HTML
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>CONFIRM License Administration</title>
      <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; color: #333; line-height: 1.5; }
        h1, h2, h3 { color: #2c3e50; }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; padding-bottom: 20px; border-bottom: 1px solid #eee; }
        .header h1 { margin: 0; }
        .status { display: flex; align-items: center; }
        .status-dot { width: 12px; height: 12px; border-radius: 50%; margin-right: 8px; background: #4CAF50; }
        .container { background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); padding: 20px; margin-bottom: 20px; }
        .tabs { display: flex; margin-bottom: 20px; border-bottom: 1px solid #ddd; }
        .tab { padding: 10px 20px; cursor: pointer; margin-right: 5px; position: relative; }
        .tab.active { font-weight: bold; color: #3498db; }
        .tab.active:after { content: ""; position: absolute; bottom: -1px; left: 0; width: 100%; height: 2px; background: #3498db; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; font-weight: 500; }
        input, select, textarea { width: 100%; padding: 10px; box-sizing: border-box; border: 1px solid #ddd; border-radius: 4px; }
        input[type="checkbox"] { width: auto; margin-right: 10px; }
        button { padding: 10px 15px; background: #3498db; color: white; border: none; border-radius: 4px; cursor: pointer; font-weight: 500; }
        button:hover { background: #2980b9; }
        .result { margin-top: 20px; padding: 15px; border-radius: 4px; display: none; }
        .success { background-color: #d4edda; border-color: #c3e6cb; color: #155724; }
        .error { background-color: #f8d7da; border-color: #f5c6cb; color: #721c24; }
        pre { background: #f8f9fa; padding: 10px; overflow-x: auto; border-radius: 4px; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        table th, table td { text-align: left; padding: 12px; border-bottom: 1px solid #eee; }
        table th { background: #f8f9fa; }
        .search-form { display: flex; margin-bottom: 20px; }
        .search-form input { flex-grow: 1; margin-right: 10px; }
        .actions { display: flex; gap: 8px; }
        .actions button { padding: 6px 12px; }
        .btn-primary { background: #3498db; }
        .btn-warning { background: #f39c12; }
        .btn-danger { background: #e74c3c; }
        .btn-success { background: #2ecc71; }
        .badge { display: inline-block; padding: 3px 8px; border-radius: 12px; font-size: 12px; font-weight: bold; }
        .badge-active { background: #d4edda; color: #155724; }
        .badge-inactive { background: #f8d7da; color: #721c24; }
        .badge-expired { background: #fff3cd; color: #856404; }
        .badge-migrated { background: #cce5ff; color: #004085; }
        #licenseDetails { padding: 15px; background: #f8f9fa; border-radius: 4px; margin-top: 15px; }
        .copy-btn { background: #6c757d; margin-left: 10px; }
        .hidden { display: none; }
        .filter-row { display: flex; gap: 10px; margin-bottom: 15px; }
        .filter-row select, .filter-row input { max-width: 200px; }
        .flex-row { display: flex; gap: 10px; }
        .flex-row > * { flex-grow: 1; }
        .json-viewer { max-height: 400px; overflow-y: auto; }
      </style>
    </head>
    <body>
      <div class="header">
        <h1>CONFIRM License Administration</h1>
        <div class="status">
          <div class="status-dot"></div>
          <span>Connected to Firebase</span>
        </div>
      </div>
      
      <div class="tabs">
        <div class="tab active" data-tab="create">Create License</div>
        <div class="tab" data-tab="search">Search Licenses</div>
        <div class="tab" data-tab="migrate">Migrate Old Licenses</div>
        <div class="tab" data-tab="reports">Reports & Stats</div>
      </div>
      
      <!-- Create License Tab -->
      <div id="create-tab" class="tab-content active">
        <div class="container">
          <h2>Create New License</h2>
          <form id="licenseForm">
            <div class="flex-row">
              <div class="form-group">
                <label for="email">Client Email:</label>
                <input type="email" id="email" placeholder="client@example.com" required>
              </div>
              
              <div class="form-group">
                <label for="productType">License Type:</label>
                <select id="productType" required>
                  <option value="professional_monthly">Professional Monthly</option>
                  <option value="professional_yearly">Professional Yearly</option>
                  <option value="enterprise">Enterprise</option>
                  <option value="enterprise_yearly">Enterprise Yearly</option>
                  <option value="trial">Trial Version</option>
                </select>
              </div>
            </div>
            
            <div class="flex-row">
              <div class="form-group">
                <label for="durationDays">Duration (days):</label>
                <input type="number" id="durationDays" value="365" required>
              </div>
              
              <div class="form-group">
                <label for="createStatus">Initial Status:</label>
                <select id="createStatus">
                  <option value="active">Active</option>
                  <option value="inactive">Inactive</option>
                </select>
              </div>
            </div>
            
            <div class="form-group">
              <label for="notes">Notes:</label>
              <textarea id="notes" rows="3" placeholder="Additional information about this license"></textarea>
            </div>
            
            <div class="flex-row">
              <button type="submit" class="btn-primary">Generate License</button>
              <button type="reset" style="background: #6c757d;">Reset Form</button>
            </div>
          </form>
          
          <div id="createResult" class="result">
            <h3>License Created:</h3>
            <div class="flex-row" style="align-items: center;">
              <pre id="licenseKey" style="margin: 0; flex-grow: 1;"></pre>
              <button id="copyLicense" class="copy-btn">Copy</button>
            </div>
            <div class="json-viewer">
              <pre id="licenseOutput"></pre>
            </div>
          </div>
        </div>
      </div>
      
      <!-- Search Licenses Tab -->
      <div id="search-tab" class="tab-content">
        <div class="container">
          <h2>Search & Manage Licenses</h2>
          
          <div class="filter-row">
            <select id="filterField">
              <option value="email">Email</option>
              <option value="license_key">License Key</option>
              <option value="computer_id">Machine ID</option>
              <option value="status">Status</option>
            </select>
            <input type="text" id="filterValue" placeholder="Filter value...">
            <button id="searchBtn" class="btn-primary">Search</button>
            <button id="clearSearchBtn" style="background: #6c757d;">Clear</button>
          </div>
          
          <div id="searchResults">
            <p>Enter search criteria above and click Search.</p>
          </div>
          
          <div id="licenseDetails" class="hidden">
            <h3>License Details</h3>
            <div id="licenseData"></div>
            
            <div class="form-group" style="margin-top: 20px;">
              <h4>Update License</h4>
              
              <div class="flex-row">
                <div class="form-group">
                  <label for="updateStatus">Status:</label>
                  <select id="updateStatus">
                    <option value="active">Active</option>
                    <option value="inactive">Inactive</option>
                    <option value="revoked">Revoked</option>
                  </select>
                </div>
                
                <div class="form-group">
                  <label for="extendDays">Extend (days):</label>
                  <input type="number" id="extendDays" value="0">
                </div>
              </div>
              
              <div class="form-group">
                <label for="updateNotes">Update Notes:</label>
                <textarea id="updateNotes" rows="2"></textarea>
              </div>
              
              <div class="actions">
                <button id="updateLicenseBtn" class="btn-primary">Update License</button>
                <button id="unbindMachineBtn" class="btn-warning">Unbind Machine</button>
                <button id="revokeLicenseBtn" class="btn-danger">Revoke License</button>
              </div>
            </div>
          </div>
        </div>
      </div>
      
      <!-- Migrate Tab -->
      <div id="migrate-tab" class="tab-content">
        <div class="container">
          <h2>Migrate Old Licenses</h2>
          
          <form id="migrateForm">
            <div class="form-group">
              <label for="oldLicenseKey">Old License Key (with hyphens):</label>
              <input type="text" id="oldLicenseKey" placeholder="e.g., WHITE-2025-D4M0KR" required>
            </div>
            
            <div class="form-group">
              <label for="migrateMachineId">Machine ID (optional):</label>
              <input type="text" id="migrateMachineId" placeholder="e.g., b3f18bafd85e">
            </div>
            
            <button type="submit" class="btn-primary">Migrate License</button>
          </form>
          
          <div id="migrateResult" class="result">
            <h3>Migration Result:</h3>
            <pre id="migrationOutput"></pre>
          </div>
          
          <div style="margin-top: 30px;">
            <h3>Bulk Migration</h3>
            <p>Migrate all old-format licenses at once:</p>
            <button id="bulkMigrateBtn" class="btn-primary">Migrate All Old Licenses</button>
            <div id="bulkMigrateResult" class="result">
              <h3>Bulk Migration Results:</h3>
              <pre id="bulkMigrationOutput"></pre>
            </div>
          </div>
        </div>
      </div>
      
      <!-- Reports Tab -->
      <div id="reports-tab" class="tab-content">
        <div class="container">
          <h2>License Statistics</h2>
          
          <div id="statsLoading">Loading statistics...</div>
          <div id="statsContent" class="hidden">
            <div style="display: flex; gap: 20px; margin-bottom: 20px;">
              <div style="flex: 1; padding: 15px; background: #d4edda; border-radius: 4px; text-align: center;">
                <h3 style="margin-top: 0;">Active Licenses</h3>
                <div id="activeCount" style="font-size: 24px; font-weight: bold;">-</div>
              </div>
              <div style="flex: 1; padding: 15px; background: #f8d7da; border-radius: 4px; text-align: center;">
                <h3 style="margin-top: 0;">Inactive/Revoked</h3>
                <div id="inactiveCount" style="font-size: 24px; font-weight: bold;">-</div>
              </div>
              <div style="flex: 1; padding: 15px; background: #cce5ff; border-radius: 4px; text-align: center;">
                <h3 style="margin-top: 0;">Total Licenses</h3>
                <div id="totalCount" style="font-size: 24px; font-weight: bold;">-</div>
              </div>
            </div>
            
            <h3>License Types</h3>
            <div id="licenseTypesChart" style="height: 200px; background: #f8f9fa; margin-bottom: 20px; border-radius: 4px;"></div>
            
            <h3>Recent Activity</h3>
            <div id="recentActivity">
              <p>Loading recent activity...</p>
            </div>
          </div>
        </div>
      </div>
      
      <script>
        // Tab functionality
        document.querySelectorAll('.tab').forEach(tab => {
          tab.addEventListener('click', () => {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            
            tab.classList.add('active');
            document.getElementById(tab.dataset.tab + '-tab').classList.add('active');
          });
        });
        
        // Copy functionality
        document.getElementById('copyLicense').addEventListener('click', function() {
          const licenseKey = document.getElementById('licenseKey').textContent;
          navigator.clipboard.writeText(licenseKey).then(() => {
            this.textContent = 'Copied!';
            setTimeout(() => {
              this.textContent = 'Copy';
            }, 2000);
          });
        });
        
        // Create license form
        document.getElementById('licenseForm').addEventListener('submit', function(e) {
          e.preventDefault();
          
          const data = {
            email: document.getElementById('email').value,
            productType: document.getElementById('productType').value,
            durationDays: parseInt(document.getElementById('durationDays').value),
            notes: document.getElementById('notes').value,
            status: document.getElementById('createStatus').value
          };
          
          fetch('/admin/create-license', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'x-app-secret': '` + sharedSecret + `'
            },
            body: JSON.stringify(data)
          })
          .then(response => {
            if (!response.ok) {
              return response.text().then(text => {
                throw new Error(\`Server returned \${response.status}: \${text}\`);
              });
            }
            return response.json();
          })
          .then(data => {
            const resultDiv = document.getElementById('createResult');
            resultDiv.style.display = 'block';
            resultDiv.className = 'result success';
            
            document.getElementById('licenseKey').textContent = data.license.licenseKey;
            document.getElementById('licenseOutput').textContent = JSON.stringify(data, null, 2);
            
            // Update stats if visible
            if (document.getElementById('reports-tab').classList.contains('active')) {
              loadStatistics();
            }
          })
          .catch(error => {
            const resultDiv = document.getElementById('createResult');
            resultDiv.style.display = 'block';
            resultDiv.className = 'result error';
            
            document.getElementById('licenseKey').textContent = 'Error generating license';
            document.getElementById('licenseOutput').textContent = 'Error: ' + error.message;
          });
        });
        
        // License search functionality
        document.getElementById('searchBtn').addEventListener('click', searchLicenses);
        
        function searchLicenses() {
          const field = document.getElementById('filterField').value;
          const value = document.getElementById('filterValue').value;
          
          if (!value) {
            document.getElementById('searchResults').innerHTML = '<p>Please enter a search value.</p>';
            return;
          }
          
          document.getElementById('searchResults').innerHTML = '<p>Searching...</p>';
          
          // Hide license details panel
          document.getElementById('licenseDetails').classList.add('hidden');
          
          // Build the appropriate query based on the field
          let queryPath = '/admin/search-licenses';
          
          fetch(queryPath, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'x-app-secret': '` + sharedSecret + `'
            },
            body: JSON.stringify({
              field,
              value
            })
          })
          .then(response => {
            if (!response.ok) {
              throw new Error(\`Server returned \${response.status}: \${response.statusText}\`);
            }
            return response.json();
          })
          .then(data => {
            if (!data.licenses || data.licenses.length === 0) {
              document.getElementById('searchResults').innerHTML = '<p>No licenses found matching your criteria.</p>';
              return;
            }
            
            let html = \`
              <p>Found \${data.licenses.length} license(s)</p>
              <table>
                <thead>
                  <tr>
                    <th>License ID</th>
                    <th>Email</th>
                    <th>Type</th>
                    <th>Status</th>
                    <th>Expires</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
            \`;
            
            data.licenses.forEach(license => {
              const statusClass = license.status === 'active' ? 'badge-active' : 
                                 license.status === 'revoked' ? 'badge-inactive' :
                                 license.status === 'migrated' ? 'badge-migrated' : 'badge-inactive';
                                 
              const expiryDate = new Date(license.expires);
              const isExpired = expiryDate < new Date();
              
              html += \`
                <tr data-id="\${license.id}">
                  <td>\${license.id.substring(0, 8)}...</td>
                  <td>\${license.email || 'N/A'}</td>
                  <td>\${license.tier || 'standard'}</td>
                  <td><span class="badge \${statusClass}">\${license.status || 'inactive'}</span></td>
                  <td>\${new Date(license.expires).toLocaleDateString()} \${isExpired ? '(expired)' : ''}</td>
                  <td>
                    <button class="view-license" data-id="\${license.id}">View</button>
                  </td>
                </tr>
              \`;
            });
            
            html += \`
                </tbody>
              </table>
            \`;
            
            document.getElementById('searchResults').innerHTML = html;
            
            // Add event listeners to view buttons
            document.querySelectorAll('.view-license').forEach(button => {
              button.addEventListener('click', function() {
                const licenseId = this.dataset.id;
                const license = data.licenses.find(l => l.id === licenseId);
                showLicenseDetails(license);
              });
            });
          })
          .catch(error => {
            document.getElementById('searchResults').innerHTML = \`
              <div class="error" style="display: block; padding: 15px;">
                <p>Error searching licenses: \${error.message}</p>
              </div>
            \`;
          });
        }
        
        function showLicenseDetails(license) {
          const detailsDiv = document.getElementById('licenseDetails');
          detailsDiv.classList.remove('hidden');
          
          // Store license ID for update operations
          detailsDiv.dataset.licenseId = license.id;
          
          // Set initial values in update form
          document.getElementById('updateStatus').value = license.status || 'inactive';
          document.getElementById('updateNotes').value = '';
          
          // Generate details HTML
          let html = '<div class="json-viewer"><pre>' + JSON.stringify(license, null, 2) + '</pre></div>';
          
          document.getElementById('licenseData').innerHTML = html;
          
          // Scroll to details
          detailsDiv.scrollIntoView({ behavior: 'smooth' });
        }
        
        // License update functionality
        document.getElementById('updateLicenseBtn').addEventListener('click', function() {
          const licenseId = document.getElementById('licenseDetails').dataset.licenseId;
          const status = document.getElementById('updateStatus').value;
          const extendDays = parseInt(document.getElementById('extendDays').value) || 0;
          const notes = document.getElementById('updateNotes').value;
          
          updateLicense(licenseId, { status, extendDays, notes });
        });
        
        document.getElementById('unbindMachineBtn').addEventListener('click', function() {
          const licenseId = document.getElementById('licenseDetails').dataset.licenseId;
          updateLicense(licenseId, { unbindMachine: true });
        });
        
        document.getElementById('revokeLicenseBtn').addEventListener('click', function() {
          if (!confirm('Are you sure you want to revoke this license? This will prevent it from being used.')) {
            return;
          }
          
          const licenseId = document.getElementById('licenseDetails').dataset.licenseId;
          updateLicense(licenseId, { status: 'revoked', notes: 'License revoked by admin' });
        });
        
        function updateLicense(licenseId, updates) {
          fetch('/admin/update-license', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'x-app-secret': '` + sharedSecret + `'
            },
            body: JSON.stringify({
              licenseId,
              ...updates
            })
          })
          .then(response => {
            if (!response.ok) {
              throw new Error(\`Server returned \${response.status}: \${response.statusText}\`);
            }
            return response.json();
          })
          .then(data => {
            alert('License updated successfully!');
            // Re-run the current search to refresh data
            searchLicenses();
          })
          .catch(error => {
            alert('Error updating license: ' + error.message);
          });
        }
        
        // Clear search button
        document.getElementById('clearSearchBtn').addEventListener('click', function() {
          document.getElementById('filterValue').value = '';
          document.getElementById('searchResults').innerHTML = '<p>Enter search criteria above and click Search.</p>';
          document.getElementById('licenseDetails').classList.add('hidden');
        });
        
        // Migrate license form
        document.getElementById('migrateForm').addEventListener('submit', function(e) {
          e.preventDefault();
          
          const oldLicenseKey = document.getElementById('oldLicenseKey').value;
          const machineId = document.getElementById('migrateMachineId').value || 'admin-migration-' + Date.now();
          
          document.getElementById('migrateResult').style.display = 'block';
          document.getElementById('migrateResult').className = 'result';
          document.getElementById('migrationOutput').textContent = 'Migrating license...';
          
          fetch('/migrate-license', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'x-app-secret': '` + sharedSecret + `'
            },
            body: JSON.stringify({
              license_key: oldLicenseKey,
              machine_id: machineId
            })
          })
          .then(response => {
            if (!response.ok) {
              return response.text().then(text => {
                throw new Error(\`Server returned \${response.status}: \${text}\`);
              });
            }
            return response.json();
          })
          .then(data => {
            const resultDiv = document.getElementById('migrateResult');
            resultDiv.className = 'result success';
            
            document.getElementById('migrationOutput').textContent = 
              'Migration successful!\\n\\n' +
              'New License Key: ' + data.new_license_key + '\\n\\n' +
              'Message: ' + data.message;
          })
          .catch(error => {
            const resultDiv = document.getElementById('migrateResult');
            resultDiv.className = 'result error';
            
            document.getElementById('migrationOutput').textContent = 'Error: ' + error.message;
          });
        });
        
        // Bulk migration button
        document.getElementById('bulkMigrateBtn').addEventListener('click', function() {
          if (!confirm('This will migrate ALL old-format licenses to the new format. Continue?')) {
            return;
          }
          
          document.getElementById('bulkMigrateResult').style.display = 'block';
          document.getElementById('bulkMigrateResult').className = 'result';
          document.getElementById('bulkMigrationOutput').textContent = 'Starting bulk migration...';
          
          fetch('/admin/migrate-all-licenses', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'x-app-secret': '` + sharedSecret + `'
            }
          })
          .then(response => {
            if (!response.ok) {
              return response.text().then(text => {
                throw new Error(\`Server returned \${response.status}: \${text}\`);
              });
            }
            return response.json();
          })
          .then(data => {
            const resultDiv = document.getElementById('bulkMigrateResult');
            resultDiv.className = 'result success';
            
            let output = \`Migration complete! Migrated \${data.totalLicenses} licenses.\\n\\nResults:\\n\`;
            
            data.results.forEach(result => {
              if (result.success) {
                output += \`✅ \${result.oldKey} → \${result.newKey}\\n\`;
              } else {
                output += \`❌ \${result.oldKey}: \${result.error}\\n\`;
              }
            });
            
            document.getElementById('bulkMigrationOutput').textContent = output;
          })
          .catch(error => {
            const resultDiv = document.getElementById('bulkMigrateResult');
            resultDiv.className = 'result error';
            
            document.getElementById('bulkMigrationOutput').textContent = 'Error: ' + error.message;
          });
        });
        
        // Reports tab functionality
        function loadStatistics() {
          document.getElementById('statsLoading').style.display = 'block';
          document.getElementById('statsContent').classList.add('hidden');
          
          fetch('/admin/license-stats', {
            method: 'GET',
            headers: {
              'x-app-secret': '` + sharedSecret + `'
            }
          })
          .then(response => {
            if (!response.ok) {
              throw new Error(\`Server returned \${response.status}: \${response.statusText}\`);
            }
            return response.json();
          })
          .then(data => {
            // Update counts
            document.getElementById('activeCount').textContent = data.activeLicenses || 0;
            document.getElementById('inactiveCount').textContent = data.inactiveLicenses || 0;
            document.getElementById('totalCount').textContent = data.totalLicenses || 0;
            
            // Display recent activity
            let recentHtml = '<table><thead><tr><th>Date</th><th>Action</th><th>License</th><th>Details</th></tr></thead><tbody>';
            
            if (data.recentActivity && data.recentActivity.length > 0) {
              data.recentActivity.forEach(activity => {
                recentHtml += \`
                  <tr>
                    <td>\${new Date(activity.timestamp).toLocaleString()}</td>
                    <td>\${activity.action}</td>
                    <td>\${activity.licenseId.substring(0, 8)}...</td>
                    <td>\${activity.details || ''}</td>
                  </tr>
                \`;
              });
            } else {
              recentHtml += '<tr><td colspan="4">No recent activity</td></tr>';
            }
            
            recentHtml += '</tbody></table>';
            document.getElementById('recentActivity').innerHTML = recentHtml;
            
            // Simple bar chart for license types
            let licenseTypesHtml = '<div style="display: flex; height: 100%;">';
            
            if (data.licenseTypes && Object.keys(data.licenseTypes).length > 0) {
              const types = Object.keys(data.licenseTypes);
              const values = Object.values(data.licenseTypes);
              const max = Math.max(...values);
              
              const colors = [
                '#4285F4', '#EA4335', '#FBBC05', '#34A853', '#FF6D01', 
                '#46BDC6', '#7BAAF7', '#F07B72', '#FCD663', '#71C588'
              ];
              
              types.forEach((type, index) => {
                const value = values[index];
                const percentage = (value / max) * 100;
                const height = Math.max(percentage, 10); // Ensure at least 10% height for visibility
                
                licenseTypesHtml += \`
                  <div style="flex: 1; display: flex; flex-direction: column; align-items: center; padding: 0 5px;">
                    <div style="margin-top: auto; width: 30px; height: \${height}%; background-color: \${colors[index % colors.length]}; border-radius: 4px 4px 0 0;"></div>
                    <div style="margin-top: 8px; text-align: center; font-size: 12px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 80px;">
                      \${type}<br>\${value}
                    </div>
                  </div>
                \`;
              });
            } else {
              licenseTypesHtml += '<div style="margin: auto; text-align: center;">No license type data available</div>';
            }
            
            licenseTypesHtml += '</div>';
            document.getElementById('licenseTypesChart').innerHTML = licenseTypesHtml;
            
            // Show stats content, hide loading
            document.getElementById('statsLoading').style.display = 'none';
            document.getElementById('statsContent').classList.remove('hidden');
          })
          .catch(error => {
            document.getElementById('statsLoading').style.display = 'none';
            document.getElementById('statsContent').classList.remove('hidden');
            
            document.getElementById('statsContent').innerHTML = \`
              <div class="error" style="display: block; padding: 15px;">
                <p>Error loading statistics: \${error.message}</p>
              </div>
            \`;
          });
        }
        
        // Load statistics when the reports tab is clicked
        document.querySelector('.tab[data-tab="reports"]').addEventListener('click', loadStatistics);
      </script>
    </body>
    </html>
  `);
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

// ORGANIC ENHANCEMENT - Session Token Caching
const sessionTokens = new Map(); // In-memory session cache

// New endpoint for cached validation
app.post('/validate-cached', async (req, res) => {
  try {
    const { licenseKey, machineId, sessionToken } = req.body;

    // Check if we have a valid cached session
    if (sessionToken && sessionTokens.has(sessionToken)) {
      const session = sessionTokens.get(sessionToken);
      
      // Check if session is still valid (7 days)
      if (new Date() < new Date(session.expiresAt) && session.licenseKey === licenseKey) {
        console.log(`Using cached session for ${session.licenseId}`);
        return res.json({
          valid: true,
          licenseId: session.licenseId,
          expiresAt: session.licenseExpiresAt,
          sessionToken: sessionToken,
          sessionExpiresAt: session.expiresAt,
          source: 'cache'
        });
      } else {
        // Remove expired session
        sessionTokens.delete(sessionToken);
      }
    }

    // No valid session - do full validation (same as existing logic)
    const parts = licenseKey.split(':');
    if (parts.length !== 3) {
      return res.status(400).json({ valid: false, error: 'Invalid license key format' });
    }

    const [licenseId, expiresAt, hash] = parts;

    // Use existing validation logic
    const licenseRef = db.ref(`licenses/${licenseId}`);
    const snapshot = await licenseRef.once('value');

    if (!snapshot.exists()) {
      return res.json({ valid: false, error: 'License not found' });
    }

    if (new Date() > new Date(expiresAt)) {
      return res.json({ valid: false, error: 'License expired' });
    }

    // Verify hash (same as existing)
    const expectedHash = crypto
      .createHash('md5')
      .update(licenseId + expiresAt + process.env.LICENSE_SECRET)
      .digest('hex')
      .substring(0, 16);

    if (hash !== expectedHash) {
      return res.json({ valid: false, error: 'Invalid license signature' });
    }

    // Create new 7-day session token
    const newSessionToken = crypto.randomBytes(32).toString('hex');
    const sessionExpiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
    
    sessionTokens.set(newSessionToken, {
      licenseKey,
      licenseId,
      licenseExpiresAt: expiresAt,
      expiresAt: sessionExpiresAt,
      machineId,
      createdAt: new Date().toISOString()
    });

    console.log(`Created 7-day session for license ${licenseId}`);

    res.json({
      valid: true,
      licenseId,
      expiresAt,
      sessionToken: newSessionToken,
      sessionExpiresAt,
      source: 'validated'
    });

  } catch (error) {
    console.error('Cached validation error:', error);
    res.status(500).json({ valid: false, error: 'Validation failed' });
  }
});

// Cleanup expired sessions every hour
setInterval(() => {
  const now = new Date();
  for (const [token, session] of sessionTokens.entries()) {
    if (now > new Date(session.expiresAt)) {
      sessionTokens.delete(token);
    }
  }
}, 60 * 60 * 1000);

import express from "express";
import crypto from "crypto";
import admin from "firebase-admin";
import Stripe from "stripe";
import sgMail from "@sendgrid/mail";

const app = express();
app.use(express.json());

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

// Initialize Firebase with Realtime Database
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

// Use Realtime Database instead of Firestore
const db = admin.database();
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

const sharedSecret = process.env.SHARED_SECRET;
const LICENSE_SECRET = process.env.LICENSE_SECRET;

console.log(`Using admin secret: ${sharedSecret?.substring(0, 8)}...`);
console.log(`Using license secret: ${LICENSE_SECRET?.substring(0, 8)}...`);
console.log('Firebase Realtime Database initialized: true');

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

// VALIDATE LICENSE - Main endpoint for Python client
app.post('/validate', async (req, res) => {
  try {
    const { license_key, machine_id } = req.body;
    
    console.log(`Validating license for machine: ${machine_id?.substring(0, 8)}...`);
    
    const verified = verifyLicense(license_key);
    if (!verified) {
      return res.status(400).json({ error: 'Invalid license key format' });
    }
    
    const { licenseId, expiry } = verified;
    
    // Get license from Realtime Database
    const snapshot = await db.ref(`license/${license_key}`).once('value');
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
      await db.ref(`license/${license_key}`).update({
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

// ACTIVATE LICENSE
app.post('/activate', async (req, res) => {
  try {
    const { license_key, machine_id, email } = req.body;
    
    const verified = verifyLicense(license_key);
    if (!verified) {
      return res.status(400).json({ error: 'Invalid license key' });
    }
    
    const { licenseId, expiry } = verified;
    
    const snapshot = await db.ref(`license/${license_key}`).once('value');
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
    await db.ref(`license/${license_key}`).update({
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
    
    await db.ref(`license/${licenseKey}`).set({
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

app.get('/favicon.ico', (req, res) => res.status(204).end());
app.get('/', (req, res) => res.send('CONFIRM License Server Running'));

const port = process.env.PORT || 10000;
app.listen(port, () => console.log(`License server on ${port}`));

import express from "express";
import crypto from "crypto";
import admin from "firebase-admin";
import Stripe from "stripe";
import sgMail from "@sendgrid/mail";
// Configuration loaded directly from environment variables

const app = express();

// Security Headers Middleware
app.use((req, res, next) => {
  // Prevent XSS attacks
  res.setHeader('X-XSS-Protection', '1; mode=block');
  
  // Prevent clickjacking
  res.setHeader('X-Frame-Options', 'DENY');
  
  // Prevent MIME type sniffing
  res.setHeader('X-Content-Type-Options', 'nosniff');
  
  // Referrer policy
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  
  // Content Security Policy
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
  
  // Feature Policy
  res.setHeader('Permissions-Policy', 
    'geolocation=(), ' +
    'microphone=(), ' +
    'camera=(), ' +
    'payment=(), ' +
    'usb=(), ' +
    'magnetometer=(), ' +
    'gyroscope=(), ' +
    'speaker=()'
  );
  
  // Expect Certificate Transparency
  res.setHeader('Expect-CT', 'max-age=86400, enforce');
  
  // Strict Transport Security (HTTPS only)
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  
  // Remove X-Powered-By header
  res.removeHeader('X-Powered-By');
  
  next();
});

// Initialize Firebase
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
  credential: admin.credential.cert(serviceAccount)
});

const db = admin.firestore();
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

// Load configuration from environment variables
const sharedSecret = process.env.SHARED_SECRET;
const LICENSE_SECRET = process.env.LICENSE_SECRET;

console.log(`Using admin secret: ${sharedSecret.substring(0, 8)}...`);
console.log(`Using license secret: ${LICENSE_SECRET.substring(0, 8)}...`);

// Pricing tiers configuration
const PRICING_TIERS = {
  [process.env.STRIPE_PRICE_ID_STUDENT_YEAR]: { 
    days: 365, 
    name: 'Student Annual',
    requiresApproval: false
  },
  [process.env.STRIPE_PRICE_ID_STARTUP_MONTH]: { 
    days: 30, 
    name: 'Startup Monthly',
    requiresApproval: false
  },
  [process.env.STRIPE_PRICE_ID_PRO_MONTH]: { 
    days: 30, 
    name: 'Professional Monthly',
    requiresApproval: false
  },
  [process.env.STRIPE_PRICE_ID_PRO_YEAR]: { 
    days: 365, 
    name: 'Professional Annual',
    requiresApproval: false
  },
  [process.env.STRIPE_PRICE_ID_ENTERPRISE_MONTH]: { 
    days: 30, 
    name: 'Enterprise Monthly',
    requiresApproval: false
  },
  [process.env.STRIPE_PRICE_ID_ENTERPRISE_YEAR]: { 
    days: 365, 
    name: 'Enterprise Annual',
    requiresApproval: false
  },
  [process.env.STRIPE_PRICE_ID_INTEGRATION]: { 
    days: 365, 
    name: 'Integration Annual',
    requiresApproval: false
  },
  [process.env.STRIPE_PRICE_ID_WHITELABEL]: { 
    days: 365, 
    name: 'White-label Annual',
    requiresApproval: false
  }
};

// Webhook needs raw body
app.use('/webhook', express.raw({type: 'application/json'}));
app.use(express.json());

// Generate license key
function generateLicense(email, durationDays) {
  const licenseId = crypto.randomBytes(16).toString('hex');
  const expiryDate = new Date();
  expiryDate.setDate(expiryDate.getDate() + durationDays);
  const expiry = expiryDate.toISOString();
  
  const signature = crypto
    .createHmac('sha256', LICENSE_SECRET)
    .update(`${licenseId}:${expiry}`)
    .digest('hex')
    .substring(0, 16);
  
  return {
    licenseKey: `${licenseId}:${expiry}:${signature}`,
    licenseId,
    expiry
  };
}

// Verify license signature
function verifyLicense(licenseKey) {
  try {
    const [licenseId, expiry, signature] = licenseKey.split(':');
    const expectedSig = crypto
      .createHmac('sha256', LICENSE_SECRET)
      .update(`${licenseId}:${expiry}`)
      .digest('hex')
      .substring(0, 16);
    return signature === expectedSig ? { licenseId, expiry } : null;
  } catch {
    return null;
  }
}

// STRIPE WEBHOOK - generates license on purchase
app.post('/webhook', async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;
  
  try {
    event = stripe.webhooks.constructEvent(
      req.body, 
      sig, 
      process.env.STRIPE_WEBHOOK_SECRET
    );
  } catch (err) {
    console.error('Webhook signature verification failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }
  
  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const customerEmail = session.customer_details?.email;
    
    if (!customerEmail) {
      console.error('No email in webhook');
      return res.status(400).json({ error: 'No email' });
    }
    
    try {
      // Get what they purchased
      const lineItems = await stripe.checkout.sessions.listLineItems(session.id);
      const priceId = lineItems.data[0].price.id;
      
      // Look up the product
      const product = PRICING_TIERS[priceId];
      
      if (!product) {
        console.error('Unknown price ID:', priceId);
        return res.status(400).json({ error: 'Unknown product' });
      }
      
      const { days: durationDays, name: productName, requiresApproval } = product;
      
      // Generate license
      const { licenseKey, licenseId, expiry } = generateLicense(customerEmail, durationDays);
      
      // Store in Firestore
      await db.collection('licenses').doc(licenseId).set({
        email: customerEmail,
        licenseKey,
        expiry,
        createdAt: new Date().toISOString(),
        activated: false,
        machineId: null,
        stripeSessionId: session.id,
        productType: productName,
        durationDays: durationDays,
        requiresApproval: requiresApproval,
        manuallyApproved: false
      });
      
      // Send email automatically (you can manually verify later if needed)
      await sgMail.send({
        to: customerEmail,
        from: 'noreply@deltavsolutions.com', // CHANGE TO YOUR VERIFIED SENDGRID EMAIL
        subject: 'Your CONFIRM License Key',
        text: `Thank you for purchasing CONFIRM (${productName})!

Your license key: ${licenseKey}

This license is valid until: ${new Date(expiry).toLocaleDateString()}

DOWNLOAD SOFTWARE:
[ADD YOUR DOWNLOAD LINK HERE]

TO ACTIVATE:
1. Download and run CONFIRM using the link above
2. Enter this license key when prompted
3. Your software will be activated on this computer

If you have any questions, reply to this email.

Thank you,
deltaV solutions`,
        html: `<p>Thank you for purchasing CONFIRM <strong>(${productName})</strong>!</p>
<p><strong>Your license key:</strong><br>
<code style="background: #f4f4f4; padding: 10px; display: block; font-size: 14px; font-family: monospace;">${licenseKey}</code></p>
<p>This license is valid until: <strong>${new Date(expiry).toLocaleDateString()}</strong></p>
<h3>Download Software:</h3>
<p><a href="[ADD YOUR DOWNLOAD LINK]" style="background: #0066cc; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px; display: inline-block;">Download CONFIRM</a></p>
<h3>To Activate:</h3>
<ol>
<li>Download and run CONFIRM using the link above</li>
<li>Enter this license key when prompted</li>
<li>Your software will be activated on this computer</li>
</ol>
<p>If you have any questions, reply to this email.</p>
<p>Thank you,<br>deltaV solutions</p>`
      });
      
      console.log(`✓ ${productName} license sent to ${customerEmail}`);
      console.log(`License key: ${licenseKey}`);
      
    } catch (error) {
      console.error('Failed to process license:', error);
    }
  }
  
  res.json({ received: true });
});

// MANUAL APPROVAL - for cases where you need to verify before activation
app.post('/admin/approve-license', async (req, res) => {
  if (!sharedSecret || req.get('x-app-secret') !== sharedSecret) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  
  const { license_id } = req.body;
  
  const docRef = db.collection('licenses').doc(license_id);
  const doc = await docRef.get();
  
  if (!doc.exists) {
    return res.status(404).json({ error: 'License not found' });
  }
  
  await docRef.update({
    manuallyApproved: true,
    approvedAt: new Date().toISOString()
  });
  
  res.json({ success: true, message: 'License approved' });
});

// MANUAL LICENSE CREATION - for admin-created licenses
app.post('/admin/create-license', async (req, res) => {
  if (!sharedSecret || req.get('x-app-secret') !== sharedSecret) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  
  const { email, productType, durationDays, notes } = req.body;
  
  if (!email || !productType || !durationDays) {
    return res.status(400).json({ error: 'Email, product type, and duration are required' });
  }
  
  try {
    // Generate license
    const { licenseKey, licenseId, expiry } = generateLicense(email, durationDays);
    
    // Store in Firestore
    await db.collection('licenses').doc(licenseId).set({
      email: email,
      licenseKey,
      expiry,
      createdAt: new Date().toISOString(),
      activated: false,
      machineId: null,
      stripeSessionId: 'manual-creation',
      productType: productType,
      durationDays: durationDays,
      requiresApproval: false,
      manuallyApproved: true,
      adminCreated: true,
      notes: notes || '',
      createdBy: 'admin'
    });
    
    res.json({ 
      success: true, 
      message: 'License created successfully',
      license: {
        id: licenseId,
        licenseKey,
        email,
        productType,
        expiry,
        createdAt: new Date().toISOString()
      }
    });
    
  } catch (error) {
    console.error('Failed to create license:', error);
    res.status(500).json({ error: 'Failed to create license' });
  }
});

// LICENSE REVOCATION - revoke a license
app.post('/admin/revoke-license', async (req, res) => {
  if (!sharedSecret || req.get('x-app-secret') !== sharedSecret) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  
  const { licenseId, reason } = req.body;
  
  if (!licenseId) {
    return res.status(400).json({ error: 'License ID is required' });
  }
  
  try {
    const docRef = db.collection('licenses').doc(licenseId);
    const doc = await docRef.get();
    
    if (!doc.exists) {
      return res.status(404).json({ error: 'License not found' });
    }
    
    const data = doc.data();
    
    // Update license status
    await docRef.update({
      revoked: true,
      revokedAt: new Date().toISOString(),
      revokedBy: 'admin',
      revocationReason: reason || 'No reason provided',
      activated: false,
      machineId: null
    });
    
    res.json({ 
      success: true, 
      message: 'License revoked successfully',
      license: {
        id: licenseId,
        email: data.email,
        productType: data.productType,
        revokedAt: new Date().toISOString(),
        revocationReason: reason || 'No reason provided'
      }
    });
    
  } catch (error) {
    console.error('Failed to revoke license:', error);
    res.status(500).json({ error: 'Failed to revoke license' });
  }
});

// ACTIVATE LICENSE
app.post('/activate', async (req, res) => {
  
  const { license_key, machine_id, email } = req.body;
  
  const verified = verifyLicense(license_key);
  if (!verified) {
    return res.status(400).json({ error: 'Invalid license key' });
  }
  
  const { licenseId, expiry } = verified;
  
  const docRef = db.collection('licenses').doc(licenseId);
  const doc = await docRef.get();
  
  if (!doc.exists) {
    return res.status(404).json({ error: 'License not found' });
  }
  
  const data = doc.data();
  
  // Check if requires manual approval (though currently all set to false)
  if (data.requiresApproval && !data.manuallyApproved) {
    return res.status(403).json({ 
      error: 'License pending approval. Please contact support.' 
    });
  }
  
  // Check if already activated on different machine
  if (data.activated && data.machineId !== machine_id) {
    return res.status(403).json({ 
      error: 'License already activated on another machine' 
    });
  }
  
  // Check expiry
  if (new Date() > new Date(expiry)) {
    return res.status(403).json({ error: 'License expired' });
  }
  
  // Activate
  await docRef.update({
    activated: true,
    machineId: machine_id,
    activatedAt: new Date().toISOString()
  });
  
  res.json({ success: true, expiry, machineId: machine_id });
});

// VALIDATE LICENSE
app.post('/validate', async (req, res) => {
  
  const { license_key, machine_id } = req.body;
  
  const verified = verifyLicense(license_key);
  if (!verified) {
    return res.status(400).json({ error: 'Invalid license' });
  }
  
  const { licenseId, expiry } = verified;
  
  const doc = await db.collection('licenses').doc(licenseId).get();
  
  if (!doc.exists) {
    return res.status(404).json({ error: 'License not found' });
  }
  
  const data = doc.data();
  
  // Check if license is revoked
  if (data.revoked) {
    return res.status(403).json({ error: 'License has been revoked' });
  }
  
  // Check if license requires approval and is not approved
  if (data.requiresApproval && !data.manuallyApproved) {
    return res.status(403).json({ error: 'License pending approval' });
  }
  
  // If activated, check machine ID matches
  if (data.activated && data.machineId !== machine_id) {
    return res.status(403).json({ error: 'License already activated on different machine' });
  }
  
  if (new Date() > new Date(expiry)) {
    return res.status(403).json({ error: 'License expired' });
  }
  
  res.json({ valid: true, expiry });
});

// ADMIN DASHBOARD
app.get('/admin', (req, res) => {
  // Allow access to admin panel without header (web interface)
  // API endpoints below still require authentication
  
  res.send(`
<!DOCTYPE html>
<html>
<head>
  <title>License Admin</title>
  <style>
    body { 
      font-family: Arial, sans-serif; 
      max-width: 1000px; 
      margin: 50px auto; 
      padding: 20px;
      background: #f5f5f5;
    }
    .section { 
      background: white; 
      padding: 20px; 
      margin: 20px 0; 
      border-radius: 8px;
      box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    button { 
      background: #0066cc; 
      color: white; 
      border: none; 
      padding: 12px 24px; 
      border-radius: 4px;
      cursor: pointer;
      font-size: 16px;
      margin: 5px;
    }
    button:hover { background: #0052a3; }
    input { 
      padding: 10px; 
      font-size: 16px; 
      width: 300px;
      border: 1px solid #ddd;
      border-radius: 4px;
    }
    .license { 
      background: #f9f9f9; 
      padding: 15px; 
      margin: 10px 0; 
      border-left: 4px solid #0066cc;
      border-radius: 4px;
    }
    .key { 
      font-family: monospace; 
      background: #eee; 
      padding: 8px; 
      display: inline-block;
      word-break: break-all;
      margin: 5px 0;
    }
    .copy-btn { 
      background: #28a745; 
      padding: 6px 12px;
      font-size: 14px;
    }
    .copy-btn:hover { background: #218838; }
    h2 { color: #333; }
    .success { color: #28a745; font-weight: bold; }
    .error { color: #dc3545; font-weight: bold; }
  </style>
</head>
<body>
  <h1>CONFIRM License Administration</h1>
  
  <div class="section">
    <h2>Create New License</h2>
    <div style="margin-bottom: 15px;">
      <label>Customer Email:</label><br>
      <input type="email" id="createEmailInput" placeholder="customer@example.com" style="width: 100%; margin-top: 5px;">
    </div>
    <div style="margin-bottom: 15px;">
      <label>Product Type:</label><br>
      <select id="productTypeSelect" style="width: 100%; padding: 10px; font-size: 16px; margin-top: 5px;">
        <option value="student">Student</option>
        <option value="startup">Startup</option>
        <option value="professional" selected>Professional</option>
        <option value="enterprise">Enterprise</option>
        <option value="integration">Integration</option>
        <option value="whitelabel">White-label</option>
      </select>
    </div>
    <div style="margin-bottom: 15px;">
      <label>Duration (days):</label><br>
      <input type="number" id="durationInput" value="365" min="1" max="3650" style="width: 100%; margin-top: 5px;">
    </div>
    <div style="margin-bottom: 15px;">
      <label>Machine ID (optional):</label><br>
      <input type="text" id="machineIdInput" placeholder="Leave empty for any machine" style="width: 100%; margin-top: 5px;">
    </div>
    <div style="margin-bottom: 15px;">
      <label>Notes (optional):</label><br>
      <textarea id="notesInput" placeholder="Additional notes..." style="width: 100%; height: 60px; margin-top: 5px; padding: 10px; font-size: 16px; border: 1px solid #ddd; border-radius: 4px;"></textarea>
    </div>
    <button onclick="createLicense()">Create License</button>
    <div id="createResult"></div>
  </div>
  
  <div class="section">
    <h2>Look Up License by Email</h2>
    <input type="email" id="emailInput" placeholder="customer@example.com">
    <button onclick="lookupEmail()">Look Up</button>
    <div id="lookupResult"></div>
  </div>
  
  <div class="section">
    <h2>Pending Licenses (Not Yet Activated)</h2>
    <button onclick="showPending()">Show Pending</button>
    <div id="pendingResult"></div>
  </div>
  
  <div class="section">
    <h2>Recent Activity (Last 24 Hours)</h2>
    <button onclick="showRecent()">Show Recent</button>
    <div id="recentResult"></div>
  </div>

  <script>
    // Use the correct admin secret - must match server SHARED_SECRET
    const SECRET = '${sharedSecret || "default-admin-secret"}';  // This injects the actual server secret
    
    console.log('Admin panel loaded');
    console.log('SECRET value:', SECRET);
    
    function copyToClipboard(text) {
      navigator.clipboard.writeText(text).then(() => {
        alert('License key copied to clipboard!');
      });
    }
    
    async function createLicense() {
      const email = document.getElementById('createEmailInput').value;
      const productType = document.getElementById('productTypeSelect').value;
      const durationDays = parseInt(document.getElementById('durationInput').value);
      const notes = document.getElementById('notesInput').value;
      
      if (!email) {
        alert('Please enter an email');
        return;
      }
      
      const result = document.getElementById('createResult');
      result.innerHTML = '<p>Creating license...</p>';
      
      try {
        const response = await fetch('/admin/create-license', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-app-secret': SECRET
          },
          body: JSON.stringify({
            email,
            productType,
            durationDays,
            notes: notes || null
          })
        });
        
        const data = await response.json();
        
        if (data.error) {
          result.innerHTML = '<p class="error">Error: ' + data.error + '</p>';
        } else {
          result.innerHTML = '<div class="license">' +
            '<p class="success">License created successfully!</p>' +
            '<strong>Email:</strong> ' + data.license.email + '<br>' +
            '<strong>Product:</strong> ' + data.license.productType + '<br>' +
            '<strong>License Key:</strong><br>' +
            '<span class="key">' + data.license.licenseKey + '</span><br>' +
            '<button class="copy-btn" onclick="copyToClipboard(\\'' + data.license.licenseKey + '\\')">Copy Key</button><br>' +
            '<strong>Expires:</strong> ' + new Date(data.license.expiry).toLocaleDateString() + '<br>' +
            '</div>';
        }
      } catch (err) {
        result.innerHTML = '<p class="error">Error: ' + err.message + '</p>';
      }
    }
    
    async function lookupEmail() {
      const email = document.getElementById('emailInput').value;
      if (!email) {
        alert('Please enter an email');
        return;
      }
      
      const result = document.getElementById('lookupResult');
      result.innerHTML = '<p>Loading...</p>';
      
      try {
        const response = await fetch('/admin/lookup-email', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-app-secret': SECRET
          },
          body: JSON.stringify({ email })
        });
        
        const data = await response.json();
        
        if (data.error) {
          result.innerHTML = '<p class="error">' + data.error + '</p>';
        } else {
          result.innerHTML = '<div class="license">' +
            '<strong>Email:</strong> ' + data.email + '<br>' +
            '<strong>Product:</strong> ' + data.productType + '<br>' +
            '<strong>License Key:</strong><br>' +
            '<span class="key">' + data.licenseKey + '</span><br>' +
            '<button class="copy-btn" onclick="copyToClipboard(\\'' + data.licenseKey + '\\')">Copy Key</button><br>' +
            '<strong>Created:</strong> ' + new Date(data.createdAt).toLocaleString() + '<br>' +
            '<strong>Expires:</strong> ' + new Date(data.expiry).toLocaleDateString() + '<br>' +
            '<strong>Activated:</strong> ' + (data.activated ? 'Yes' : 'No') +
            '</div>';
        }
      } catch (err) {
        result.innerHTML = '<p class="error">Error: ' + err.message + '</p>';
      }
    }
    
    async function showPending() {
      const result = document.getElementById('pendingResult');
      result.innerHTML = '<p>Loading...</p>';
      
      try {
        const response = await fetch('/admin/pending-licenses', {
          headers: { 'x-app-secret': SECRET }
        });
        
        const data = await response.json();
        
        if (data.licenses.length === 0) {
          result.innerHTML = '<p>No pending licenses</p>';
        } else {
          let html = '<p class="success">Found ' + data.licenses.length + ' pending licenses:</p>';
          data.licenses.forEach(lic => {
            html += '<div class="license">' +
              '<strong>Email:</strong> ' + lic.email + '<br>' +
              '<strong>Product:</strong> ' + lic.productType + '<br>' +
              '<span class="key">' + lic.licenseKey + '</span><br>' +
              '<button class="copy-btn" onclick="copyToClipboard(\\'' + lic.licenseKey + '\\')">Copy Key</button><br>' +
              '<strong>Created:</strong> ' + new Date(lic.createdAt).toLocaleString() +
              '</div>';
          });
          result.innerHTML = html;
        }
      } catch (err) {
        result.innerHTML = '<p class="error">Error: ' + err.message + '</p>';
      }
    }
    
    async function showRecent() {
      const result = document.getElementById('recentResult');
      result.innerHTML = '<p>Loading...</p>';
      
      try {
        const response = await fetch('/admin/recent-licenses', {
          headers: { 'x-app-secret': SECRET }
        });
        
        const data = await response.json();
        
        if (data.licenses.length === 0) {
          result.innerHTML = '<p>No licenses created in last 24 hours</p>';
        } else {
          let html = '<p class="success">Found ' + data.licenses.length + ' licenses:</p>';
          data.licenses.forEach(lic => {
            html += '<div class="license">' +
              '<strong>Email:</strong> ' + lic.email + '<br>' +
              '<strong>Product:</strong> ' + lic.productType + '<br>' +
              '<strong>Created:</strong> ' + new Date(lic.createdAt).toLocaleString() + '<br>' +
              '<strong>Activated:</strong> ' + (lic.activated ? 'Yes' : 'No') +
              '</div>';
          });
          result.innerHTML = html;
        }
      } catch (err) {
        result.innerHTML = '<p class="error">Error: ' + err.message + '</p>';
      }
    }
  </script>
</body>
</html>
  `);
});

// Admin API endpoints
app.post('/admin/lookup-email', async (req, res) => {
  if (!sharedSecret || req.get('x-app-secret') !== sharedSecret) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  
  const { email } = req.body;
  
  const snapshot = await db.collection('licenses')
    .where('email', '==', email)
    .orderBy('createdAt', 'desc')
    .limit(1)
    .get();
  
  if (snapshot.empty) {
    return res.json({ error: 'No license found for this email' });
  }
  
  const data = snapshot.docs[0].data();
  res.json(data);
});

app.get('/admin/pending-licenses', async (req, res) => {
  if (!sharedSecret || req.get('x-app-secret') !== sharedSecret) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  
  const snapshot = await db.collection('licenses')
    .where('activated', '==', false)
    .orderBy('createdAt', 'desc')
    .limit(20)
    .get();
  
  const licenses = [];
  snapshot.forEach(doc => licenses.push(doc.data()));
  
  res.json({ licenses });
});

app.get('/admin/recent-licenses', async (req, res) => {
  if (!sharedSecret || req.get('x-app-secret') !== sharedSecret) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  
  const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
  
  const snapshot = await db.collection('licenses')
    .where('createdAt', '>', oneDayAgo)
    .orderBy('createdAt', 'desc')
    .get();
  
  const licenses = [];
  snapshot.forEach(doc => licenses.push(doc.data()));
  
  res.json({ licenses });
});

// SEARCH LICENSE BY ID - for revocation
app.post('/admin/search-license', async (req, res) => {
  if (!sharedSecret || req.get('x-app-secret') !== sharedSecret) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  
  const { searchTerm } = req.body;
  
  if (!searchTerm) {
    return res.status(400).json({ error: 'Search term is required' });
  }
  
  try {
    // Search by license ID (first part of license key)
    const snapshot = await db.collection('licenses')
      .where('email', '==', searchTerm)
      .limit(10)
      .get();
    
    if (snapshot.empty) {
      return res.json({ licenses: [] });
    }
    
    const licenses = [];
    snapshot.forEach(doc => {
      const data = doc.data();
      licenses.push({
        id: doc.id,
        ...data
      });
    });
    
    res.json({ licenses });
    
  } catch (error) {
    console.error('Failed to search licenses:', error);
    res.status(500).json({ error: 'Failed to search licenses' });
  }
});

// DEBUG ENDPOINTS - Remove these after fixing the issue
app.get('/debug', (req, res) => {
  const debugInfo = {
    hasSharedSecret: !!process.env.SHARED_SECRET,
    sharedSecretLength: process.env.SHARED_SECRET ? process.env.SHARED_SECRET.length : 0,
    sharedSecretPreview: process.env.SHARED_SECRET ? 
      process.env.SHARED_SECRET.substring(0, 8) + '...' : 'NOT SET',
    nodeEnv: process.env.NODE_ENV,
    timestamp: new Date().toISOString()
  };
  
  res.json(debugInfo);
});

app.post('/test-auth', (req, res) => {
  const providedKey = req.get('x-app-secret');
  const expectedKey = process.env.SHARED_SECRET;
  
  const result = {
    providedKey: providedKey ? providedKey.substring(0, 8) + '...' : 'NOT PROVIDED',
    expectedKey: expectedKey ? expectedKey.substring(0, 8) + '...' : 'NOT SET',
    keysMatch: providedKey === expectedKey,
    providedLength: providedKey ? providedKey.length : 0,
    expectedLength: expectedKey ? expectedKey.length : 0,
    timestamp: new Date().toISOString()
  };
  
  res.json(result);
});

// Favicon route to prevent 404 errors
app.get('/favicon.ico', (req, res) => {
  res.status(204).end(); // No content
});

app.get('/', (req, res) => res.send('CONFIRM License Server Running'));

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`License server on ${port}`));
/*
 * Quick diagnostic script to check license status in Firebase
 */

import 'dotenv/config';
import admin from "firebase-admin";

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
  credential: admin.credential.cert(serviceAccount),
  databaseURL: "https://confirm-license-manager-default-rtdb.firebaseio.com"
});

const db = admin.database();

// License ID from the logs (594918d13839cd11)
const licenseId = process.argv[2] || '594918d13839cd11';

console.log(`\n=== CHECKING LICENSE: ${licenseId} ===\n`);

try {
  const snapshot = await db.ref(`license/${licenseId}`).once('value');
  const data = snapshot.val();
  
  if (!data) {
    console.log('❌ LICENSE NOT FOUND IN FIREBASE');
    console.log('\nThis means the license was never created or was deleted.');
    console.log('You need to create this license in the admin panel.\n');
  } else {
    console.log('✓ License found in Firebase:\n');
    console.log('License Key:', data.license_key || 'N/A');
    console.log('Status:', data.status || 'unknown');
    console.log('Revoked:', data.revoked || false);
    console.log('Expires:', data.expires || 'N/A');
    console.log('');
    console.log('=== MACHINE BINDING ===');
    console.log('Bound Computer ID:', data.computer_id || 'NOT BOUND');
    console.log('Bound At:', data.bound_at || 'N/A');
    console.log('Binding Method:', data.binding_method || 'N/A');
    console.log('');
    console.log('=== FULL DATA ===');
    console.log(JSON.stringify(data, null, 2));
    
    // Diagnosis
    console.log('\n=== DIAGNOSIS ===');
    if (data.revoked) {
      console.log('⚠️  PROBLEM: License is REVOKED');
      console.log('   FIX: Unrevoke the license in admin panel');
    }
    
    const expiryDate = new Date(data.expires);
    if (expiryDate < new Date()) {
      console.log('⚠️  PROBLEM: License is EXPIRED');
      console.log('   FIX: Extend the license in admin panel');
    }
    
    if (data.computer_id) {
      console.log('⚠️  License is bound to machine:', data.computer_id);
      console.log('   If client machine ID is different, this causes 403!');
      console.log('   FIX: Unbind machine in admin panel, or verify client machine ID matches');
    }
    
    if (!data.computer_id && !data.revoked && expiryDate >= new Date()) {
      console.log('✓ License appears valid and unbound - should work!');
    }
  }
} catch (error) {
  console.error('Error checking license:', error.message);
}

process.exit(0);

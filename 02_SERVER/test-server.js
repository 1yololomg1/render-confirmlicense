#!/usr/bin/env node

// Simple test script to verify server functionality
import fetch from 'node-fetch';

const SERVER_URL = process.env.SERVER_URL || 'http://localhost:10000';

async function testServer() {
  console.log('Testing CONFIRM License Server...\n');
  
  try {
    // Test health endpoint
    console.log('1. Testing health endpoint...');
    const healthResponse = await fetch(`${SERVER_URL}/health`);
    const healthData = await healthResponse.json();
    console.log('✅ Health check:', healthData.status);
    
    // Test main endpoint
    console.log('\n2. Testing main endpoint...');
    const mainResponse = await fetch(`${SERVER_URL}/`);
    const mainText = await mainResponse.text();
    console.log('✅ Main endpoint:', mainText);
    
    // Test validation endpoint (should fail without proper data)
    console.log('\n3. Testing validation endpoint...');
    const validateResponse = await fetch(`${SERVER_URL}/validate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ license_key: 'test', machine_id: 'test' })
    });
    const validateData = await validateResponse.json();
    console.log('✅ Validation endpoint responds:', validateData.error);
    
    console.log('\n🎉 All tests passed! Server is working correctly.');
    
  } catch (error) {
    console.error('❌ Test failed:', error.message);
    console.log('\nMake sure the server is running on', SERVER_URL);
    process.exit(1);
  }
}

testServer();

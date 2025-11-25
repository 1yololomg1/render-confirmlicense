# RENDER DEPLOYMENT - EXACT ENVIRONMENT VARIABLES TO SET

## The Problem
Error 254 occurs because Render is missing the required Firebase environment variables. The server validates these on startup and exits with code 1 (which becomes Error 254) if any are missing.

## SOLUTION: Set These Exact Environment Variables in Render Dashboard

### Required Firebase Service Account Variables:
```
type=service_account
project_id=confirm-license-manager
private_key_id=<PRIVATE_KEY_ID_PLACEHOLDER>
private_key="-----BEGIN PRIVATE KEY-----
<REDACTED_PRIVATE_KEY>
-----END PRIVATE KEY-----\n"
client_email=firebase-adminsdk-fbsvc@confirm-license-manager.iam.gserviceaccount.com
client_id=<CLIENT_ID_PLACEHOLDER>
auth_uri=https://accounts.google.com/o/oauth2/auth
token_uri=https://oauth2.googleapis.com/token
auth_provider_x509_cert_url=https://www.googleapis.com/oauth2/v1/certs
client_x509_cert_url=https://www.googleapis.com/robot/v1/metadata/x509/firebase-adminsdk-fbsvc%40confirm-license-manager.iam.gserviceaccount.com
universe_domain=googleapis.com
```

### Required Application Secrets:
```
SHARED_SECRET=<SET_IN_RENDER_DASHBOARD>
LICENSE_SECRET=<SET_IN_RENDER_DASHBOARD>
```

### Optional Services (can be left empty):
```
STRIPE_SECRET_KEY=your_stripe_secret_key_here
SENDGRID_API_KEY=your_sendgrid_api_key_here
```

### Server Configuration:
```
NODE_ENV=production
PORT=10000
```

## How to Set Environment Variables in Render:

1. Go to your Render dashboard
2. Click on your service
3. Go to "Environment" tab
4. Add each variable above as a separate environment variable
5. Click "Save Changes"
6. Redeploy your service

## Verification:

After setting all environment variables, your service should:
- Start successfully (no more Error 254)
- Show "Firebase Realtime Database initialized successfully" in logs
- Respond to health checks at `/health`
- Process license validations at `/validate`

## Important Notes:

- **private_key** must include the quotes and newlines exactly as shown
- All Firebase variables are REQUIRED - the server will crash if any are missing
- The server validates environment variables on startup and exits with code 1 if missing
- This is the exact cause of Error 254 - missing environment variables

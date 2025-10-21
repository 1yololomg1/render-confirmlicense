# CONFIRM License Server - Render Deployment Guide

## Quick Fix for Error 254

The server has been completely rewritten with proper error handling and environment variable validation. This should resolve the Render crashes.

## Required Environment Variables

Set these in your Render dashboard under Environment Variables:

### Firebase Service Account (Required)
```
type=service_account
project_id=your-project-id
private_key_id=your-private-key-id
private_key="-----BEGIN PRIVATE KEY-----\nYOUR_PRIVATE_KEY_HERE\n-----END PRIVATE KEY-----\n"
client_email=your-service-account@your-project.iam.gserviceaccount.com
client_id=your-client-id
auth_uri=https://accounts.google.com/o/oauth2/auth
token_uri=https://oauth2.googleapis.com/token
auth_provider_x509_cert_url=https://www.googleapis.com/oauth2/v1/certs
client_x509_cert_url=https://www.googleapis.com/robot/v1/metadata/x509/your-service-account%40your-project.iam.gserviceaccount.com
universe_domain=googleapis.com
```

### Application Secrets (Required)
```
SHARED_SECRET=your-super-secret-admin-key-here
LICENSE_SECRET=your-license-encryption-secret-here
```

### Optional Services
```
STRIPE_SECRET_KEY=sk_test_your_stripe_secret_key
SENDGRID_API_KEY=SG.your_sendgrid_api_key
```

## Deployment Steps

1. **Push to GitHub**: Make sure your code is pushed to GitHub
2. **Connect to Render**: Link your GitHub repository to Render
3. **Set Environment Variables**: Add all required environment variables in Render dashboard
4. **Deploy**: Render will automatically deploy using the `render.yaml` configuration

## Key Improvements Made

1. **Environment Variable Validation**: Server now validates all required environment variables on startup
2. **Graceful Error Handling**: Proper error handling prevents crashes
3. **Health Check Endpoint**: `/health` endpoint for monitoring
4. **Graceful Shutdown**: Proper SIGTERM/SIGINT handling
5. **Comprehensive Logging**: Better error logging for debugging

## Testing the Deployment

1. **Health Check**: Visit `https://your-app.onrender.com/health`
2. **Main Endpoint**: Visit `https://your-app.onrender.com/`
3. **License Validation**: Test with your Python client

## Troubleshooting

- **Error 254**: Usually means missing environment variables or syntax errors (now fixed)
- **Firebase Connection Issues**: Check that all Firebase environment variables are set correctly
- **Memory Issues**: The free tier has limited memory; consider upgrading if needed

## Admin Interface

Access the admin interface at: `https://your-app.onrender.com/admin`
Use the `x-app-secret` header with your `SHARED_SECRET` value.

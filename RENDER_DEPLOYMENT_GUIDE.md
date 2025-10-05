# Render Deployment Guide for CONFIRM License System

This guide will help you deploy your entire Cursor workspace to Render using the API key: `rnd_2hdonGoimhH6CUxHasW1WcoCHU3Z`

## 🚀 Quick Deployment Steps

### 1. Connect Repository to Render

1. Go to [Render Dashboard](https://dashboard.render.com)
2. Click "New" → "Web Service"
3. Connect your GitHub repository: `1yololomg1/render-confirmlicense`
4. Use the provided API key: `rnd_2hdonGoimhH6CUxHasW1WcoCHU3Z`

### 2. Configure Service Settings

**Basic Configuration:**
- **Name**: `render-confirmlicense`
- **Environment**: `Node`
- **Build Command**: `npm install`
- **Start Command**: `node server.mjs`
- **Plan**: Free (or upgrade as needed)

### 3. Set Environment Variables

You'll need to configure these environment variables in the Render dashboard:

#### Required Secrets (Set in Render Dashboard):
```
SHARED_SECRET=your_admin_secret_here
LICENSE_SECRET=your_license_secret_here
STRIPE_SECRET_KEY=sk_test_...
STRIPE_WEBHOOK_SECRET=whsec_...
SENDGRID_API_KEY=SG...
```

#### Firebase Configuration:
```
project_id=your-firebase-project-id
private_key_id=your-private-key-id
private_key="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n"
client_email=firebase-adminsdk-...@your-project.iam.gserviceaccount.com
client_id=your-client-id
client_x509_cert_url=https://www.googleapis.com/robot/v1/metadata/x509/...
```

#### Stripe Price IDs:
```
STRIPE_PRICE_ID_STUDENT_YEAR=price_...
STRIPE_PRICE_ID_STARTUP_MONTH=price_...
STRIPE_PRICE_ID_PRO_MONTH=price_...
STRIPE_PRICE_ID_PRO_YEAR=price_...
STRIPE_PRICE_ID_ENTERPRISE_MONTH=price_...
STRIPE_PRICE_ID_ENTERPRISE_YEAR=price_...
STRIPE_PRICE_ID_INTEGRATION=price_...
STRIPE_PRICE_ID_WHITELABEL=price_...
```

### 4. Deploy

1. Click "Create Web Service"
2. Render will automatically build and deploy your application
3. Your service will be available at: `https://render-confirmlicense.onrender.com`

## 🔧 Post-Deployment Configuration

### Update Client Applications

After deployment, update your client applications to use the new Render URL:

1. **Python GUI** (`license_manager_gui.py`):
   ```python
   self.api_base_url = 'https://render-confirmlicense.onrender.com'
   ```

2. **CONFIRM Application** (`CONFIRM_Integrated.py`):
   ```python
   LICENSE_SERVER_URL = "https://render-confirmlicense.onrender.com"
   ```

### Test Your Deployment

1. **Health Check**: Visit `https://render-confirmlicense.onrender.com`
2. **Admin Panel**: Visit `https://render-confirmlicense.onrender.com/admin`
3. **API Endpoints**: Test the license validation endpoints

## 📋 Environment Variables Checklist

Before deploying, ensure you have all these values ready:

- [ ] SHARED_SECRET (admin authentication)
- [ ] LICENSE_SECRET (license signing)
- [ ] STRIPE_SECRET_KEY
- [ ] STRIPE_WEBHOOK_SECRET
- [ ] SENDGRID_API_KEY
- [ ] Firebase service account JSON (all fields)
- [ ] All Stripe Price IDs

## 🔄 Auto-Deployment

Once configured, Render will automatically redeploy when you push changes to your GitHub repository's main branch.

## 🆘 Troubleshooting

### Common Issues:

1. **Build Failures**: Check that all dependencies are in `package.json`
2. **Environment Variables**: Ensure all required variables are set
3. **Firebase Connection**: Verify Firebase credentials are correct
4. **Stripe Webhooks**: Update webhook URL to point to your Render service

### Useful Commands:

```bash
# Check deployment logs
# Available in Render dashboard under "Logs"

# Test API endpoints
curl https://render-confirmlicense.onrender.com/
curl -H "x-app-secret: YOUR_SECRET" https://render-confirmlicense.onrender.com/admin
```

## 📞 Support

If you encounter issues:
1. Check Render deployment logs
2. Verify all environment variables are set
3. Test API endpoints individually
4. Contact Render support if needed

---

**Your Render API Key**: `rnd_2hdonGoimhH6CUxHasW1WcoCHU3Z`
**Repository**: `1yololomg1/render-confirmlicense`
**Deployment URL**: `https://render-confirmlicense.onrender.com`
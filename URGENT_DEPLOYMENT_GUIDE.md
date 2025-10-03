# 🚨 URGENT: Deploy License Server NOW

## Your license server is ready - deploy it immediately!

### **STEP 1: Deploy to Render.com (5 minutes)**

1. **Go to Render.com** → https://render.com
2. **Sign up/Login** → Connect your GitHub account
3. **New Web Service** → Connect your repository
4. **Configure Service:**
   - **Name**: `render-confirmlicense`
   - **Runtime**: `Node`
   - **Build Command**: `npm install`
   - **Start Command**: `node server.mjs`
   - **Environment**: `Node`

### **STEP 2: Set Environment Variables (CRITICAL)**

In Render dashboard, add these environment variables:

```bash
# Firebase Configuration (REQUIRED)
type=service_account
project_id=your-firebase-project-id
private_key_id=your-private-key-id
private_key="-----BEGIN PRIVATE KEY-----\nYOUR_PRIVATE_KEY\n-----END PRIVATE KEY-----"
client_email=your-service-account@your-project.iam.gserviceaccount.com
client_id=your-client-id
auth_uri=https://accounts.google.com/o/oauth2/auth
token_uri=https://oauth2.googleapis.com/token
auth_provider_x509_cert_url=https://www.googleapis.com/oauth2/v1/certs
client_x509_cert_url=https://www.googleapis.com/robot/v1/metadata/x509/your-service-account%40your-project.iam.gserviceaccount.com
universe_domain=googleapis.com

# Admin Security
ADMIN_SECRET_KEY=your-secure-admin-key-here
LICENSE_SECRET=your-secure-license-secret-here

# Stripe Configuration (for payments)
STRIPE_SECRET_KEY=sk_test_your_stripe_secret_key
STRIPE_PRICE_ID_STUDENT_YEAR=price_your_student_price_id
STRIPE_PRICE_ID_STARTUP_MONTH=price_your_startup_price_id
STRIPE_PRICE_ID_PROFESSIONAL_MONTH=price_your_professional_price_id
STRIPE_PRICE_ID_PROFESSIONAL_YEAR=price_your_professional_yearly_price_id
STRIPE_PRICE_ID_ENTERPRISE_MONTH=price_your_enterprise_price_id
STRIPE_PRICE_ID_ENTERPRISE_YEAR=price_your_enterprise_yearly_price_id

# Email Configuration
SENDGRID_API_KEY=SG.your_sendgrid_api_key
```

### **STEP 3: Quick Firebase Setup (10 minutes)**

1. **Go to Firebase Console** → https://console.firebase.google.com
2. **Create New Project** → Name it `confirm-license-system`
3. **Enable Firestore Database** → Create database in test mode
4. **Generate Service Account**:
   - Go to Project Settings → Service Accounts
   - Generate new private key
   - Download JSON file
   - Use values from JSON in Render environment variables

### **STEP 4: Test Deployment (2 minutes)**

Once deployed, test these URLs:

```bash
# Test server is running
curl https://render-confirmlicense.onrender.com

# Test admin endpoint
curl https://render-confirmlicense.onrender.com/admin
```

### **STEP 5: Update Your GUI Configuration**

Update `license_manager_gui.py` line 27:
```python
self.api_base_url = "https://render-confirmlicense.onrender.com"
```

### **STEP 6: Test License Creation**

1. **Run Admin GUI**: `python license_manager_gui.py`
2. **Enter Admin Key**: Use the key you set in Render
3. **Create Test License**: Use the Create License tab
4. **Test with CONFIRM**: Run `python CONFIRM_Integrated.py`

## 🚨 **CRITICAL: If You Don't Have Firebase/Stripe Setup**

### **Quick Mock Server (Emergency Option)**

If you need it working in 2 minutes, I can create a mock server:

```bash
# Create simple test server
echo '{"status": "ok", "message": "License server running"}' > test_server.json
python -m http.server 3000
```

But this won't persist licenses - you need the real server for production!

## 📞 **Need Help Right Now?**

1. **Firebase Setup**: 5 minutes - just create project and get service account
2. **Render Deployment**: 3 minutes - upload code and set variables
3. **Testing**: 2 minutes - verify endpoints work

**Total time: 10 minutes to working license system**

Your server code is perfect - just needs deployment!

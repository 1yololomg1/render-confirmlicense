# CONFIRM License Management Server

**Copyright (c) 2024 TraceSeis, Inc. All rights reserved.**

This software and associated documentation files (the "Software") are proprietary and confidential to TraceSeis, Inc. and its affiliates. The Software is protected by copyright laws and international copyright treaties, as well as other intellectual property laws and treaties.

**Contact Information:**
- Email: info@traceseis.com or alvarochf@traceseis.com
- Created by: Alvaro Chaveste (deltaV solutions)

Unauthorized copying, distribution, or modification of this Software is strictly prohibited and may result in severe civil and criminal penalties.

---

A Node.js server for managing CONFIRM software licenses with Stripe payment integration and Firebase database.

## Deployment on Render

This server is configured for deployment on Render.com with the following setup:

### Required Environment Variables

Set these in your Render dashboard:

- `SHARED_SECRET` - Admin authentication secret
- `LICENSE_SECRET` - License key signing secret
- `STRIPE_SECRET_KEY` - Stripe API secret key
- `STRIPE_WEBHOOK_SECRET` - Stripe webhook endpoint secret
- `SENDGRID_API_KEY` - SendGrid email API key
- `STRIPE_PRICE_ID_*` - Stripe price IDs for different license tiers

### Firebase Configuration

Set these Firebase service account environment variables:
- `type`, `project_id`, `private_key_id`, `private_key`
- `client_email`, `client_id`, `auth_uri`, `token_uri`
- `auth_provider_x509_cert_url`, `client_x509_cert_url`, `universe_domain`

### Build Configuration

- **Build Command**: `npm install`
- **Start Command**: `npm start`
- **Node Version**: 18+ (automatically detected)

The server will be available at your Render URL with admin panel at `/admin`.


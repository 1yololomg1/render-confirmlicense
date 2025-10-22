# RENDER DEPLOYMENT - EXACT ENVIRONMENT VARIABLES TO SET

## The Problem
Error 254 occurs because Render is missing the required Firebase environment variables. The server validates these on startup and exits with code 1 (which becomes Error 254) if any are missing.

## SOLUTION: Set These Exact Environment Variables in Render Dashboard

### Required Firebase Service Account Variables:
```
type=service_account
project_id=confirm-license-manager
private_key_id=4123bb420e9e270aad04e60a4286f870b19e5bda
private_key="-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDJph5Pu26/PeZt\nGS7JMAAuzYgSBD3iEm4OUEWKWutk2MWp8+Q7zjaELdoRPtn4gM+ANwAWfnkiEXJF\nqaaeOzsCWGw2CcgbzFY2JhT8WSXvOErIfifW9Ty2ExewR04ybudxbEapFSiQBTfk\n0qDs+8OZgNLWXi3NBubNuH+/AZc2o8ipP6F5/LsAYCWBKqlEFuygV8REVIyGULCW\nARVnUYiNmMv72uwEqsBkEWEUQVJyPZUJZKVjCRxCCZz6uKJIsxXfKLuSZbsnI2D8\nqRU6UbhWgsWaZd0GcXbiULq5KcoRcKJoBc35BAXZ1ALZRzb5fgkN8ALqviFQnqnE\n+ik1UNMHAgMBAAECggEAASDk92YhkNWOameN6F//KVT1dnydqC0h5QJphxV1Pdp5\nHLdozXoUZOQ+RCUKiOiGTY7jX4mnUyiEb9TmqE9N8t7HNh7f9ciqdz9yC3ywokqX\nlzcNQlvwyawzWPiR/LHND/u8kzsRDJ0E/wZ3rAVzNb+tlMjwnDYpYE59UmWQDILs\nLb4qZFS8cE089ACKbWgN/uQKdrKPufqltP9de6M6+WVam9cauO9tbmLY7+C6DbsN\nIXT2e6cAaFtEjbctp1/rdffgRy1UIVm7MJUoCG1hy0vaq1RLJPIxV4UmRP60gn3Y\nzgVrJ5IaB1krLID0sF7F28A/ahEntFiWkQ9PksJRqQKBgQD/EJsKt4me2okBMb3m\nqQC4K76mN8uEsHmrZPw4e7bKJInWHwbJBhaXU2IwqNnphdxdx8dznA3u3LV3djEJ\nJSbc+r8h/604g8jwpJAptF24Khv7ycwXvj2AjE2XJLaAM68PGwe/cWEsdtST6Dxs\nrNL1BWE6z0IgLt/JlBkB8Pc8+QKBgQDKY2Dn8DflGLAV+S4/AGC5w2wg9ChpbsnE\npHx3Pooxcb2MTp2IhkevF+N5zq8AdrfdEfIcteoUyTSFP0o4OHuP3s2FG69uaTDh\nVtrzZhFZEO/OCaEYPt7cu+bas6sT+8zQyvasy5TL80w4YL8iELzJioT8y6Ha/1b7\nhMs2ntyP/wKBgQCCYB+P887xluzu4lkaPQq0GRAjcGOkGHyooj7WNE5ztweJnmRe\nfrEvepy3GKgCWL0SZprJulvY25IaVRytewMJc1Ydb85AFASzFLrnxl0dVNDm+/hJ\nrqFLQuwqNMbgcwqpYvyr2617B+aTD+NK/W/7dFuFrwky4CLdq8i4mE4YKQKBgB+e\nnSI/fowValVUg+wl4/bB2F/hpXqra2yEgkmjBLYq3gFQuv38dLCfW9PI/cBly94H\nErt3lGXA9aqns7HK6UsV9SgJpkPqvU9HYZfLZ4Rxx/V5vahrEiiMVsnubhkGKv6n\n5xgiClI+5badLt9knAok0RgpvFTZtb5ABfu3oCADAoGARdkdZKACCSxhS5mSY4Q5\nwskGJ6eWVrwi12KCndrOG93N7Je3zCX6s1nWpfvR/nJ7cd+SzQcj7o5Wt6+ve5bh\nuHrTuxVQEooWh9URemt6f47Ripdyi6BQlhjtQDbv/ftfEIV7zPXs2I+6DuLU694D\nmtnaob8NzKh0ATCOkSvIbrc=\n-----END PRIVATE KEY-----\n"
client_email=firebase-adminsdk-fbsvc@confirm-license-manager.iam.gserviceaccount.com
client_id=117839336252058777646
auth_uri=https://accounts.google.com/o/oauth2/auth
token_uri=https://oauth2.googleapis.com/token
auth_provider_x509_cert_url=https://www.googleapis.com/oauth2/v1/certs
client_x509_cert_url=https://www.googleapis.com/robot/v1/metadata/x509/firebase-adminsdk-fbsvc%40confirm-license-manager.iam.gserviceaccount.com
universe_domain=googleapis.com
```

### Required Application Secrets:
```
SHARED_SECRET=confirm-admin-secret-2024
LICENSE_SECRET=tynaeKXDf7B6GkuPxffFSeu^NJEy1byV
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

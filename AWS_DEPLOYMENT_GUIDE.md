# AWS Elastic Beanstalk Deployment Guide

## Prerequisites

- AWS CLI installed and configured
- EB CLI installed (`pip install awsebcli`)
- AWS account with appropriate permissions

## Files Created for Deployment

### ✅ Procfile

```
web: gunicorn app:app
```

### ✅ runtime.txt

```
python-3.11.5
```

### ✅ requirements.txt

Updated with all necessary dependencies including PyJWT.

### ✅ .ebextensions/01_flask.config

Configuration for Flask app setup and database initialization.

## Deployment Steps

### 1. Initialize EB Application

```bash
eb init
```

- Choose your region
- Select "Create new application"
- Name your application (e.g., "ticketing-system")
- Choose Python as platform
- Choose Python 3.11 running on 64bit Amazon Linux 2023
- Do not set up SSH for now

### 2. Create Environment

```bash
eb create production
```

This will create a production environment and deploy your app.

### 3. Set Environment Variables

After deployment, set your environment variables:

```bash
# Required Environment Variables
eb setenv SECRET_KEY="your-super-secure-secret-key-here"
eb setenv CLERK_PUBLISHABLE_KEY="pk_test_..."
eb setenv CLERK_SECRET_KEY="sk_test_..."
eb setenv RESEND_API_KEY="re_..."
eb setenv GMAIL_APP_PASSWORD="your-gmail-app-password"

# Firebase Configuration (if using Firebase)
eb setenv FIREBASE_API_KEY="your-firebase-api-key"
eb setenv FIREBASE_AUTH_DOMAIN="your-project.firebaseapp.com"
eb setenv FIREBASE_PROJECT_ID="your-project-id"
eb setenv FIREBASE_STORAGE_BUCKET="your-project.appspot.com"
eb setenv FIREBASE_MESSAGING_SENDER_ID="123456789"
eb setenv FIREBASE_APP_ID="1:123456789:web:abc123"

# Firebase Admin SDK (if using Firebase)
eb setenv FIREBASE_PRIVATE_KEY_ID="your-private-key-id"
eb setenv FIREBASE_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n"
eb setenv FIREBASE_CLIENT_EMAIL="firebase-adminsdk-...@your-project.iam.gserviceaccount.com"
eb setenv FIREBASE_CLIENT_ID="123456789"
eb setenv FIREBASE_CLIENT_CERT_URL="https://www.googleapis.com/robot/v1/metadata/x509/firebase-adminsdk-...%40your-project.iam.gserviceaccount.com"
```

### 4. Deploy Updates

When you make changes to your code:

```bash
eb deploy
```

### 5. View Application

```bash
eb open
```

## Important Notes

### Database

- The app uses SQLite by default
- Database will be initialized automatically on first deployment
- For production, consider migrating to RDS (PostgreSQL/MySQL)

### File Uploads

- Uploaded files are stored in `static/uploads/`
- For production, consider using S3 for file storage

### Security

- Make sure to set a strong SECRET_KEY in production
- Keep all API keys and secrets secure
- Never commit sensitive data to version control

### Monitoring

- Use `eb logs` to view application logs
- Use `eb health` to check application health
- Monitor through AWS Console for detailed metrics

## Troubleshooting

### Common Issues

1. **Database not initialized**: Check logs with `eb logs`
2. **Environment variables not set**: Use `eb printenv` to verify
3. **Permission errors**: Ensure IAM roles have proper permissions

### Useful Commands

```bash
# View logs
eb logs

# Check environment status
eb status

# View environment variables
eb printenv

# SSH into instance (if enabled)
eb ssh

# Terminate environment
eb terminate
```

## Production Considerations

### 1. Database Migration

For production, consider using Amazon RDS:

- Update database configuration in app.py
- Use PostgreSQL or MySQL instead of SQLite
- Update requirements.txt with appropriate database drivers

### 2. Static Files

Consider using Amazon S3 + CloudFront for static file serving:

- Upload static files to S3
- Configure CloudFront distribution
- Update templates to use CDN URLs

### 3. Environment Configuration

- Use separate environments for staging/production
- Configure auto-scaling based on traffic
- Set up health checks and monitoring

### 4. SSL Certificate

- Configure SSL certificate through AWS Certificate Manager
- Update security groups for HTTPS traffic
- Redirect HTTP to HTTPS

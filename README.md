# ticketing_system

A comprehensive Flask-based ticketing system for educational institutions with AWS Elastic Beanstalk deployment support.

## Features

- User authentication with Clerk and Firebase integration
- Role-based access control (Admin, Agent, User)
- Ticket management and assignment
- Knowledge base articles
- Service catalog
- Rich text editor for comments
- Email notifications via Resend
- Department-specific workflows

## Quick Start

1. Clone the repository
2. Install dependencies: `pip install -r requirements.txt`
3. Initialize the database: `python init_db.py`
4. Run the application: `python app.py`

## AWS Deployment

This application is ready for AWS Elastic Beanstalk deployment. See `AWS_DEPLOYMENT_GUIDE.md` for detailed instructions.

### Deployment Files

- `Procfile` - Gunicorn configuration
- `runtime.txt` - Python version specification
- `.ebextensions/01_flask.config` - EB configuration
- `requirements.txt` - Python dependencies

## Environment Variables

Set the following environment variables for production:

```bash
SECRET_KEY=your-secure-secret-key
CLERK_PUBLISHABLE_KEY=pk_test_...
CLERK_SECRET_KEY=sk_test_...
RESEND_API_KEY=re_...
GMAIL_APP_PASSWORD=your-gmail-app-password
```

## License

MIT License

# Epic FHIR Backend Authentication Implementation

## Overview
This application implements Epic's OAuth 2.0 backend authentication flow using JSON Web Tokens (JWT) for system-to-system integration with Epic's FHIR API. It retrieves patient data for multiple FHIR resources and exports them as NDJSON files. The application is designed to facilitate secure access to patient data while adhering to Epic's guidelines and best practices.

## Architecture Diagram
![Architecture Diagram](/architecture_diagram.png)

## Features
- OAuth 2.0 client credentials flow with JWT assertion
- RSA key pair management
- Configurable FHIR resource retrieval
- NDJSON file export
- Email notifications via ProtonMail Bridge
- Scheduled execution support

## Prerequisites
- Node.js 14+
- ProtonMail Bridge (for email notifications)
- Epic FHIR API access credentials
- Epic Sandbox test patient access

## Installation
1. Clone the repository:

2. Install dependencies:
```
npm install
```

3. Set up configuration:
```
cp backend_epic_using_jwt.ini.example backend_epic_using_jwt.ini
```

## Configuration
The application uses an INI file (`backend_epic_using_jwt.ini`) for configuration. See the [Configuration Guide](docs/CONFIGURATION.md) for detailed settings.

### Key Settings:
```
[paths]
app_folder_name = C:\FHIR\BackendEpic
epic_data_export_folder = ${app_folder_name}\epic_data_export

[oauth_settings]
client_id = your_client_id
token_endpoint = https://fhir.epic.com/interconnect-fhir-oauth/oauth2/token

[email]
smtp_host = 127.0.0.1
smtp_port = 1025
smtp_secure = false
smtp_user = your_email@domain.com
notification_to = recipient@domain.com
```

### Required Files
1. `epic_sandbox_roster.csv` - List of test patients
2. `epic_sandbox_resources.csv` - FHIR resources to retrieve

## Usage

### Manual Execution
```
node backend_epic_using_jwt.js
```

### Scheduled Execution
Using the built-in scheduler:
```
node scheduler.js
```

Using PM2:
```
pm2 start ecosystem.config.js
```

## Data Flow
1. **Authentication**
   - Generate/verify RSA keys
   - Create JWT token
   - Obtain access token

2. **Data Retrieval**
   - Load patient roster
   - Process each FHIR resource
   - Save data as NDJSON

3. **Notification**
   - Generate summary
   - Send email report

## Error Handling
- JWT generation failures
- API authentication errors
- Resource retrieval errors
- File system errors
- Email notification failures

## Logging
The application provides comprehensive logging:
- Console output for real-time monitoring
- File logging to `backend_epic.log`
- Email notifications for job completion
- Export summaries with file sizes and record counts

## Epic Documentation References
- [Authentication Guide](https://fhir.epic.com/Documentation?docId=oauth2)
- [JWT Requirements](https://fhir.epic.com/Documentation?docId=jwt)
- [Non-Production Access](https://fhir.epic.com/Documentation?docId=testpatients)
- [FHIR API Endpoints](https://fhir.epic.com/Documentation?docId=epiconfhir)

## Dependencies
| Package | Purpose |
|---------|---------|
| axios | HTTP requests to Epic endpoints |
| jsonwebtoken | JWT creation and signing |
| crypto | RSA key pair generation |
| csv-parse | CSV file processing |
| nodemailer | Email notifications |
| node-schedule | Task scheduling |
| ini | Configuration file parsing |
| winston | Logging framework |

## Author
Ajay Prashar

## License
ISC License

## Version
1.0.0

## Support
For support, please contact anyone but the author as I, Ajay Prashar, am still learning.
```


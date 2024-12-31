const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const readline = require('readline');

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

async function setup() {
    console.log('EPIC FHIR Application Setup');
    console.log('==========================');

    // Create .env template
    const envTemplate = `
PROTON_MAIL_USER=your.email@proton.me
PROTON_MAIL_PASS=your_bridge_password

# EPIC Configuration
EPIC_CLIENT_ID=your_epic_client_id
EPIC_TEST_PATIENT_ID=your_test_patient_id
`;

    // Create directories
    const dirs = ['epic_data_export', 'scheduler_logs'];
    dirs.forEach(dir => {
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir);
            console.log(`Created directory: ${dir}`);
        }
    });

    // Create .env if it doesn't exist
    if (!fs.existsSync('.env')) {
        fs.writeFileSync('.env', envTemplate);
        console.log('\nCreated .env template file');
        console.log('Please edit .env with your credentials');
    }

    // Generate new key pair if needed
    if (!fs.existsSync('private.key')) {
        const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: {
                type: 'spki',
                format: 'pem'
            },
            privateKeyEncoding: {
                type: 'pkcs8',
                format: 'pem'
            }
        });

        fs.writeFileSync('private.key', privateKey);
        fs.writeFileSync('public.key', publicKey);
        console.log('\nGenerated new RSA key pair');
    }

    console.log('\nSetup complete! Next steps:');
    console.log('1. Edit .env with your credentials');
    console.log('2. Configure ProtonMail Bridge');
    console.log('3. Run the application: node backend_epic_using_jwt.js');
}

setup(); 
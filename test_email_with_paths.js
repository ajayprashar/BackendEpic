const nodemailer = require('nodemailer');
const path = require('path');
require('dotenv').config();

async function testEmailWithPaths() {
    console.log('Starting email test with paths...');
    
    const exportDir = path.resolve('epic_data_export');
    const logFile = path.resolve('backend_epic.log');
    
    console.log('Using paths:', {
        exportDir,
        logFile
    });

    const transporter = nodemailer.createTransport({
        host: '127.0.0.1',
        port: 1025,
        secure: false,
        auth: {
            user: process.env.PROTON_MAIL_USER,
            pass: process.env.PROTON_MAIL_PASS
        },
        tls: {
            rejectUnauthorized: false,
            ciphers: 'SSLv3'
        }
    });

    try {
        const info = await transporter.sendMail({
            from: process.env.PROTON_MAIL_USER,
            to: "ajay@aprashar.com",
            subject: "EPIC FHIR Test Email with Paths",
            text: `
EPIC FHIR Test Email
===================

Export Directory:
${exportDir}

Log File:
${logFile}

This is a test email showing the full paths that will be used in the sync report.
            `
        });

        console.log("Email sent successfully");
        console.log("Message ID:", info.messageId);
    } catch (error) {
        console.error("Error sending email:", error);
        console.error("Error details:", error.message);
    }
}

testEmailWithPaths(); 
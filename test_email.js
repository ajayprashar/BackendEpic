const nodemailer = require('nodemailer');
require('dotenv').config();

async function testEmail() {
    console.log('Starting email test...');
    console.log('Email credentials:', {
        user: process.env.PROTON_MAIL_USER,
        host: '127.0.0.1',
        port: 1025
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
        },
        debug: true, // Enable debug logging
        logger: true  // Enable built-in logger
    });

    try {
        console.log('Verifying connection...');
        await transporter.verify();
        console.log('Connection verified successfully');

        console.log('Sending test email...');
        const info = await transporter.sendMail({
            from: process.env.PROTON_MAIL_USER,
            to: "ajay@aprashar.com",
            subject: "EPIC FHIR Test Email",
            text: "This is a test email from the EPIC FHIR sync application."
        });

        console.log("Email sent successfully");
        console.log("Message ID:", info.messageId);
        console.log("Full response:", info);
    } catch (error) {
        console.error("Error sending email:", error);
        console.error("Error details:", error.message);
        console.error("Stack trace:", error.stack);
    }
}

testEmail(); 
const schedule = require('node-schedule');
const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const nodemailer = require('nodemailer');
const ini = require('ini');

// Load config file
const configPath = path.join(__dirname, 'backend_epic_using_jwt.ini');
const config = ini.parse(fs.readFileSync(configPath, 'utf-8'));

// Email configuration using ProtonMail Bridge
const transporter = nodemailer.createTransport({
    host: config.email.smtp_host,
    port: config.email.smtp_port,
    secure: false,
    auth: {
        user: process.env.PROTON_MAIL_USER || config.email.smtp_user,
        pass: process.env.PROTON_MAIL_PASS
    },
    tls: {
        rejectUnauthorized: false,
        ciphers: 'SSLv3'
    }
});

// Create logs directory if it doesn't exist
const logsDir = path.join(__dirname, 'scheduler_logs');
if (!fs.existsSync(logsDir)) {
    fs.mkdirSync(logsDir);
}

// Create log file with timestamp
function createLogStream() {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const logPath = path.join(logsDir, `scheduler_${timestamp}.log`);
    return fs.createWriteStream(logPath, { flags: 'a' });
}

async function sendCompletionEmail(exitCode, startTime, endTime) {
    const mailOptions = {
        from: config.email.notification_from,
        to: config.email.notification_to,
        subject: `EPIC FHIR Sync ${exitCode === 0 ? 'Success' : 'Failed'}`,
        text: `
            EPIC FHIR Sync Job Report
            ========================
            Start Time: ${startTime}
            End Time: ${endTime}
            Status: ${exitCode === 0 ? 'Successful' : 'Failed'}
            Exit Code: ${exitCode}
            
            Please check the logs for more details.
        `
    };

    try {
        await transporter.sendMail(mailOptions);
        console.log('Completion email sent via ProtonMail');
    } catch (error) {
        console.error('Error sending email:', error);
    }
}

// Schedule job to run at 2 AM every day
const job = schedule.scheduleJob('0 2 * * *', function() {
    const logStream = createLogStream();
    const startTime = new Date().toISOString();
    
    logStream.write(`\n=== Job Started at ${startTime} ===\n`);
    
    const scriptPath = path.join(__dirname, 'backend_epic_using_jwt.js');
    const process = spawn('node', [scriptPath]);
    
    process.stdout.on('data', (data) => {
        const output = data.toString();
        console.log(output);
        logStream.write(`${output}`);
    });
    
    process.stderr.on('data', (data) => {
        const error = data.toString();
        console.error(error);
        logStream.write(`ERROR: ${error}`);
    });
    
    process.on('close', async (code) => {
        const endTime = new Date().toISOString();
        const message = `\n=== Job Completed at ${endTime} with exit code ${code} ===\n`;
        console.log(message);
        logStream.write(message);
        logStream.end();

        // Send completion email
        await sendCompletionEmail(code, startTime, endTime);
    });
});

// Calculate time until next run
function getTimeUntilNext() {
    const nextInvocation = job.nextInvocation();
    const now = new Date();
    const timeUntil = nextInvocation - now;
    
    const hours = Math.floor(timeUntil / (1000 * 60 * 60));
    const minutes = Math.floor((timeUntil % (1000 * 60 * 60)) / (1000 * 60));
    
    return `${hours} hours and ${minutes} minutes`;
}

console.log(`Scheduler started - EPIC FHIR sync will run daily at 2 AM`);
console.log(`Next run in ${getTimeUntilNext()}`);

// Log any scheduler errors
job.on('error', async (err) => {
    console.error('Scheduler error:', err);
    const logStream = createLogStream();
    logStream.write(`\nScheduler error at ${new Date().toISOString()}: ${err}\n`);
    logStream.end();
    
    // Send error email
    await sendCompletionEmail(1, new Date().toISOString(), new Date().toISOString());
}); 
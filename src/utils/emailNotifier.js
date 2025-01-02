/**
 * Email Notifier Module
 * ===================
 * Handles email notifications for the FHIR data export process.
 */

const nodemailer = require('nodemailer');
const path = require('path');
const observationAnalyzer = require('./observationAnalyzer');

async function sendCompletionEmail(success, startTime, endTime, exportedFiles, config) {
    if (!config.email?.smtp_user || !config.email?.smtp_pass) {
        console.error('Email configuration missing - check smtp_user and smtp_pass in INI file');
        return;
    }

    const transporter = nodemailer.createTransport({
        host: config.email.smtp_host,
        port: parseInt(config.email.smtp_port),
        secure: config.email.smtp_secure === 'true',
        auth: {
            user: config.email.smtp_user,
            pass: config.email.smtp_pass
        },
        tls: {
            rejectUnauthorized: false
        }
    });

    let reportString = '';
    try {
        const exportDir = path.resolve(config.paths.epic_data_export_folder);
        const observationFile = observationAnalyzer.getLatestObservationFile(exportDir);
        const observations = observationAnalyzer.readNDJSON(observationFile);
        const patientStats = observationAnalyzer.analyzeObservations(observations);
        reportString = observationAnalyzer.generateReport(patientStats);

        // Log the report
        console.log('\nObservation Analysis Report');
        console.log('=========================');
        console.log(reportString);
    } catch (error) {
        console.error('Error generating observation analysis report:', error);
        reportString = 'Error generating observation analysis report: ' + error.message;
    }

    const scriptName = path.basename(process.argv[1]);
    const mailOptions = {
        from: config.email.notification_from,
        to: config.email.notification_to,
        subject: `EPIC FHIR Sync ${success ? 'Success' : 'Failed'}`,
        text: `
${scriptName} Report
${'='.repeat(scriptName.length + 7)}
Start Time: ${startTime}
End Time: ${endTime}
Status: ${success ? 'Success' : 'Failed'}

Exported Files:
${exportedFiles.map(file => `- ${file}`).join('\n')}

Observation Analysis Report:
${reportString}
`
    };

    try {
        await transporter.sendMail(mailOptions);
        console.log('Email notification sent successfully');
        return { success: true, reportString };
    } catch (error) {
        console.error('Error sending email notification:', error);
        return { success: false, reportString };
    }
}

module.exports = {
    sendCompletionEmail
}; 
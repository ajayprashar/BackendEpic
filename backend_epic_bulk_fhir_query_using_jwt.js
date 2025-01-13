const fs = require('fs');
const path = require('path');
const { JWTManager } = require('./jwt_manager');
const Logger = require('./src/utils/Logger');
const { loadConfig } = require('./config_loader');
const { FHIRQueryClient } = require('./fhir_query_client');
const { KeyManager } = require('./key_manager');
const axios = require('axios');
const nodemailer = require('nodemailer');

const scriptName = path.basename(__filename);

async function clearExportDirectory(dirPath, logger) {
    try {
        logger.writeLog('INFO', [
            '================================================================================',
            '                        EPIC FHIR BULK DATA EXPORT TUTORIAL                      ',
            '================================================================================',
            '',
            'STEP 1: INITIALIZATION',
            '--------------------',
            'Preparing environment for bulk data export...',
            `• Export Directory: ${dirPath}`,
            '• Action: Clearing previous bulk export files'
        ]);

        if (fs.existsSync(dirPath)) {
            const files = fs.readdirSync(dirPath);
            const bulkFiles = files.filter(file => file.startsWith('bulk_fhir_'));
            
            logger.writeLog('INFO', [
                `• Found ${bulkFiles.length} bulk FHIR files to remove`,
                'Files to be removed:',
                ...bulkFiles.map(file => `• ${file}`),
                ''
            ]);

            for (const file of bulkFiles) {
                const filePath = path.join(dirPath, file);
                await fs.promises.unlink(filePath);
            }
            logger.writeLog('INFO', ['• Successfully cleared all bulk FHIR files']);
        } else {
            await fs.promises.mkdir(dirPath, { recursive: true });
            logger.writeLog('INFO', ['• Created new export directory']);
        }
    } catch (error) {
        throw new Error(`Failed to clear export directory: ${error.message}`);
    }
}

async function monitorExportStatus(statusUrl, accessToken, logger, maxAttempts = 60) {
    logger.writeLog('INFO', [
        'EXPORT STATUS MONITORING',
        '----------------------',
        '• Poll Interval: 10 seconds',
        `• Maximum Attempts: ${maxAttempts}`,
        '• Status URL:',
        `  ${statusUrl}`,
        '',
        'Beginning status checks...',
        ''
    ]);

    let attempt = 1;
    let lastProgress = '';

    while (attempt <= maxAttempts) {
        logger.writeLog('INFO', [
            `Status Check #${attempt}`,
            '----------------',
            'STATUS CHECK REQUEST',
            '------------------',
            '• URL:',
            `  ${statusUrl}`,
            '',
            '• Headers:',
            '  Authorization: Bearer [TOKEN]',
            '  Accept: application/json',
            ''
        ]);

        try {
            const response = await axios.get(statusUrl, {
                headers: {
                    'Authorization': `Bearer ${accessToken}`,
                    'Accept': 'application/json'
                }
            });

            logger.writeLog('INFO', [
                'STATUS CHECK RESPONSE',
                '-------------------',
                '• Status Code:',
                `  ${response.status} ${response.statusText}`,
                '',
                '• Response Headers:',
                ...Object.entries(response.headers).map(([key, value]) => `  ${key}: ${value}`),
                ''
            ]);

            // Check for completion (200 OK)
            if (response.status === 200) {
                logger.writeLog('INFO', [
                    '• Status: COMPLETED',
                    '',
                    'Export completed successfully. Processing output files...',
                    '',
                    'Response Data:',
                    JSON.stringify(response.data, null, 2)
                ]);
                
                // The response should contain an output array with file URLs
                if (response.data && response.data.output) {
                    return response.data.output;
                } else {
                    throw new Error('No output URLs found in completion response');
                }
            }

            // Still processing (202 Accepted)
            const progress = response.headers['x-progress'] || 'No progress information available';
            if (progress !== lastProgress) {
                logger.writeLog('INFO', [
                    '• Current Progress:',
                    `  ${progress}`,
                    ''
                ]);
                lastProgress = progress;
            }

            // Extract numbers from progress header (e.g., "Searched 0 of 7 patients")
            const progressMatch = progress.match(/Searched (\d+) of (\d+) patients/);
            if (progressMatch) {
                const [, current, total] = progressMatch;
                const percentComplete = (parseInt(current) / parseInt(total) * 100).toFixed(1);
                logger.writeLog('INFO', [
                    `• Progress: ${percentComplete}% complete (${current}/${total} patients)`,
                    ''
                ]);
            }

            logger.writeLog('INFO', [
                '• Status: IN PROGRESS',
                '• Waiting 10 seconds before next check...',
                ''
            ]);

            await new Promise(resolve => setTimeout(resolve, 10000));
            attempt++;
        } catch (error) {
            // Check if it's a 429 (Too Many Requests) error
            if (error.response && error.response.status === 429) {
                const retryAfter = parseInt(error.response.headers['retry-after'] || '30');
                logger.writeLog('WARN', [
                    '• Rate limit exceeded. Waiting before retry...',
                    `• Retry-After: ${retryAfter} seconds`,
                    ''
                ]);
                await new Promise(resolve => setTimeout(resolve, retryAfter * 1000));
                continue;
            }

            // Handle other errors
            logger.writeLog('ERROR', [
                'Error checking export status:',
                error.message,
                '',
                'Response details (if available):',
                error.response ? JSON.stringify(error.response.data, null, 2) : 'No response data',
                '',
                'Retrying in 10 seconds...',
                ''
            ]);

            await new Promise(resolve => setTimeout(resolve, 10000));
            attempt++;
        }
    }

    throw new Error(`Export monitoring timed out after ${maxAttempts} attempts`);
}

async function downloadExportFiles(outputFiles, accessToken, exportDir, logger) {
    if (!outputFiles || !Array.isArray(outputFiles)) {
        throw new Error('No valid output files received from export');
    }

    // Log information about batch files for each resource type
    const resourceCounts = {};
    outputFiles.forEach(file => {
        resourceCounts[file.type] = (resourceCounts[file.type] || 0) + 1;
    });

    logger.writeLog('INFO', [
        'DOWNLOADING EXPORT FILES',
        '----------------------',
        `• Total files to download: ${outputFiles.length}`,
        `• Export directory: ${exportDir}`,
        '',
        'Resource Types and Batch Counts:',
        ...Object.entries(resourceCounts).map(([type, count]) => 
            `• ${type}: ${count} batch${count > 1 ? 'es' : ''}`
        ),
        '',
        'Note: When a resource type has multiple batches, this indicates the server',
        'has split the data into chunks for efficient transfer. The split is not',
        'based on patients or clinical criteria - it is purely for data management.',
        '',
        'File Details:',
        ...outputFiles.map((file, i) => `• File ${i + 1}: ${file.type || 'unknown type'}`),
        ''
    ]);

    for (let i = 0; i < outputFiles.length; i++) {
        const file = outputFiles[i];
        // Count how many files of this type we've seen before this one to create unique filenames
        const typeCount = outputFiles.slice(0, i).filter(f => f.type === file.type).length;
        // For multiple batches of the same type, append a batch number to the filename
        const filename = typeCount > 0 
            ? `bulk_fhir_${file.type}_${typeCount + 1}.ndjson` // Batch file (e.g. Observation_2.ndjson)
            : `bulk_fhir_${file.type}.ndjson`;                 // First/only file
        const filepath = path.join(exportDir, filename);

        logger.writeLog('INFO', [
            `Downloading file ${i + 1} of ${outputFiles.length}:`,
            `• Type: ${file.type}`,
            `• Batch: ${typeCount + 1} of ${resourceCounts[file.type]}`,
            `• URL: ${file.url}`,
            `• Saving to: ${filepath}`,
            ''
        ]);

        try {
            const response = await axios({
                method: 'GET',
                url: file.url,
                headers: {
                    'Authorization': `Bearer ${accessToken}`,
                    'Accept': 'application/fhir+ndjson'
                },
                responseType: 'stream',
                maxRedirects: 5,
                timeout: 60000
            });

            // Log response headers for debugging
            logger.writeLog('INFO', [
                'Download Response Headers:',
                ...Object.entries(response.headers).map(([key, value]) => `  ${key}: ${value}`),
                ''
            ]);

            // Create write stream
            const writer = fs.createWriteStream(filepath);
            
            let bytesWritten = 0;
            response.data.on('data', (chunk) => {
                bytesWritten += chunk.length;
                logger.writeLog('INFO', [`• Downloaded ${(bytesWritten / 1024 / 1024).toFixed(2)} MB for ${file.type}`]);
            });

            // Use pipe to handle the streaming data
            await new Promise((resolve, reject) => {
                response.data.pipe(writer);
                response.data.on('end', resolve);
                response.data.on('error', reject);
                writer.on('error', reject);
            });

            // Verify file was created and has content
            const stats = await fs.promises.stat(filepath);
            if (stats.size === 0) {
                // For FHIR bulk exports, empty responses are valid (means no data of this type)
                logger.writeLog('INFO', [
                    `• No data available for ${file.type}`,
                    `• This is normal - it means there are no ${file.type} resources for the requested patients`,
                    ''
                ]);
                // Remove empty file
                await fs.promises.unlink(filepath);
                continue;
            }

            logger.writeLog('INFO', [
                `• Successfully downloaded ${file.type || 'file'} data`,
                `• Saved to: ${filepath}`,
                `• File size: ${(stats.size / 1024 / 1024).toFixed(2)} MB`,
                ''
            ]);
        } catch (error) {
            const errorDetails = error.response ? {
                status: error.response.status,
                statusText: error.response.statusText,
                headers: error.response.headers,
                data: error.response.data
            } : {};

            logger.writeLog('ERROR', [
                `Failed to download file ${i + 1}:`,
                `• Error: ${error.message}`,
                '• Error Details:',
                JSON.stringify(errorDetails, null, 2),
                '',
                'Continuing with next file...',
                ''
            ]);
        }
    }
}

async function processObservationData(exportDir, logger) {
    // First, load Patient data to get names and details
    const patientFile = path.join(exportDir, 'bulk_fhir_Patient.ndjson');
    const patients = {};
    
    if (fs.existsSync(patientFile)) {
        const patientContent = await fs.promises.readFile(patientFile, 'utf8');
        const patientLines = patientContent.trim().split('\n');
        for (const line of patientLines) {
            if (line.trim()) {
                const patient = JSON.parse(line);
                patients[patient.id] = {
                    name: patient.name?.[0]?.family 
                          ? `${patient.name[0].family}, ${patient.name[0].given?.join(' ') || ''}`
                          : 'Unknown Patient',
                    id: patient.id,
                    gender: patient.gender || 'Unknown',
                    birthDate: patient.birthDate || 'Unknown',
                    observations: {
                        total: 0,
                        normal: 0,
                        abnormal: 0,
                        byType: {}
                    }
                };
            }
        }
    }

    // Find all observation batch files
    const observationFiles = fs.readdirSync(exportDir)
        .filter(file => file.startsWith('bulk_fhir_Observation'))
        .map(file => path.join(exportDir, file));

    logger.writeLog('INFO', [
        'PROCESSING OBSERVATION DATA',
        '-------------------------',
        `Found ${observationFiles.length} observation batch file(s):`,
        ...observationFiles.map(file => `• ${path.basename(file)}`),
        '',
        observationFiles.length > 0 
            ? 'Note: Multiple batch files indicate the server split the data into chunks.\nAll batches will be combined and processed together.'
            : 'Note: No observation files found. This is normal if there are no observations\nfor the requested patients or if the data export is still in progress.',
        ''
    ]);

    if (observationFiles.length === 0) {
        return {
            totalObservations: 0,
            normalReadings: 0,
            abnormalReadings: 0,
            vitalSignStats: {},
            patientStats: Object.fromEntries(
                Object.entries(patients).map(([id, patient]) => [
                    id,
                    {
                        name: patient.name,
                        total: 0,
                        normal: 0,
                        abnormal: 0,
                        byType: {}
                    }
                ])
            ),
            detailedObservations: []
        };
    }

    const observations = [];
    const vitalSignStats = {
        totalReadings: 0,
        normalReadings: 0,
        abnormalReadings: 0,
        byType: {},
        byPatient: {}
    };

    // Process each observation batch file
    for (const observationFile of observationFiles) {
        logger.writeLog('INFO', [
            `Processing batch file: ${path.basename(observationFile)}`,
            '----------------------------------------'
        ]);

        try {
            const observationContent = await fs.promises.readFile(observationFile, 'utf8');
            const observationLines = observationContent.trim().split('\n');
            
            let batchObservations = 0;
            let batchNormal = 0;
            let batchAbnormal = 0;

            for (const line of observationLines) {
                if (line.trim()) {
                    const obs = JSON.parse(line);
                    const patientId = obs.subject?.reference?.split('/')[1];
                    const patient = patients[patientId] || { name: 'Unknown Patient', id: patientId };
                    
                    // Extract observation details
                    const observationType = obs.code?.coding?.[0]?.display || 'Unknown';
                    const value = obs.valueQuantity 
                        ? `${obs.valueQuantity.value} ${obs.valueQuantity.unit || ''}`
                        : (obs.valueString || obs.valueCodeableConcept?.coding?.[0]?.display || 'No value recorded');

                    // Get reference range with units
                    let referenceRange = 'No range specified';
                    if (obs.referenceRange?.[0]) {
                        const range = obs.referenceRange[0];
                        const unit = range.high?.unit || range.low?.unit || '';
                        const low = range.low?.value !== undefined ? range.low.value : '';
                        const high = range.high?.value !== undefined ? range.high.value : '';
                        if (low !== '' || high !== '') {
                            referenceRange = `${low}${low !== '' && high !== '' ? '-' : ''}${high} ${unit}`.trim();
                        }
                    }

                    // Determine status with detailed interpretation
                    let status = 'NORMAL';
                    let interpretation = '';
                    if (obs.interpretation?.[0]?.coding?.[0]) {
                        const code = obs.interpretation[0].coding[0].code;
                        const text = obs.interpretation[0].coding[0].display || '';
                        status = ['A', 'H', 'L'].includes(code) ? 'ABNORMAL' : 'NORMAL';
                        interpretation = text;
                    } else if (obs.referenceRange?.[0]) {
                        const range = obs.referenceRange[0];
                        const value = obs.valueQuantity?.value;
                        if (value !== undefined && (range.low?.value !== undefined || range.high?.value !== undefined)) {
                            if ((range.low?.value !== undefined && value < range.low.value) ||
                                (range.high?.value !== undefined && value > range.high.value)) {
                                status = 'ABNORMAL';
                            }
                        }
                    }

                    // Update statistics
                    vitalSignStats.totalReadings++;
                    if (status === 'NORMAL') {
                        vitalSignStats.normalReadings++;
                        batchNormal++;
                    } else {
                        vitalSignStats.abnormalReadings++;
                        batchAbnormal++;
                    }
                    batchObservations++;

                    // Track by type
                    if (!vitalSignStats.byType[observationType]) {
                        vitalSignStats.byType[observationType] = {
                            total: 0,
                            normal: 0,
                            abnormal: 0,
                            values: [],
                            referenceRanges: new Set(),
                            units: new Set()
                        };
                    }
                    vitalSignStats.byType[observationType].total++;
                    if (status === 'NORMAL') {
                        vitalSignStats.byType[observationType].normal++;
                    } else {
                        vitalSignStats.byType[observationType].abnormal++;
                    }
                    vitalSignStats.byType[observationType].values.push(value);
                    if (referenceRange !== 'No range specified') {
                        vitalSignStats.byType[observationType].referenceRanges.add(referenceRange);
                    }
                    if (obs.valueQuantity?.unit) {
                        vitalSignStats.byType[observationType].units.add(obs.valueQuantity.unit);
                    }

                    // Track by patient
                    if (!vitalSignStats.byPatient[patientId]) {
                        vitalSignStats.byPatient[patientId] = {
                            name: patient.name,
                            total: 0,
                            normal: 0,
                            abnormal: 0,
                            byType: {}
                        };
                    }
                    vitalSignStats.byPatient[patientId].total++;
                    if (status === 'NORMAL') {
                        vitalSignStats.byPatient[patientId].normal++;
                    } else {
                        vitalSignStats.byPatient[patientId].abnormal++;
                    }

                    // Track patient-specific observation types
                    if (!vitalSignStats.byPatient[patientId].byType[observationType]) {
                        vitalSignStats.byPatient[patientId].byType[observationType] = {
                            total: 0,
                            normal: 0,
                            abnormal: 0,
                            values: []
                        };
                    }
                    vitalSignStats.byPatient[patientId].byType[observationType].total++;
                    if (status === 'NORMAL') {
                        vitalSignStats.byPatient[patientId].byType[observationType].normal++;
                    } else {
                        vitalSignStats.byPatient[patientId].byType[observationType].abnormal++;
                    }
                    vitalSignStats.byPatient[patientId].byType[observationType].values.push(value);

                    observations.push({
                        date: new Date(obs.effectiveDateTime || obs.issued),
                        patientName: patient.name,
                        patientId: patient.id,
                        patientGender: patient.gender,
                        patientBirthDate: patient.birthDate,
                        observationType,
                        value,
                        referenceRange,
                        status,
                        interpretation,
                        category: obs.category?.[0]?.coding?.[0]?.display || 'Unknown',
                        issued: obs.issued,
                        effectiveDateTime: obs.effectiveDateTime
                    });
                }
            }

            // Log batch statistics
            logger.writeLog('INFO', [
                'Batch Statistics:',
                `• Total Observations: ${batchObservations}`,
                `• Normal Readings: ${batchNormal}`,
                `• Abnormal Readings: ${batchAbnormal}`,
                ''
            ]);
        } catch (error) {
            // Log a more informative message about missing or invalid files
            logger.writeLog('INFO', [
                `Note: Could not process ${path.basename(observationFile)}`,
                'This is normal if:',
                '• The file was empty and automatically cleaned up',
                '• The export process is still ongoing',
                '• There was no data for this batch',
                '',
                'Continuing with remaining files...',
                ''
            ]);
            continue;
        }
    }

    // Sort all observations by date descending
    observations.sort((a, b) => b.date - a.date);

    return {
        totalObservations: vitalSignStats.totalReadings,
        normalReadings: vitalSignStats.normalReadings,
        abnormalReadings: vitalSignStats.abnormalReadings,
        vitalSignStats: vitalSignStats.byType,
        patientStats: vitalSignStats.byPatient,
        detailedObservations: observations
    };
}

async function generateAndEmailReport(exportDir, observationData, logger, config) {
    // Create report content
    const reportLines = [
        'OBSERVATION ANALYSIS REPORT',
        '==========================',
        '',
        'DATA ANALYSIS OVERVIEW',
        '---------------------',
        '',
        'Vital Signs Analysis:',
        '-------------------'
    ];

    // Add analysis for each vital sign type
    for (const [type, stats] of Object.entries(observationData.vitalSignStats)) {
        reportLines.push(
            `${type}:`,
            `  Total Readings: ${stats.total}`,
            `  Normal Readings: ${stats.normal}`,
            `  Abnormal Readings: ${stats.abnormal}`,
            `  Values: ${Array.from(new Set(stats.values)).join(', ')}`,
            `  Units: ${Array.from(stats.units).join(', ') || 'N/A'}`,
            `  Reference Ranges: ${Array.from(stats.referenceRanges).join(', ') || 'N/A'}`,
            ''
        );
    }

    // Add patient-specific analysis
    reportLines.push(
        'Patient Analysis:',
        '----------------'
    );
    
    for (const [patientId, stats] of Object.entries(observationData.patientStats)) {
        reportLines.push(
            `Patient: ${stats.name}`,
            `  Total Observations: ${stats.total}`,
            `  Normal Readings: ${stats.normal}`,
            `  Abnormal Readings: ${stats.abnormal}`,
            '  Observation Types:'
        );

        // Add type-specific stats for each patient
        for (const [type, typeStats] of Object.entries(stats.byType)) {
            reportLines.push(
                `    ${type}:`,
                `      Total: ${typeStats.total}`,
                `      Normal: ${typeStats.normal}`,
                `      Abnormal: ${typeStats.abnormal}`,
                `      Values: ${typeStats.values.join(', ')}`
            );
        }
        reportLines.push('');
    }

    // Add summary section
    reportLines.push(
        'SUMMARY',
        '-------',
        `Total Observations: ${observationData.totalObservations}`,
        `Total Normal Readings: ${observationData.normalReadings}`,
        `Total Abnormal Readings: ${observationData.abnormalReadings}`,
        '',
        'DETAILED OBSERVATIONS',
        '--------------------',
        'Date | Patient | Type | Value | Reference Range | Status | Category',
        '----------------------------------------------------------------'
    );

    // Add detailed observations
    for (const obs of observationData.detailedObservations) {
        const date = obs.date.toISOString().split('T')[0];
        reportLines.push(
            `${date} | ${obs.patientName} | ${obs.observationType} | ${obs.value} | ${obs.referenceRange} | ${obs.status} | ${obs.category}`
        );
    }

    // Add export information
    reportLines.push(
        '',
        'EXPORT INFORMATION',
        '------------------',
        `Export Directory: ${exportDir}`,
        `Report Generated: ${new Date().toISOString()}`,
        ''
    );

    const reportContent = reportLines.join('\n');

    // Write report to log file
    logger.writeLog('INFO', [
        'OBSERVATION ANALYSIS REPORT',
        '--------------------------',
        reportContent,
        '--------------------------'
    ]);

    // Save report to file
    const reportPath = path.join(exportDir, 'bulk_fhir_observation_report.txt');
    await fs.promises.writeFile(reportPath, reportContent, 'utf8');

    // Send email with report
    const mailOptions = {
        from: config.email.smtp_user,
        to: config.email.notification_to,
        subject: 'EPIC BULK FHIR DATA EXPORT - OBSERVATION ANALYSIS REPORT',
        text: reportContent,
        attachments: [{
            filename: 'bulk_fhir_observation_report.txt',
            path: reportPath
        }]
    };

    const transporter = nodemailer.createTransport({
        host: config.email.smtp_host,
        port: parseInt(config.email.smtp_port),
        secure: false,
        auth: {
            user: config.email.smtp_user,
            pass: config.email.smtp_pass
        },
        tls: {
            rejectUnauthorized: false
        }
    });

    try {
        await transporter.sendMail(mailOptions);
        logger.writeLog('INFO', ['Email sent successfully with observation report']);
    } catch (error) {
        logger.writeLog('ERROR', [`Error sending email: ${error.message}`]);
        throw error;
    }
}

async function main() {
    let logger = null;
    let config = null;

    try {
        // Reset any existing logger instance
        Logger.resetInstance();
        
        // Load configuration first
        config = loadConfig();
        
        // Initialize logger with config and script name
        logger = Logger.getInstance(config, scriptName);

        // Initialize export directory path
        const exportDir = path.resolve(config.paths.epic_data_export_folder);
        
        // Clear export directory
        await clearExportDirectory(exportDir, logger);
        
        logger.writeLog('INFO', [
            '================================================================================',
            '                     EPIC BULK FHIR DATA EXPORT TUTORIAL                        ',
            '================================================================================',
            '',
            'This script demonstrates the Epic Bulk FHIR Data Export process using JWT',
            'authentication. It will walk through each step of the process, explaining the',
            'technical details and showing the actual data involved.',
            '',
            'STEP 1: INITIALIZATION',
            '--------------------',
            'Before we begin, we need to set up our environment:',
            '• Clear previous export files',
            '• Initialize logging',
            '• Load configuration',
            '',
            '',
            'STEP 2: JWT CREATION AND SIGNING',
            '---------------------------',
            'The JWT (JSON Web Token) is created with the following structure:',
            '',
            'Header:',
            '  {',
            '    "alg": "RS384",',
            '    "typ": "JWT"',
            '  }',
            '',
            'Claims:',
            '  {',
            `    "iss": "${config.oauth_settings.client_id}",`,
            '    "sub": [same as iss],',
            '    "aud": [token endpoint],',
            '    "jti": [unique identifier],',
            '    "exp": [expiration time],',
            '    "iat": [issued at time],',
            '  },',
            '',
            'The JWT is signed using:',
            `• Algorithm: ${config.jwt_settings.jwt_algorithm}`,
            `• Key Size: ${config.rsa_settings.rsa_key_size} bits`,
            `• Private Key: ${config.paths.private_key}`,
            `• Public Key: ${config.paths.public_key}`,
            ''
        ]);

        // Initialize key manager and generate keys if needed
        const keyManager = new KeyManager(config);
        await keyManager.generateKeyPair();

        logger.writeLog('INFO', [
            '',
            'STEP 3: OAUTH 2.0 TOKEN EXCHANGE',
            '-----------------------------',
            'The signed JWT is exchanged for an access token using:',
            '• Epic Base URL:',
            `  ${config.epic_settings.epic_endpoint}`,
            '• OAuth Token Endpoint:',
            `  ${config.oauth_settings.token_endpoint}`,
            '• Client ID:',
            `  ${config.oauth_settings.client_id}`,
            '',
            'Request Parameters:',
            '  {',
            `    "grant_type": "${config.oauth_settings.grant_type}",`,
            `    "client_assertion_type": "${config.oauth_settings.client_assertion_type}",`,
            '    "client_assertion": [signed JWT]',
            '  }',
            ''
        ]);

        const jwtManager = new JWTManager(config);
        const client = new FHIRQueryClient(config, logger);

        // Get access token
        const accessToken = await jwtManager.getAccessToken();
        
        logger.writeLog('INFO', [
            '• Successfully obtained access token',
            '',
            'STEP 4: BULK FHIR DATA EXPORT',
            '--------------------------',
            'The Bulk FHIR Data Export process follows these steps:',
            '',
            '1. Initiate Export:',
            '   • Send request to Group/$export endpoint',
            '   • Specify desired resource types',
            '   • Receive status URL in response',
            '',
            '2. Monitor Progress:',
            '   • Poll status URL periodically',
            '   • Check for completion or errors',
            '',
            '3. Download Results:',
            '   • Retrieve data for each resource type',
            '   • Save as NDJSON files',
            '',
            'Resource Types Requested:'
        ]);

        // Define resource types for bulk export
        const resourceTypes = [
            'Patient',
            'Observation',
            'Condition',
            'AllergyIntolerance',
            'MedicationRequest',
            'Procedure'
        ];

        logger.writeLog('INFO', [
            ...resourceTypes.map(type => `  - ${type}`),
            '',
            'Group Export Details:',
            '• Group ID: e3iabhmS8rsueyz7vaimuiaSmfGvi.QwjVXJANlPOgR83',
            '• Export URL Format:',
            `  ${config.epic_settings.epic_endpoint}Group/[id]/$export?_type=[types]`,
            '',
            'Headers:',
            '  Authorization: Bearer [token]',
            '  Accept: application/fhir+json',
            '  Prefer: respond-async',
            '',
            'Initiating bulk export request...'
        ]);
        
        // Initiate bulk export
        const statusUrl = await client.initiateGroupExport(accessToken, resourceTypes);
        
        logger.writeLog('INFO', [
            '',
            'STEP 5: EXPORT MONITORING AND DOWNLOAD',
            '----------------------------------',
            'The export process is asynchronous. We will:',
            '1. Poll the status URL every 10 seconds',
            '2. Check for completion status',
            '3. Download each resource file when ready',
            '4. Process observation data for analysis',
            '',
            'Status URL:',
            `  ${statusUrl}`,
            '',
            'Starting export status monitoring...'
        ]);

        // Poll status and download results
        const outputFiles = await monitorExportStatus(statusUrl, accessToken, logger);
        await downloadExportFiles(outputFiles, accessToken, exportDir, logger);
        
        // Process observations and send report
        logger.writeLog('INFO', [
            '',
            'STEP 6: DATA ANALYSIS AND REPORTING',
            '--------------------------------',
            'Processing downloaded data to:',
            '1. Analyze observation patterns',
            '2. Generate statistical report',
            '3. Email findings to stakeholders',
            ''
        ]);

        const stats = await processObservationData(exportDir, logger);
        await generateAndEmailReport(exportDir, stats, logger, config);

        logger.writeLog('INFO', [
            '',
            'STEP 6: DATA ANALYSIS',
            '-------------------',
            'After downloading the bulk data, we:',
            '1. Parse the NDJSON files',
            '2. Analyze observation data',
            '3. Generate a summary report',
            '4. Save results to the export directory',
            '',
            'The observation report includes:',
            '• Reference ranges for vital signs',
            '• Normal vs abnormal readings',
            '• Patient-specific statistics',
            '',
            '================================================================================',
            '                               PROCESS COMPLETE                                  ',
            '================================================================================',
            '',
            'Summary:',
            '• Successfully authenticated using JWT',
            '• Completed bulk FHIR data export',
            '• Downloaded and processed resource data',
            '• Generated observation analysis report',
            '',
            'All files can be found in:',
            `  ${exportDir}`,
            '================================================================================',
        ]);

    } catch (error) {
        if (logger) {
            logger.writeLog('ERROR', [
                '',
                '================================================================================',
                '                               PROCESS FAILED                                    ',
                '================================================================================',
                'Error Details:',
                `• Message: ${error.message}`,
                '• Stack Trace:',
                error.stack,
                '',
                '================================================================================',
            ]);
        } else {
            console.error('Initialization Error:', error.message);
            console.error('Stack Trace:', error.stack);
        }
        process.exit(1);
    }
}

if (require.main === module) {
    main();
}
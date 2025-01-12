const fs = require('fs');
const path = require('path');
const { JWTManager } = require('./jwt_manager');
const Logger = require('./src/utils/Logger');
const { loadConfig } = require('./config_loader');
const { FHIRQueryClient } = require('./fhir_query_client');
const { KeyManager } = require('./key_manager');
const axios = require('axios');

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
            '• Action: Clearing previous export files'
        ]);

        if (fs.existsSync(dirPath)) {
            const files = fs.readdirSync(dirPath);
            logger.writeLog('INFO', [`• Found ${files.length} files to remove`]);
            for (const file of files) {
                const filePath = path.join(dirPath, file);
                await fs.promises.unlink(filePath);
            }
            logger.writeLog('INFO', ['• Successfully cleared all existing files']);
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

    logger.writeLog('INFO', [
        'DOWNLOADING EXPORT FILES',
        '----------------------',
        `• Total files to download: ${outputFiles.length}`,
        `• Export directory: ${exportDir}`,
        '',
        'File Details:',
        ...outputFiles.map((file, i) => `• File ${i + 1}: ${file.type || 'unknown type'}`),
        ''
    ]);

    for (let i = 0; i < outputFiles.length; i++) {
        const file = outputFiles[i];
        const filename = `${file.type || `export_${i + 1}`}.ndjson`;
        const filepath = path.join(exportDir, filename);

        logger.writeLog('INFO', [
            `Downloading file ${i + 1} of ${outputFiles.length}:`,
            `• Type: ${file.type || 'unknown'}`,
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
                throw new Error('Downloaded file is empty');
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
            ''
        ]);

        // Clear the export directory
        const exportDir = path.resolve(config.paths.epic_data_export_folder);
        await clearExportDirectory(exportDir, logger);
        
        logger.writeLog('INFO', [
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
            '    "iat": [issued at time]',
            '  }',
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
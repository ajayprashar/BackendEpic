/**
 * EPIC FHIR Backend Data Integration System
 * =======================================
 * Author: Ajay Prashar
 * Date: 12/30/2024
 * Version: 1.0.0
 * 
 * Primary Functions:
 * 1. OAuth 2.0 Authentication with Epic's FHIR API using JWT
 * 2. Automated batch data retrieval from Epic's FHIR endpoints
 * 3. Data export and analysis with reporting capabilities
 * 4. Email notification system for process monitoring
 * 
 * Process Flow:
 * 1. Initialization
 *    - Load configuration from INI file
 *    - Set up logging system
 *    - Prepare export directory
 * 
 * 2. Authentication
 *    - Manage RSA key pair (generate/verify)
 *    - Create JWT with required claims
 *    - Obtain access token from Epic's OAuth endpoint
 * 
 * 3. Data Collection
 *    - Load patient roster and resource definitions
 *    - Iterate through resources for each patient
 *    - Handle paginated API requests
 *    - Manage rate limiting and error handling
 * 
 * 4. Data Processing
 *    - Convert API responses to NDJSON format
 *    - Export to timestamped files
 *    - Track export statistics
 * 
 * 5. Analysis & Reporting
 *    - Process observation data
 *    - Generate statistical analysis
 *    - Create detailed reports
 * 
 * 6. Notification
 *    - Send completion email
 *    - Include analysis report
 *    - List exported files
 * 
 * Key Components:
 * - ConfigManager: Configuration and environment management
 * - KeyManager: RSA key pair operations for JWT signing
 * - JWTManager: JWT creation and token management
 * - EpicClient: FHIR API communication and data retrieval
 * - Logger: Logging and export directory management
 * 
 * Dependencies:
 * - fs: File system operations
 * - path: Path manipulation
 * - crypto: RSA key operations
 * - ini: Configuration parsing
 * - axios: HTTP client for API requests
 * - jsonwebtoken: JWT operations
 * - uuid: Unique identifier generation
 * - csv: CSV file parsing
 * - nodemailer: Email notifications
 * 
 * Security Features:
 * - RSA key pair management (2048-bit)
 * - JWT-based authentication
 * - Secure email notifications
 * - Environment variable support
 * 
 * Error Handling:
 * - Comprehensive logging
 * - Email notifications for failures
 * - Graceful process termination
 * - Rate limiting management
 * 
 * Output:
 * - NDJSON files for each resource type
 * - Detailed observation analysis
 * - Process completion email
 * - Comprehensive log file
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const ini = require('ini');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const csv = require('csv-parse/sync');
const util = require('util');
const nodemailer = require('nodemailer');
require('dotenv').config();
const ConfigManager = require('./src/managers/ConfigManager');
const Logger = require('./src/utils/Logger');

const scriptName = path.basename(__filename);

// Reset any existing logger instance
Logger.resetInstance();

// Get logger instance with script name
const logger = Logger.getInstance(null, scriptName);

// Ensure logger is closed properly on exit
process.on('exit', () => {
    logger.close();
});

process.on('uncaughtException', (error) => {
    console.error('Uncaught Exception:', error);
    logger.close();
    process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
    logger.close();
    process.exit(1);
});

// Remove direct config loading
const configPath = path.resolve(__dirname, 'backend_epic_using_jwt.ini');
const configManager = new ConfigManager(configPath);

/**
 * Key Management
 * =============
 * Handles RSA key pair generation and storage according to EPIC's requirements:
 * - 2048-bit minimum key length
 * - PKCS#8 format for private key
 * - SPKI format for public key
 * - Base64 encoded public key for registration
 * 
 * Security Note:
 * Private keys are sensitive and should be properly secured in production.
 */
class KeyManager {
    constructor(config) {
        if (!config.paths) {
            throw new Error('Configuration missing required paths section');
        }

        this.privateKeyPath = path.resolve(config.paths.private_key);
        this.publicKeyPath = path.resolve(config.paths.public_key);
        this.base64PublicKeyPath = path.resolve(config.paths.base64_public_key);

        this.rsaKeySize = parseInt(config.rsa_settings.rsa_key_size) || 2048;
        this.rsaPublicEncoding = config.rsa_settings.rsa_public_encoding || 'spki';
        this.rsaPrivateEncoding = config.rsa_settings.rsa_private_encoding || 'pkcs8';
    }

    calculatePublicKeyId(publicKey) {
        const cleanContent = publicKey.toString()
            .replace(/-----BEGIN PUBLIC KEY-----/, '')
            .replace(/-----END PUBLIC KEY-----/, '')
            .replace(/-----BEGIN CERTIFICATE-----/, '')
            .replace(/-----END CERTIFICATE-----/, '')
            .replace(/\n/g, '');

        const derBuffer = Buffer.from(cleanContent, 'base64');
        const hash = crypto.createHash('sha1');
        hash.update(derBuffer);
        return hash.digest('hex').toUpperCase();
    }

    async generateKeyPair() {
        if (!this.privateKeyPath) {
            throw new Error('Private key path is not defined in configuration');
        }

        const dir = path.dirname(this.privateKeyPath);
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }

        let publicKey;
        if (!fs.existsSync(this.privateKeyPath)) {
            const keyPair = crypto.generateKeyPairSync('rsa', {
                modulusLength: this.rsaKeySize,
                publicKeyEncoding: {
                    type: this.rsaPublicEncoding,
                    format: 'pem'
                },
                privateKeyEncoding: {
                    type: this.rsaPrivateEncoding,
                    format: 'pem'
                }
            });

            fs.writeFileSync(this.privateKeyPath, keyPair.privateKey);
            fs.writeFileSync(this.publicKeyPath, keyPair.publicKey);
            
            const base64PublicKey = Buffer.from(keyPair.publicKey).toString('base64');
            fs.writeFileSync(this.base64PublicKeyPath, base64PublicKey);
            
            publicKey = keyPair.publicKey;
            const publicKeyId = this.calculatePublicKeyId(publicKey);
            logger.writeLog('INFO', [`Key pair generated successfully (Public Key ID: ${publicKeyId})`], console.log);
        } else {
            publicKey = fs.readFileSync(this.publicKeyPath, 'utf8');
            const publicKeyId = this.calculatePublicKeyId(publicKey);
            logger.writeLog('INFO', [`Using existing key pair (Public Key ID: ${publicKeyId})`], console.log);
        }
    }
}

/**
 * JWT Management
 * =============
 * Creates JSON Web Tokens required for EPIC authentication.
 * 
 * JWT Structure:
 * 1. Header:
 *    - alg: RS384 (Required by EPIC)
 *    - typ: JWT
 * 
 * 2. Claims:
 *    - iss (issuer): Client ID assigned by EPIC
 *    - sub (subject): Same as issuer for backend services
 *    - aud (audience): EPIC's token endpoint
 *    - jti (JWT ID): Unique identifier per request
 *    - exp (expiration): Current time + 5 minutes
 *    - nbf (not before): Current time
 *    - iat (issued at): Current time
 * 
 * Security Note:
 * The JWT is signed using the private key to prove client identity
 */
class JWTManager {
    constructor(config) {
        if (!config.paths || !config.oauth_settings) {
            throw new Error('Configuration missing required paths or oauth_settings section');
        }

        this.config = config;
        this.privateKey = fs.readFileSync(config.paths.private_key, 'utf8');
        this.clientId = config.oauth_settings.client_id;
        this.tokenEndpoint = config.oauth_settings.token_endpoint;
        this.algorithm = config.jwt_settings.jwt_algorithm || 'RS384';
        this.expiryMinutes = parseInt(config.jwt_settings.jwt_expiry_minutes) || 5;
    }

    generateJWT() {
        const publicKey = fs.readFileSync(this.config.paths.public_key, 'utf8');
        const publicKeyId = crypto.createHash('sha1')
            .update(Buffer.from(publicKey.replace(/-----BEGIN (?:PUBLIC KEY|CERTIFICATE)-----|\n|-----END (?:PUBLIC KEY|CERTIFICATE)-----/g, ''), 'base64'))
            .digest('hex')
            .toUpperCase();
        
        const currentTime = Math.floor(Date.now() / 1000);
        const expiryTime = currentTime + (this.expiryMinutes * 60);
        
        const claims = {
            iss: this.clientId,
            sub: this.clientId,
            aud: this.tokenEndpoint,
            jti: uuidv4(),
            exp: expiryTime,
            nbf: currentTime,
            iat: currentTime
        };

        const header = {
            alg: this.algorithm,
            typ: 'JWT',
            kid: publicKeyId
        };

        return jwt.sign(claims, this.privateKey, {
            algorithm: this.algorithm,
            header: header,
            noTimestamp: true
        });
    }

    async getAccessToken() {
        try {
            const jwt = this.generateJWT();
            
            const response = await axios.post(this.tokenEndpoint, 
                new URLSearchParams({
                    grant_type: this.config.oauth_settings.grant_type,
                    client_assertion_type: this.config.oauth_settings.client_assertion_type,
                    client_assertion: jwt
                }), 
                {
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded'
                    }
                }
            );

            if (!response.data.access_token) {
                throw new Error('No access token received in response');
            }

            return response.data.access_token;
        } catch (error) {
            console.error('Error in token request process:', {
                message: error.message,
                status: error.response?.status,
                data: error.response?.data
            });
            throw error;
        }
    }
}

/**
 * Reads and parses a CSV file
 * @param {string} filePath - Path to the CSV file
 * @returns {Array} Parsed CSV data as array of objects
 */
async function readCSVFile(filePath, logger) {
    try {
        const fileContent = await fs.promises.readFile(filePath, 'utf-8');
        return csv.parse(fileContent, {
            columns: true,
            skip_empty_lines: true,
            trim: true
        });
    } catch (error) {
        logger.writeLog('ERROR', [
            `Failed to read CSV file: ${filePath}`,
            `Error: ${error.message}`
        ]);
        throw error;
    }
}

/**
 * Loads patient roster and resources configuration
 */
async function loadDataSources(config, logger) {
    logger.writeLog('INFO', [
        'Loading data sources...',
        `• Patient Roster: ${path.basename(config.data_sources.epic_sandbox_roster)}`,
        `• Resources: ${path.basename(config.data_sources.epic_sandbox_resources)}`,
        ''
    ]);

    try {
        const roster = await readCSVFile(config.data_sources.epic_sandbox_roster, logger);
        const resources = await readCSVFile(config.data_sources.epic_sandbox_resources, logger);

        // Validate roster data
        if (!roster.every(patient => patient.fhir_id)) {
            throw new Error('Invalid roster format: Missing fhir_id column');
        }

        // Validate resources data
        if (!resources.every(resource => resource.resource)) {
            throw new Error('Invalid resources format: Missing resource column');
        }

        // Map the CSV data to the expected format
        const mappedRoster = roster.map(patient => ({
            PatientID: patient.fhir_id,
            name: patient.name
        }));

        const mappedResources = resources.map(resource => ({
            ResourceType: resource.resource,
            description: resource.description
        }));

        logger.writeLog('INFO', [
            'Data sources loaded:',
            `• Found ${mappedRoster.length} patients in roster:`,
            ...mappedRoster.map(p => `  - ${p.name} (${p.PatientID})`),
            '',
            `• Found ${mappedResources.length} resource types configured:`,
            ...mappedResources.map(r => `  - ${r.ResourceType}: ${r.description}`),
            ''
        ]);

        return { 
            roster: mappedRoster, 
            resources: mappedResources.filter(r => r.ResourceType?.trim())
        };
    } catch (error) {
        logger.writeLog('ERROR', [
            'Failed to load data sources:',
            `• Error: ${error.message}`,
            '',
            'Please ensure the CSV files exist and have the correct format:',
            '• Roster CSV must have "fhir_id" and "name" columns',
            '• Resources CSV must have "resource" and "description" columns',
            ''
        ]);
        throw error;
    }
}

/**
 * EPIC API Client
 * ==============
 * Handles communication with EPIC's FHIR API endpoints.
 * 
 * Authentication Process:
 * 1. Generate JWT using JWTManager
 * 2. Request access token using JWT assertion:
 *    - POST to token endpoint
 *    - Include JWT as client_assertion
 *    - Specify client_credentials grant type
 * 3. Use received access token for FHIR API requests
 * 
 * Error Handling:
 * - Catches and logs authentication errors
 * - Catches and logs FHIR API errors
 * - Provides detailed error information for debugging
 */
class EpicClient {
    constructor(config) {
        if (!config) {
            throw new Error('Configuration object is required');
        }
        this.config = config;
        this.exportDir = path.resolve(config.paths.epic_data_export_folder);
        this.exportedFiles = [];
        this.epicEndpoint = config.epic_settings.epic_endpoint;
        this.tokenEndpoint = config.oauth_settings.token_endpoint;
        
        // Add these lines to get the paths from config
        this.patientRosterPath = config.data_sources.epic_sandbox_roster;
        this.resourcesListPath = config.data_sources.epic_sandbox_resources;
        
        // Validate required paths
        if (!this.patientRosterPath) {
            throw new Error('Patient roster path not found in configuration');
        }
        if (!this.resourcesListPath) {
            throw new Error('Resources list path not found in configuration');
        }

        // Create export directory if it doesn't exist
        if (!fs.existsSync(this.exportDir)) {
            fs.mkdirSync(this.exportDir, { recursive: true });
        }
    }

    async getAllResourceData(accessToken) {
        const logger = Logger.getInstance();
        try {
            this.exportedFiles = [];
            
            // Load data sources using the function defined above
            const { roster, resources } = await loadDataSources(this.config, logger);
            
            // Define resource types from resources
            const resourceTypes = resources.map(r => r.ResourceType);

            logger.writeLog('INFO', [
                'STEP 2: DATA RETRIEVAL',
                '--------------------',
                'Retrieving data for the following resource types:',
                ...resourceTypes.map(type => `• ${type}`),
                '',
                `Processing ${roster.length} patients:`,
                ...roster.map(p => `• ${p.name} (${p.PatientID})`),
                ''
            ]);

            // Download data for each resource type
            const downloadedFiles = {};
            for (const patient of roster) {
                logger.writeLog('INFO', [
                    `Processing patient: ${patient.name} (${patient.PatientID})`,
                    '-'.repeat(50)
                ]);

                for (const resourceType of resourceTypes) {
                    try {
                        const filepath = await downloadResourceData(
                            resourceType, 
                            accessToken, 
                            this.exportDir, 
                            logger, 
                            this.config,
                            patient.PatientID
                        );
                        if (filepath) {
                            if (!downloadedFiles[resourceType]) {
                                downloadedFiles[resourceType] = [];
                            }
                            downloadedFiles[resourceType].push(filepath);
                        }
                    } catch (error) {
                        logger.writeLog('ERROR', [
                            `Failed to download ${resourceType} for patient ${patient.name} (${patient.PatientID}):`,
                            error.message,
                            'Continuing with remaining resources...',
                            ''
                        ]);
                    }
                }
            }

            // Process downloaded data and generate report
            await this.processDownloadedData(downloadedFiles, roster, logger);

        } catch (error) {
            logger.writeLog('ERROR', ['Error in data retrieval process:', error.message], console.error);
            throw error;
        }
    }

    async processDownloadedData(downloadedFiles, roster, logger) {
        logger.writeLog('INFO', [
            'STEP 3: DATA PROCESSING',
            '---------------------',
            'Processing downloaded data...',
            ''
        ]);

        // Process observation data
        let observationStats = await this.processObservations(downloadedFiles.Observation, roster, logger);

        // Generate report
        logger.writeLog('INFO', [
            'STEP 4: REPORT GENERATION',
            '----------------------',
            'Generating analysis report...',
            ''
        ]);

        const reportPath = await generateReport(observationStats, this.exportDir, logger);

        // Log completion summary
        this.logCompletionSummary(downloadedFiles, reportPath, logger);
    }

    async processObservations(observationFiles, roster, logger) {
        let observationStats = {
            totalReadings: 0,
            normalReadings: 0,
            abnormalReadings: 0,
            byType: {},
            byPatient: {},
            byCategory: {}
        };

        if (!observationFiles || observationFiles.length === 0) {
            logger.writeLog('INFO', ['No observation files to process']);
            return observationStats;
        }

        logger.writeLog('INFO', [
            'PROCESSING OBSERVATION DATA',
            '-------------------------',
            `Processing files for ${observationFiles.length} patients`,
            ''
        ]);

        for (const observationFile of observationFiles) {
            const observationContent = await fs.promises.readFile(observationFile, 'utf8');
            const observations = observationContent
                .trim()
                .split('\n')
                .filter(line => line.trim())
                .map(line => JSON.parse(line));

            const fileStats = await processObservationData(observations, roster, logger);
            this.mergeObservationStats(observationStats, fileStats);
        }

        return observationStats;
    }

    mergeObservationStats(target, source) {
        target.totalReadings += source.totalReadings;
        target.normalReadings += source.normalReadings;
        target.abnormalReadings += source.abnormalReadings;

        // Merge byType stats
        for (const [type, stats] of Object.entries(source.byType)) {
            if (!target.byType[type]) {
                target.byType[type] = {
                    total: 0,
                    normal: 0,
                    abnormal: 0,
                    values: [],
                    units: new Set(),
                    referenceRanges: new Set()
                };
            }
            target.byType[type].total += stats.total;
            target.byType[type].normal += stats.normal;
            target.byType[type].abnormal += stats.abnormal;
            target.byType[type].values.push(...stats.values);
            stats.units?.forEach(unit => target.byType[type].units.add(unit));
            stats.referenceRanges?.forEach(range => target.byType[type].referenceRanges.add(range));
        }

        // Merge byPatient stats
        for (const [patientId, stats] of Object.entries(source.byPatient)) {
            if (!target.byPatient[patientId]) {
                target.byPatient[patientId] = {
                    name: stats.name,
                    total: 0,
                    normal: 0,
                    abnormal: 0,
                    byType: {}
                };
            }
            target.byPatient[patientId].total += stats.total;
            target.byPatient[patientId].normal += stats.normal;
            target.byPatient[patientId].abnormal += stats.abnormal;

            // Merge patient-specific observation types
            for (const [type, typeStats] of Object.entries(stats.byType)) {
                if (!target.byPatient[patientId].byType[type]) {
                    target.byPatient[patientId].byType[type] = {
                        total: 0,
                        normal: 0,
                        abnormal: 0,
                        values: []
                    };
                }
                target.byPatient[patientId].byType[type].total += typeStats.total;
                target.byPatient[patientId].byType[type].normal += typeStats.normal;
                target.byPatient[patientId].byType[type].abnormal += typeStats.abnormal;
                target.byPatient[patientId].byType[type].values.push(...typeStats.values);
            }
        }

        // Merge byCategory stats
        for (const [category, stats] of Object.entries(source.byCategory)) {
            if (!target.byCategory[category]) {
                target.byCategory[category] = {
                    total: 0,
                    types: new Set()
                };
            }
            target.byCategory[category].total += stats.total;
            stats.types.forEach(type => target.byCategory[category].types.add(type));
        }
    }

    logCompletionSummary(downloadedFiles, reportPath, logger) {
        logger.writeLog('INFO', [
            '================================================================================',
            '                               PROCESS COMPLETE                                  ',
            '================================================================================',
            '',
            'Summary:',
            '• Successfully retrieved data using individual queries',
            `• Processed ${Object.keys(downloadedFiles).length} resource types`,
            '• Generated observation analysis report',
            '',
            'Files Generated:',
            ...Object.entries(downloadedFiles).map(([type, files]) => 
                `• ${type}: ${files.length} files`
            ),
            reportPath ? `• Report: ${path.basename(reportPath)}` : '',
            '',
            'All files can be found in:',
            `  ${this.exportDir}`,
            '',
            'Note: Compare these results with the bulk export method to understand:',
            '• Performance differences',
            '• Resource usage',
            '• Error handling approaches',
            '• Data consistency',
            '================================================================================',
        ].filter(Boolean));
    }

    // ... rest of the EpicClient class methods ...
}

/**
 * Downloads data for a specific resource type and patient
 */
async function downloadResourceData(resourceType, accessToken, exportDir, logger, config, patientId) {
    try {
        // Ensure export directory exists
        if (!fs.existsSync(exportDir)) {
            fs.mkdirSync(exportDir, { recursive: true });
        }

        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const filename = `fhir_${resourceType}_${patientId}_${timestamp}.ndjson`;
        const filepath = path.join(exportDir, filename);
        
        // Build query parameters based on resource type
        const queryParams = {
            _format: config.data_export.format,
            _count: config.data_export.default_count
        };

        // Add resource-specific parameters
        switch (resourceType) {
            case 'Patient':
                queryParams._id = patientId;
                break;
            case 'Observation':
                queryParams.patient = patientId;
                queryParams.category = 'laboratory,vital-signs'; // Add standard FHIR categories
                break;
            default:
                queryParams.patient = patientId;
                break;
        }

        const batches = [];
        let page = 1;
        let hasMore = true;

        logger.writeLog('INFO', [
            `Downloading ${resourceType} data for patient ${patientId}`,
            `• Output: ${filename}`,
            `• Format: ${queryParams._format}`,
            `• Batch size: ${queryParams._count}`,
            ''
        ]);

        while (hasMore && page <= config.api_settings.max_pages) {
            try {
                const url = `${config.epic_settings.epic_endpoint}${resourceType}`;
                queryParams._page = page;

                const response = await axios.get(url, {
                    params: queryParams,
                    headers: {
                        'Authorization': `Bearer ${accessToken}`,
                        'Accept': queryParams._format
                    }
                });

                if (response.data.entry && response.data.entry.length > 0) {
                    batches.push(...response.data.entry.map(e => e.resource));
                    logger.writeLog('INFO', [
                        `• Batch ${page}: Retrieved ${response.data.entry.length} resources`
                    ]);
                }

                // Check if there are more pages
                const nextLink = response.data.link?.find(link => link.relation === 'next')?.url;
                hasMore = !!nextLink;
                page++;

            } catch (error) {
                logger.writeLog('ERROR', [
                    `Failed to retrieve batch ${page} for ${resourceType}:`,
                    error.response?.data?.issue?.[0]?.diagnostics || error.message,
                    ''
                ]);
                break;
            }
        }

        if (batches.length > 0) {
            // Write data to file
            await fs.promises.writeFile(filepath, batches.map(resource => JSON.stringify(resource)).join('\n') + '\n');

            logger.writeLog('INFO', [
                `Successfully downloaded ${resourceType} data:`,
                `• Total resources: ${batches.length}`,
                `• File: ${filename}`,
                `• Size: ${(fs.statSync(filepath).size / 1024).toFixed(2)} KB`,
                ''
            ]);

            return filepath;
        } else {
            logger.writeLog('INFO', [
                `No ${resourceType} data found for patient ${patientId}`,
                ''
            ]);
            return null;
        }

    } catch (error) {
        logger.writeLog('ERROR', [
            `Failed to download ${resourceType} data:`,
            error.message,
            ''
        ]);
        throw error;
    }
}

/**
 * Processes observation data and generates statistics
 */
async function processObservationData(observations, roster, logger) {
    const stats = {
        totalReadings: 0,
        normalReadings: 0,
        abnormalReadings: 0,
        byType: {},
        byPatient: {},
        byCategory: {}
    };

    // Create a map of patient IDs to names for faster lookup
    const patientMap = new Map(roster.map(p => [p.PatientID, p.name]));

    for (const observation of observations) {
        try {
            // Skip observations without values
            if (!observation.valueQuantity) continue;

            const type = observation.code?.coding?.[0]?.display || 'Unknown';
            const value = observation.valueQuantity.value;
            const unit = observation.valueQuantity.unit;
            const patientId = observation.subject?.reference?.split('/')[1];
            const category = observation.category?.[0]?.coding?.[0]?.code || 'uncategorized';
            const referenceRange = observation.referenceRange?.[0];

            // Update category stats
            if (!stats.byCategory[category]) {
                stats.byCategory[category] = {
                    total: 0,
                    types: new Set()
                };
            }
            stats.byCategory[category].total++;
            stats.byCategory[category].types.add(type);

            // Initialize type stats if not exists
            if (!stats.byType[type]) {
                stats.byType[type] = {
                    total: 0,
                    normal: 0,
                    abnormal: 0,
                    values: [],
                    units: new Set(),
                    referenceRanges: new Set()
                };
            }

            // Initialize patient stats if not exists
            if (!stats.byPatient[patientId]) {
                stats.byPatient[patientId] = {
                    name: patientMap.get(patientId),
                    total: 0,
                    normal: 0,
                    abnormal: 0,
                    byType: {}
                };
            }

            // Initialize patient-specific type stats if not exists
            if (!stats.byPatient[patientId].byType[type]) {
                stats.byPatient[patientId].byType[type] = {
                    total: 0,
                    normal: 0,
                    abnormal: 0,
                    values: []
                };
            }

            // Update stats
            stats.totalReadings++;
            stats.byType[type].total++;
            stats.byType[type].values.push(value);
            stats.byType[type].units.add(unit);
            stats.byPatient[patientId].total++;
            stats.byPatient[patientId].byType[type].total++;
            stats.byPatient[patientId].byType[type].values.push(value);

            if (referenceRange) {
                const rangeStr = `${referenceRange.low?.value || '*'} - ${referenceRange.high?.value || '*'} ${unit}`;
                stats.byType[type].referenceRanges.add(rangeStr);

                const isNormal = (!referenceRange.low || value >= referenceRange.low.value) &&
                                (!referenceRange.high || value <= referenceRange.high.value);

                if (isNormal) {
                    stats.normalReadings++;
                    stats.byType[type].normal++;
                    stats.byPatient[patientId].normal++;
                    stats.byPatient[patientId].byType[type].normal++;
                } else {
                    stats.abnormalReadings++;
                    stats.byType[type].abnormal++;
                    stats.byPatient[patientId].abnormal++;
                    stats.byPatient[patientId].byType[type].abnormal++;
                }
            }
        } catch (error) {
            logger.writeLog('ERROR', [
                'Error processing observation:',
                error.message,
                JSON.stringify(observation, null, 2),
                ''
            ]);
        }
    }

    return stats;
}

/**
 * Generates a detailed report from observation statistics
 */
async function generateReport(observationStats, exportDir, logger) {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const reportPath = path.join(exportDir, `observation_report_${timestamp}.txt`);
    const reportLines = [];

    // Add report header
    reportLines.push(
        '================================================================================',
        '                           OBSERVATION ANALYSIS REPORT                           ',
        '================================================================================',
        '',
        'OVERVIEW',
        '--------',
        `Total Readings: ${observationStats.totalReadings}`,
        `Normal Readings: ${observationStats.normalReadings}`,
        `Abnormal Readings: ${observationStats.abnormalReadings}`,
        '',
        'OBSERVATION CATEGORIES',
        '---------------------'
    );

    // Add category analysis
    for (const [category, stats] of Object.entries(observationStats.byCategory)) {
        reportLines.push(
            `Category: ${category}`,
            `• Total Observations: ${stats.total}`,
            `• Observation Types: ${Array.from(stats.types).join(', ')}`,
            ''
        );
    }

    // Add type analysis
    reportLines.push(
        'OBSERVATION TYPES',
        '-----------------'
    );

    for (const [type, stats] of Object.entries(observationStats.byType)) {
        const values = stats.values;
        const avg = values.reduce((a, b) => a + b, 0) / values.length;
        const min = Math.min(...values);
        const max = Math.max(...values);
        
        reportLines.push(
            `Type: ${type}`,
            `• Total: ${stats.total}`,
            `• Normal: ${stats.normal}`,
            `• Abnormal: ${stats.abnormal}`,
            `• Units: ${Array.from(stats.units).join(', ')}`,
            `• Reference Ranges: ${Array.from(stats.referenceRanges).join(', ')}`,
            `• Value Range: ${min.toFixed(2)} - ${max.toFixed(2)}`,
            `• Average: ${avg.toFixed(2)}`,
            ''
        );
    }

    // Add patient analysis
    reportLines.push(
        'PATIENT ANALYSIS',
        '----------------'
    );

    for (const [patientId, stats] of Object.entries(observationStats.byPatient)) {
        reportLines.push(
            `Patient: ${stats.name} (${patientId})`,
            `• Total Readings: ${stats.total}`,
            `• Normal: ${stats.normal}`,
            `• Abnormal: ${stats.abnormal}`,
            '',
            'Observation Types:'
        );

        for (const [type, typeStats] of Object.entries(stats.byType)) {
            const values = typeStats.values;
            const avg = values.reduce((a, b) => a + b, 0) / values.length;
            
            reportLines.push(
                `  ${type}:`,
                `  • Total: ${typeStats.total}`,
                `  • Normal: ${typeStats.normal}`,
                `  • Abnormal: ${typeStats.abnormal}`,
                `  • Average: ${avg.toFixed(2)}`,
                ''
            );
        }
        reportLines.push('');
    }

    // Write report to file
    await fs.promises.writeFile(reportPath, reportLines.join('\n'));

    logger.writeLog('INFO', [
        'Report generated successfully:',
        `• File: ${path.basename(reportPath)}`,
        `• Size: ${(fs.statSync(reportPath).size / 1024).toFixed(2)} KB`,
        ''
    ]);

    return reportPath;
}

/**
 * Main application entry point
 * Handles the complete flow of:
 * 1. Configuration loading
 * 2. Key management
 * 3. JWT token acquisition
 * 4. Data retrieval
 * 5. Report generation
 */
async function main() {
    try {
        logger.writeLog('INFO', [
            '================================================================================',
            '                    EPIC FHIR Backend Data Integration System                    ',
            '================================================================================',
            '',
            'STEP 1: INITIALIZATION',
            '--------------------',
            'Loading configuration and preparing environment...',
            ''
        ]);

        // Load configuration
        const config = await configManager.loadConfig();

        // Initialize key manager and generate/verify keys
        const keyManager = new KeyManager(config);
        await keyManager.generateKeyPair();

        // Initialize JWT manager
        const jwtManager = new JWTManager(config);

        // Get access token
        const accessToken = await jwtManager.getAccessToken();

        // Initialize Epic client
        const epicClient = new EpicClient(config);

        // Get all resource data
        await epicClient.getAllResourceData(accessToken);

    } catch (error) {
        logger.writeLog('ERROR', [
            'Process failed:',
            error.message,
            error.stack,
            ''
        ], console.error);
        process.exit(1);
    }
}

// Application entry point
main().catch(error => {
    console.error('Fatal error:', error);
    process.exit(1);
});

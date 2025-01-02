/**
 * EPIC FHIR Backend Authentication Implementation
 * ============================================
 * Author: Ajay Prashar
 * Date: 12/30/2024
 * Version: 1.0.0
 * 
 * Description:
 * This application implements Epic's OAuth 2.0 backend authentication flow using 
 * JSON Web Tokens (JWT) for system-to-system integration with Epic's FHIR API.
 * 
 * Epic Documentation References:
 * - Authentication: https://fhir.epic.com/Documentation?docId=oauth2
 * - JWT Requirements: https://fhir.epic.com/Documentation?docId=jwt
 * - Non-Production Access: https://fhir.epic.com/Documentation?docId=testpatients
 * - FHIR API Endpoints: https://fhir.epic.com/Documentation?docId=epiconfhir
 * 
 * Authentication Flow:
 * 1. Generate/Load RSA Key Pair (Epic Auth Guide - Key Requirements)
 * 2. Create JWT with required claims (Epic Auth Guide - JWT Claims)
 * 3. Request access token using JWT assertion (Epic Auth Guide - Token Request)
 * 4. Use access token for FHIR API requests (Epic API Guide - Authentication)
 * 
 * Key Components:
 * - ConfigManager: Configuration loading and variable resolution
 * - KeyManager: RSA key pair generation/storage (Epic Auth Guide - Key Management)
 * - JWTManager: JWT creation and signing (Epic Auth Guide - JWT Format)
 * - EpicClient: FHIR API communication (Epic API Guide - REST Implementation)
 * 
 * Resource Types Implemented:
 * - Patient (Epic FHIR API - Patient Resource)
 * - Observation (Epic FHIR API - Observation Resource)
 * - Condition (Epic FHIR API - Condition Resource)
 * - AllergyIntolerance (Epic FHIR API - AllergyIntolerance Resource)
 * - DocumentReference (Epic FHIR API - DocumentReference Resource)
 * - MedicationRequest (Epic FHIR API - MedicationRequest Resource)
 * - Procedure (Epic FHIR API - Procedure Resource)
 * - Immunization (Epic FHIR API - Immunization Resource)
 * - DiagnosticReport (Epic FHIR API - DiagnosticReport Resource)
 * - Goal (Epic FHIR API - Goal Resource)
 * - Device (Epic FHIR API - Device Resource)
 * 
 * Dependencies:
 * - fs: File system operations
 * - path: Path manipulation
 * - crypto: RSA key pair generation (Epic Auth Guide - Key Generation)
 * - ini: Configuration file parsing
 * - axios: HTTP requests to Epic endpoints
 * - jsonwebtoken: JWT creation and signing
 * - uuid: Unique identifier generation for JWT jti claim
 * - csv: Patient roster and resources list parsing
 * - nodemailer: Email notifications via ProtonMail Bridge
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

const scriptName = path.basename(process.argv[1]);

let logger = null;

/**
 * Logger Class
 * ============
 * Handles logging to a file and directory listing
 */
class Logger {
    constructor() {
        const timestamp = new Date().toISOString();
        const divider = '\n' + '='.repeat(80) + '\n' + 
                       `New Session Started: ${timestamp}` + 
                       '\n' + '='.repeat(80) + '\n';
        
        this.indentLevel = 0;
        this.logStream = fs.createWriteStream('backend_epic.log', { flags: 'a' });
        
        // Append divider to log file
        this.logStream.write(divider);
        
        // Replace console.log with indented file logging
        const originalLog = console.log;
        console.log = (...args) => {
            const indent = '  '.repeat(this.indentLevel);
            const message = indent + util.format(...args) + '\n';
            this.logStream.write(message);
            originalLog(...args);
        };
        
        // Replace console.error with indented file logging
        const originalError = console.error;
        console.error = (...args) => {
            const indent = '  '.repeat(this.indentLevel);
            const message = indent + 'ERROR: ' + util.format(...args) + '\n';
            this.logStream.write(message);
            originalError(...args);
        };
    }

    clearExportDirectory() {
        const exportDir = 'epic_data_export';
        console.log(`\nClearing export directory: ${exportDir}`);
        
        if (fs.existsSync(exportDir)) {
            const files = fs.readdirSync(exportDir);
            files.forEach(file => {
                const filePath = path.join(exportDir, file);
                fs.unlinkSync(filePath);
                console.log(`Deleted: ${file}`);
            });
            console.log('Export directory cleared');
        } else {
            fs.mkdirSync(exportDir, { recursive: true });
            console.log('Created empty export directory');
        }
    }

    logReport(reportString) {
        const separator = '='.repeat(80);
        const content = `
${separator}
Observation Analysis Report
${separator}
${reportString}
${separator}
`;
        fs.appendFileSync('backend_epic.log', content);
    }
}

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

        // Make sure we're accessing the nested paths correctly
        this.privateKeyPath = path.resolve(config.paths.private_key);
        this.publicKeyPath = path.resolve(config.paths.public_key);
        this.base64PublicKeyPath = path.resolve(config.paths.base64_public_key);

        this.rsaKeySize = parseInt(config.rsa_settings.rsa_key_size) || 2048;
        this.rsaPublicEncoding = config.rsa_settings.rsa_public_encoding || 'spki';
        this.rsaPrivateEncoding = config.rsa_settings.rsa_private_encoding || 'pkcs8';
    }

    async generateKeyPair() {
        console.log('Checking for existing key pair...');
        
        if (!this.privateKeyPath) {
            throw new Error('Private key path is not defined in configuration');
        }

        const dir = path.dirname(this.privateKeyPath);
        if (!fs.existsSync(dir)) {
            console.log(`Creating directory: ${dir}`);
            fs.mkdirSync(dir, { recursive: true });
        }

        if (!fs.existsSync(this.privateKeyPath)) {
            console.log('Generating new RSA key pair...');
            
            const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
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

            fs.writeFileSync(this.privateKeyPath, privateKey);
            fs.writeFileSync(this.publicKeyPath, publicKey);
            
            const base64PublicKey = Buffer.from(publicKey).toString('base64');
            fs.writeFileSync(this.base64PublicKeyPath, base64PublicKey);
            
            console.log('Key pair generated and saved successfully');
        } else {
            console.log('Existing key pair found');
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

        this.privateKey = fs.readFileSync(config.paths.private_key, 'utf8');
        this.clientId = config.oauth_settings.client_id;
        this.tokenEndpoint = config.oauth_settings.token_endpoint;
        this.algorithm = config.jwt_settings.jwt_algorithm || 'RS384';
        this.expiryMinutes = parseInt(config.jwt_settings.jwt_expiry_minutes) || 5;
    }

    generateJWT() {
        console.log('Generating JWT...');
        
        const currentTime = Math.floor(Date.now() / 1000);
        const expiryMinutes = parseInt(this.expiryMinutes) || 5; // Default to 5 if not specified
        
        console.log(`Setting JWT expiry to ${expiryMinutes} minutes from now`);
        
        const claims = {
            iss: this.clientId,
            sub: this.clientId,
            aud: this.tokenEndpoint,
            jti: uuidv4(),
            exp: currentTime + (expiryMinutes * 60), // Convert minutes to seconds
            nbf: currentTime,
            iat: currentTime
        };

        console.log('JWT Claims:', claims);
        console.log(`JWT will expire at: ${new Date(claims.exp * 1000).toISOString()}`);

        const token = jwt.sign(claims, this.privateKey, {
            algorithm: this.algorithm,
            header: {
                alg: this.algorithm,
                typ: 'JWT'
            }
        });

        return token;
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
        this.jwtManager = new JWTManager(config);
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
    }

    async getAccessToken() {
        try {
            console.log('Requesting access token...');
            const jwt = await this.jwtManager.generateJWT();
            
            console.log('Using token endpoint:', this.tokenEndpoint);
            
            const response = await axios.post(this.tokenEndpoint, 
                new URLSearchParams({
                    grant_type: this.config.oauth_settings.grant_type,
                    client_assertion_type: this.config.oauth_settings.client_assertion_type,
                    client_assertion: jwt
                }), {
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
            console.error('Error getting access token from', this.tokenEndpoint + ':', error.message);
            throw error;
        }
    }

    async loadPatientRoster() {
        try {
            console.log('Loading patient roster from CSV...');
            const rosterPath = this.patientRosterPath;
            
            if (!fs.existsSync(rosterPath)) {
                throw new Error(`Patient roster file not found at: ${rosterPath}`);
            }

            const fileContent = fs.readFileSync(rosterPath, 'utf-8');
            const records = csv.parse(fileContent, {
                columns: true,
                skip_empty_lines: true
            });

            console.log(`Loaded ${records.length} patients from roster`);
            return records;
        } catch (error) {
            console.error('Error loading patient roster:', error.message);
            throw error;
        }
    }

    async loadResourcesList() {
        try {
            console.log('Loading resources list from CSV...');
            const resourcesPath = this.resourcesListPath;
            
            if (!fs.existsSync(resourcesPath)) {
                throw new Error(`Resources list file not found at: ${resourcesPath}`);
            }

            const fileContent = fs.readFileSync(resourcesPath, 'utf-8');
            const records = csv.parse(fileContent, {
                columns: true,
                skip_empty_lines: true
            });

            console.log(`Loaded ${records.length} resources from list`);
            return records;
        } catch (error) {
            console.error('Error loading resources list:', error.message);
            throw error;
        }
    }

    async getResourceData(accessToken, resourceType, patientId) {
        console.log(`Querying ${resourceType} data for patient ${patientId}...`);
        
        // Initialize query parameters
        const queryParams = new URLSearchParams({
            '_format': this.config.data_export.format,
            '_count': this.config.api_settings.page_size
        });

        // Build base URL
        const baseUrl = this.epicEndpoint.replace(/\/$/, '');
        let url;
        
        if (resourceType === 'Patient') {
            url = `${baseUrl}/Patient/${patientId}`;
        } else {
            url = `${baseUrl}/${resourceType}`;
            queryParams.append('patient', patientId);
            
            // Add category parameter for Observations
            if (resourceType === 'Observation') {
                queryParams.append('category', this.config.lab_data_category);
            }
        }

        try {
            let allResults = [];
            let nextUrl = `${url}?${queryParams.toString()}`;
            let pageCount = 0;

            while (nextUrl && pageCount < this.config.api_settings.max_pages) {
                pageCount++;
                console.log(`Page ${pageCount}: URL: ${nextUrl}`);
                
                const response = await axios.get(nextUrl, {
                    headers: {
                        'Authorization': `Bearer ${accessToken}`,
                        'Accept': this.config.data_export.format
                    }
                });

                // Handle single resource response (like Patient)
                if (!response.data.entry && response.data.resourceType === resourceType) {
                    allResults.push(response.data);
                    console.log('Retrieved single resource');
                    break;
                }

                // Handle bundle responses
                if (response.data.entry) {
                    const results = response.data.entry.map(e => e.resource);
                    allResults = allResults.concat(results);
                    console.log(`Retrieved ${results.length} results on this page`);
                }

                // Check for next page
                nextUrl = null;
                if (response.data.link) {
                    const nextLink = response.data.link.find(link => link.relation === 'next');
                    if (nextLink) {
                        nextUrl = nextLink.url;
                    }
                }
                
                if (!nextUrl) {
                    console.log('No more pages available');
                }
            }

            console.log(`Total ${resourceType} results retrieved: ${allResults.length}`);
            return allResults;

        } catch (error) {
            console.error(`Error fetching ${resourceType} for patient ${patientId}:`, {
                message: error.message,
                status: error.response?.status,
                data: error.response?.data
            });
            throw error;
        }
    }

    async saveResourceData(resourceType, data) {
        if (!data || data.length === 0) {
            return;
        }

        const timestamp = new Date().toISOString().replace(/:/g, '-');
        const fileName = `${resourceType}_data_${timestamp}.ndjson`;
        const filePath = path.join(this.config.paths.epic_data_export_folder, fileName);
        
        // Convert data to NDJSON format
        const ndjsonData = data.map(item => JSON.stringify(item)).join('\n');
        
        // Write to file
        fs.writeFileSync(filePath, ndjsonData);
        
        // Calculate file size in KB
        const stats = fs.statSync(filePath);
        const fileSizeInKB = (stats.size / 1024).toFixed(2);
        
        // Add to exported files list with full path
        this.exportedFiles.push({
            name: fileName,
            size: fileSizeInKB,
            path: filePath
        });
        
        console.log(`Exported ${data.length} records to: ${filePath}`);
    }

    async getResourceDataForPatient(resourceType, patientId, accessToken) {
        try {
            console.log(`Fetching ${resourceType} data for patient ${patientId}`);
            let url = `${this.epicEndpoint}${resourceType}`;
            const params = new URLSearchParams({
                _format: 'application/fhir+json',
                _count: this.config.api_settings.page_size
            });

            // Special handling for Patient resource
            if (resourceType === 'Patient') {
                url = `${this.epicEndpoint}Patient/${patientId}`;
            } 
            // Special handling for Observation resource
            else if (resourceType === 'Observation') {
                params.append('patient', patientId);
                params.append('category', 'vital-signs,laboratory');
                params.append('_sort', '-date');
            }
            // Default handling for other resources
            else {
                params.append('patient', patientId);
            }

            console.log(`Querying ${resourceType} data for patient ${patientId}...`);
            console.log(`Page 1: URL: ${url}?${params}`);

            const response = await axios.get(`${url}?${params}`, {
                headers: {
                    'Authorization': `Bearer ${accessToken}`,
                    'Accept': 'application/fhir+json'
                }
            });

            let results = [];
            
            if (response.data) {
                // Handle both array responses and single resource responses
                if (response.data.resourceType === 'Bundle' && Array.isArray(response.data.entry)) {
                    results = response.data.entry.map(entry => entry.resource);
                    console.log(`Retrieved ${results.length} results on this page`);
                } else if (response.data.resourceType === resourceType) {
                    results = [response.data];
                    console.log('Retrieved single resource');
                }
            }

            console.log(`Total ${resourceType} results retrieved: ${results.length}`);
            console.log(`Retrieved ${results.length} records for ${resourceType}`);

            return results;

        } catch (error) {
            const errorMessage = error.response?.data?.issue?.[0]?.details?.text || 
                               error.response?.data?.issue?.[0]?.diagnostics ||
                               error.message;
            console.error(`Error fetching ${resourceType} data for patient ${patientId}: ${errorMessage}`);
            return [];
        }
    }

    async getAllResourceData(accessToken) {
        try {
            this.exportedFiles = [];
            
            console.log('\nStarting data retrieval process...');
            const patients = await this.loadPatientRoster();
            const resources = await this.loadResourcesList();
            
            console.log('\nProcessing resources for each patient:');
            console.log('=====================================');
            
            for (const resource of resources) {
                console.log(`\nResource: ${resource.resource}`);
                console.log(`Description: ${resource.description}`);
                let allResourceResults = [];
                
                for (const patient of patients) {
                    console.log(`\n  Patient: ${patient.name} (${patient.fhir_id})`);
                    try {
                        const patientData = await this.getResourceDataForPatient(
                            resource.resource, 
                            patient.fhir_id, 
                            accessToken
                        );
                        if (patientData && patientData.length > 0) {
                            allResourceResults = allResourceResults.concat(patientData);
                            console.log(`  ✓ Retrieved ${patientData.length} records`);
                        } else {
                            console.log('  ✓ No records found');
                        }
                    } catch (error) {
                        console.error(`  ✗ Error: ${error.message}`);
                    }
                }
                
                if (allResourceResults.length > 0) {
                    await this.saveResourceData(resource.resource, allResourceResults);
                    console.log(`\n✓ Completed ${resource.resource}: ${allResourceResults.length} total records`);
                } else {
                    console.log(`\n- Skipped ${resource.resource}: No data found`);
                }
            }
            
            console.log('\nData Retrieval Summary');
            console.log('====================');
            this.logExportSummary(this.exportedFiles);
            
            return this.exportedFiles;
            
        } catch (error) {
            console.error('\nError in data retrieval process:', error.message);
            throw error;
        }
    }

    logExportSummary(files) {
        if (files.length === 0) {
            console.log('No files were exported');
            return;
        }
        
        console.log('\nExported Files Summary (Filename | Size | Path | Records)');
        console.log('================================================');
        files.forEach(file => {
            // Count lines in the file
            const content = fs.readFileSync(file.path, 'utf8');
            const lineCount = content.split('\n').filter(line => line.trim()).length;
            
            // Output pipe-delimited format with spaces
            console.log(`${file.name} | ${file.size} KB | ${file.path} | ${lineCount}`);
        });
    }
}

/**
 * Main Application Flow
 * ====================
 * Orchestrates the authentication and API request process:
 * 1. Load configuration
 * 2. Verify/generate key pair
 * 3. Initialize EPIC client
 * 4. Obtain access token
 * 5. Make sample FHIR API request
 * 
 * Error handling wraps the entire process to catch and log any failures
 */
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

    const exportDir = path.resolve(config.paths.epic_data_export_folder);
    const observationFile = getLatestObservationFile(exportDir);
    const observations = readNDJSON(observationFile);
    const patientStats = analyzeObservations(observations);
    const reportString = generateReport(patientStats);

    // Log the report
    console.log('\nObservation Analysis Report');
    console.log('=========================');
    console.log(reportString);

    const mailOptions = {
        from: config.email.notification_from,
        to: config.email.notification_to,
        subject: `EPIC FHIR Sync ${success ? 'Success' : 'Failed'}`,
        text: `
${scriptName} Report
${'='.repeat(scriptName.length + 7)}
Start Time: ${startTime}
End Time: ${endTime}
Duration: ${Math.round((new Date(endTime) - new Date(startTime))/1000)} seconds
Status: ${success ? 'Successful' : 'Failed'}

Observation Analysis Report
=========================
${reportString}

Export Directory:
${exportDir}

Exported Files:
    ${exportedFiles.map(file => `${file.name} (${file.size} KB)`).join('\n    ')}

Log File:
${path.resolve('backend_epic.log')}
        `
    };

    try {
        await transporter.sendMail(mailOptions);
        console.log('Completion email sent successfully');
        return { success: true, reportString };
    } catch (error) {
        console.error('Error sending email:', error);
        console.error('Error details:', error.message);
        return { success: false, reportString };
    }
}

function logExportSummary(files) {
    console.log('=== Begin Export Summary ===');
    files.forEach(file => {
        console.log(`Exported: ${file.name} (${file.size} KB)`);
    });
    console.log('=== End Export Summary ===');
}

// Function to read and parse NDJSON file
function readNDJSON(filePath) {
    const data = fs.readFileSync(filePath, 'utf8');
    return data.split('\n')
        .filter(line => line.trim() !== '') // Filter out empty lines
        .map(line => JSON.parse(line)); // Parse each line as JSON
}

// Function to get the latest Observation NDJSON file
function getLatestObservationFile(directory) {
    const files = fs.readdirSync(directory);
    const observationFiles = files.filter(file => file.startsWith('Observation_data_'));
    
    if (observationFiles.length === 0) {
        throw new Error('No Observation files found in the directory.');
    }

    // Sort files by timestamp in the filename
    observationFiles.sort((a, b) => {
        const timestampA = new Date(a.match(/_(\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}\.\d{3}Z)/)[1]);
        const timestampB = new Date(b.match(/_(\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}\.\d{3}Z)/)[1]);
        return timestampB - timestampA; // Sort descending
    });

    return path.join(directory, observationFiles[0]);
}

function analyzeObservations(observations) {
    // Define standard reference ranges
    const REFERENCE_RANGES = {
        'BP': '90-140/60-90',
        'Temp': '36.5-37.5',
        'Pulse': '60-100',
        'Cholesterol [Mass/volume] in Serum or Plasma': '<=200'
    };

    const patientStats = {};

    // Process each observation
    observations.forEach(obs => {
        try {
            if (obs.resourceType !== 'Observation') {
                return;
            }

            const observationId = obs.id;
            const observationType = obs.code?.coding?.[0]?.display || 'Unknown Type';
            
            // Get patient info
            let patientId, patientName;
            if (obs.subject?.reference) {
                patientId = obs.subject.reference.split('/')[1];
                patientName = obs.subject.display || 'Unknown Patient';
            } else {
                return;
            }
            
            // Initialize patient stats if not exists
            if (!patientStats[patientId]) {
                patientStats[patientId] = {
                    name: patientName,
                    normalCount: 0,
                    abnormalCount: 0,
                    normalObservations: [],
                    abnormalReadings: []
                };
            }

            // Handle different observation types
            let value, unit, referenceText;
            
            if (observationType === 'BP') {
                // Special handling for blood pressure
                const systolic = obs.component?.[0]?.valueQuantity?.value;
                const diastolic = obs.component?.[1]?.valueQuantity?.value;
                if (systolic && diastolic) {
                    value = `${systolic}/${diastolic}`;
                    unit = 'mmHg';
                    referenceText = '90-140/60-90';
                    const isAbnormal = systolic > 140 || systolic < 90 || diastolic > 90 || diastolic < 60;
                    const status = isAbnormal ? 'ABNORMAL' : 'NORMAL';
                    const observationDate = obs.effectiveDateTime || obs.issued || 'No date';
                    const formattedDate = observationDate !== 'No date' 
                        ? new Date(observationDate).toISOString().split('T')[0]
                        : observationDate;
                    
                    const observationRecord = {
                        observationId,
                        type: observationType,
                        value: `${value} ${unit}`,
                        referenceRange: referenceText,
                        status,
                        date: formattedDate  // Use the formatted date
                    };
                    if (isAbnormal) {
                        patientStats[patientId].abnormalCount++;
                        patientStats[patientId].abnormalReadings.push(observationRecord);
                    } else {
                        patientStats[patientId].normalCount++;
                        patientStats[patientId].normalObservations.push(observationRecord);
                    }
                }
                return;
            }

            // Handle other types of observations
            if (obs.valueQuantity) {
                value = obs.valueQuantity.value;
                unit = obs.valueQuantity.unit;

                // Get reference range - first try observation's own range
                if (obs.referenceRange && obs.referenceRange.length > 0) {
                    const range = obs.referenceRange[0];
                    referenceText = range.text || '';
                }

                // If no range in observation, use standard ranges
                if (!referenceText && REFERENCE_RANGES[observationType]) {
                    referenceText = REFERENCE_RANGES[observationType];
                }

                // Determine if value is abnormal based on reference range
                let status = 'NORMAL';
                if (referenceText) {
                    if (referenceText.includes('<=')) {
                        const highValue = parseFloat(referenceText.replace('<=', ''));
                        if (value > highValue) {
                            status = 'ABNORMAL (High)';
                        }
                    } else if (referenceText.includes('-')) {
                        const [low, high] = referenceText.split('-').map(Number);
                        if (value < low) {
                            status = 'ABNORMAL (Low)';
                        } else if (value > high) {
                            status = 'ABNORMAL (High)';
                        }
                    }
                }

                // Get the observation date - prefer effectiveDateTime, fall back to issued
                const observationDate = obs.effectiveDateTime || obs.issued || 'No date';
                // Format the date to be more readable
                const formattedDate = observationDate !== 'No date' 
                    ? new Date(observationDate).toISOString().split('T')[0]
                    : observationDate;

                // Create observation record with date
                const observationRecord = {
                    observationId,
                    type: observationType,
                    value: `${value}${unit ? ' ' + unit : ''}`,
                    referenceRange: referenceText || 'No range specified',
                    status,
                    date: formattedDate  // Add date to the record
                };

                if (status === 'NORMAL') {
                    patientStats[patientId].normalCount++;
                    patientStats[patientId].normalObservations.push(observationRecord);
                } else {
                    patientStats[patientId].abnormalCount++;
                    patientStats[patientId].abnormalReadings.push(observationRecord);
                }
            }

        } catch (error) {
            console.warn(`Error processing observation ${obs?.id || 'unknown'}: ${error.message}`);
        }
    });

    return patientStats;
}

// Function to generate report string
function generateReport(patientStats) {
    let reportString = '';
    
    // Summary section
    let totalNormal = 0;
    let totalAbnormal = 0;
    Object.values(patientStats).forEach(stats => {
        totalNormal += stats.normalCount;
        totalAbnormal += stats.abnormalCount;
    });

    reportString += `Summary:\n`;
    reportString += `---------\n`;
    reportString += `Total Observations: ${totalNormal + totalAbnormal}\n`;
    reportString += `Total Normal Readings: ${totalNormal}\n`;
    reportString += `Total Abnormal Readings: ${totalAbnormal}\n\n`;

    // Detailed Observations Header
    reportString += 'Detailed Observations:\n';
    reportString += '--------------------\n';
    reportString += 'Date | Patient Name | Patient ID | Observation Type | Value | Reference Range | Status\n';
    reportString += '-----|--------------|------------|------------------|--------|----------------|--------\n';

    // Patient-wise observations
    Object.entries(patientStats).forEach(([patientId, stats]) => {
        const allObservations = [...stats.normalObservations || [], ...stats.abnormalReadings || []];
        
        allObservations.forEach(obs => {
            reportString += `${obs.date} | `;  // Add date to the output
            reportString += `${stats.name} | `;
            reportString += `${patientId} | `;
            reportString += `${obs.type} | `;
            reportString += `${obs.value} | `;
            reportString += `${obs.referenceRange || 'N/A'} | `;
            reportString += `${obs.status || 'NORMAL'}\n`;
        });
    });

    return reportString;
}

async function main() {
    const startTime = new Date().toISOString();
    let success = false;
    let exportedFiles = [];
    let config = null;
    let logger = null;
    
    try {
        // Initialize logger first
        logger = new Logger();
        
        console.log(`Starting ${scriptName}...`);
        
        // Clear export directory before starting
        logger.clearExportDirectory();
        
        // Initialize configuration
        const configManager = new ConfigManager();
        config = await configManager.loadConfig();
        
        // Initialize key manager
        console.log('Initializing key manager...');
        const keyManager = new KeyManager(config);
        await keyManager.generateKeyPair();
        
        // Initialize EPIC client
        console.log('Initializing EPIC client...');
        const epicClient = new EpicClient(config);
        
        // Get access token
        console.log('Requesting access token...');
        const accessToken = await epicClient.getAccessToken();
        console.log('Access token received successfully');
        
        // Get data for all resources and patients
        console.log('Retrieving resource data...');
        exportedFiles = await epicClient.getAllResourceData(accessToken);
        
        success = true;
        console.log(`\n${scriptName} completed successfully`);

    } catch (error) {
        console.error('Application error:', error.message);
        if (error.response) {
            console.error('Response data:', error.response.data);
            console.error('Response status:', error.response.status);
        }
        success = false;
    } finally {
        const endTime = new Date().toISOString();
        if (config) {
            const result = await sendCompletionEmail(success, startTime, endTime, exportedFiles, config);
            if (logger && result?.reportString) {
                logger.logReport(result.reportString);
            }
        }
        
        if (!success) {
            process.exit(1);
        }
    }
}

// Application entry point
main();

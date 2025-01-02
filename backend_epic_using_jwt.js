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

const scriptName = path.basename(process.argv[1]);

let logger = null;

/**
 * Logger Class
 * ============
 * Handles logging to a file and directory listing with source file tracking
 */
class Logger {
    constructor() {
        const timestamp = new Date().toISOString();
        const divider = '\n' + '='.repeat(80) + '\n' + 
                       `New Session Started: ${timestamp}` + 
                       '\n' + '='.repeat(80) + '\n';
        
        this.logStream = fs.createWriteStream('backend_epic.log', { flags: 'a' });
        this.logStream.write(divider);
        
        // Replace console.log with file logging
        const originalLog = console.log;
        console.log = (...args) => {
            // Get the calling file from the stack trace
            const stack = new Error().stack;
            const callerFile = stack.split('\n')[2]?.match(/[\/\\]([\w-]+\.js)/)?.[1] || 'unknown.js';
            
            const message = util.format(...args);
            const logMessage = message.endsWith(']') ? 
                `${message}\n` : 
                `${message} [Source: ${callerFile}]\n`;
            
            this.logStream.write(logMessage);
            originalLog(...args);
        };
        
        // Replace console.error with file logging
        const originalError = console.error;
        console.error = (...args) => {
            // Get the calling file from the stack trace
            const stack = new Error().stack;
            const callerFile = stack.split('\n')[2]?.match(/[\/\\]([\w-]+\.js)/)?.[1] || 'unknown.js';
            
            const message = util.format(...args);
            const logMessage = `ERROR: ${message} [Source: ${callerFile}]\n`;
            
            this.logStream.write(logMessage);
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

    /**
     * Calculates the public key ID (thumbprint) using Epic's method.
     * This was determined through analysis comparing different methods against Epic's known thumbprint:
     * A9449062942DEBF66B8B48B131AC47C9189583F4 (from publickey509.pem/publickey509.b64)
     * 
     * The method follows RFC 5280 standard for certificate thumbprints:
     * 1. Take the DER-encoded form of the certificate/public key (from publickey509.pem)
     * 2. Calculate SHA-1 hash of the DER-encoded binary data
     * 3. Convert to uppercase hexadecimal
     * 
     * Key Files Used:
     * - publickey509.pem: X.509 certificate in PEM format
     * - publickey509.b64: Base64-encoded DER format (same certificate, different encoding)
     * Both files contain the same certificate and will generate the same thumbprint.
     * 
     * Verification process:
     * - Created analyze_key_id.js to test different methods
     * - Tested against both PEM and Base64 encoded certificates
     * - Confirmed that DER-encoded SHA-1 matches Epic's thumbprint
     * 
     * @param {string} publicKey - The public key in PEM format
     * @returns {string} The uppercase hexadecimal thumbprint
     */
    calculatePublicKeyId(publicKey) {
        // Remove PEM headers and newlines to get clean Base64
        const cleanContent = publicKey.toString()
            .replace(/-----BEGIN PUBLIC KEY-----/, '')
            .replace(/-----END PUBLIC KEY-----/, '')
            .replace(/-----BEGIN CERTIFICATE-----/, '')
            .replace(/-----END CERTIFICATE-----/, '')
            .replace(/\n/g, '');

        // Decode Base64 to get DER-encoded binary format
        const derBuffer = Buffer.from(cleanContent, 'base64');
        
        // Calculate SHA-1 hash of DER-encoded data
        const hash = crypto.createHash('sha1');
        hash.update(derBuffer);
        
        // Convert to uppercase hexadecimal
        return hash.digest('hex').toUpperCase();
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

        let publicKey;
        if (!fs.existsSync(this.privateKeyPath)) {
            console.log('Generating new RSA key pair...');
            
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
            console.log(`Key pair generated and saved successfully (Public Key ID: ${publicKeyId} from ${path.basename(this.publicKeyPath)})`);
        } else {
            publicKey = fs.readFileSync(this.publicKeyPath, 'utf8');
            const publicKeyId = this.calculatePublicKeyId(publicKey);
            console.log(`Existing key pair found (Public Key ID: ${publicKeyId} from ${path.basename(this.publicKeyPath)})`);
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
        // Calculate public key ID from the corresponding public key
        const publicKey = fs.readFileSync(this.config.paths.public_key, 'utf8');
        const publicKeyId = crypto.createHash('sha1')
            .update(Buffer.from(publicKey.replace(/-----BEGIN (?:PUBLIC KEY|CERTIFICATE)-----|\n|-----END (?:PUBLIC KEY|CERTIFICATE)-----/g, ''), 'base64'))
            .digest('hex')
            .toUpperCase();

        console.log('\n=== JWT Generation Tutorial ===');
        console.log('Step 1: Preparing JWT Claims');
        console.log('----------------------------');
        
        const currentTime = Math.floor(Date.now() / 1000);
        const expiryMinutes = parseInt(this.expiryMinutes) || 5;
        const expiryTime = currentTime + (expiryMinutes * 60);
        
        console.log('• Setting up timestamps:');
        console.log(`  - Current time (iat): EPOCH=${currentTime} | Human=${new Date(currentTime * 1000).toISOString()}`);
        console.log(`  - Not Before (nbf): EPOCH=${currentTime} | Human=${new Date(currentTime * 1000).toISOString()} (same as iat)`);
        console.log(`  - Expiry time (exp): EPOCH=${expiryTime} | Human=${new Date(expiryTime * 1000).toISOString()} (iat + ${expiryMinutes} minutes)`);
        console.log(`  - Token validity window: ${expiryMinutes} minutes from issuance to allow time for token retrieval and API calls`);
        
        const claims = {
            iss: this.clientId,
            sub: this.clientId,
            aud: this.tokenEndpoint,
            jti: uuidv4(),
            exp: expiryTime,
            nbf: currentTime,
            iat: currentTime
        };

        console.log('\nStep 2: JWT Claims Structure');
        console.log('-------------------------');
        console.log('• Required claims for Epic:');
        console.log(`  - iss (Issuer): ${claims.iss}`);
        console.log(`  - sub (Subject): ${claims.sub} (same as Issuer for backend services)`);
        console.log(`  - aud (Audience): ${claims.aud}`);
        console.log(`  - jti (JWT ID): ${claims.jti} (random unique identifier)`);
        console.log(`  - exp (Expiration): EPOCH=${claims.exp} | Human=${new Date(claims.exp * 1000).toISOString()} (iat + ${expiryMinutes} min window)`);
        console.log(`  - nbf (Not Before): EPOCH=${claims.nbf} | Human=${new Date(claims.nbf * 1000).toISOString()} (current time)`);
        console.log(`  - iat (Issued At): EPOCH=${claims.iat} | Human=${new Date(claims.iat * 1000).toISOString()} (current time)`);

        console.log('\n• Actual JWT Claims (JSON):');
        console.log(JSON.stringify(claims, null, 2));

        console.log('\nStep 3: Signing JWT');
        console.log('------------------');
        console.log(`• Algorithm: ${this.algorithm}`);
        // Get first 15 characters of the private key (after the header), removing all newlines
        const privateKeyPreview = this.privateKey
            .replace(/-----BEGIN PRIVATE KEY-----/, '')
            .replace(/-----END PRIVATE KEY-----/, '')
            .replace(/\n/g, '')
            .substring(0, 15);
        console.log(`• Using private key to sign JWT... (Private Key starting with "${privateKeyPreview}" paired with Public Key ID: ${publicKeyId} from ${path.basename(this.config.paths.public_key)})`);

        const token = jwt.sign(claims, this.privateKey, {
            algorithm: this.algorithm,
            header: {
                alg: this.algorithm,
                typ: 'JWT'
            }
        });

        console.log('\n• Generated JWT Token:');
        console.log('---------------------');
        const [header, payload, signature] = token.split('.');
        console.log('Header (decoded):');
        console.log(JSON.stringify(JSON.parse(Buffer.from(header, 'base64').toString()), null, 2));
        console.log('\nPayload (decoded):');
        console.log(JSON.stringify(JSON.parse(Buffer.from(payload, 'base64').toString()), null, 2));
        console.log('\nComplete JWT Token (used in request):');
        console.log(token);

        console.log('\n✓ JWT successfully generated and signed');
        console.log('===============================\n');

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
            console.log('\n=== Epic OAuth 2.0 Token Request Tutorial ===');
            console.log('Step 1: JWT Assertion Generation');
            console.log('--------------------------------');
            const jwt = await this.jwtManager.generateJWT();
            
            console.log('\nStep 2: Preparing Token Request');
            console.log('------------------------------');
            console.log('• Endpoint:', this.tokenEndpoint);
            console.log('• Grant Type:', this.config.oauth_settings.grant_type);
            console.log('• Client Assertion Type:', this.config.oauth_settings.client_assertion_type);
            
            console.log('\nStep 3: Sending Token Request');
            console.log('----------------------------');
            console.log('• Making POST request to Epic\'s token endpoint...');
            
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

            console.log('✓ Access token received successfully');
            console.log('• Token type:', response.data.token_type);
            console.log('• Expires in:', response.data.expires_in, 'seconds');
            console.log('=========================================\n');

            return response.data.access_token;
        } catch (error) {
            console.error('\n❌ Error in token request process:');
            console.error('• Error message:', error.message);
            if (error.response) {
                console.error('• Response status:', error.response.status);
                console.error('• Response data:', JSON.stringify(error.response.data, null, 2));
            }
            console.error('=========================================\n');
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
                console.log(`\nPage ${pageCount} URL Details:`);
                console.log('------------------');
                console.log('Human readable URL:');
                console.log(`${url}?${decodeURIComponent(queryParams.toString())}`);
                console.log('\nActual URL used (encoded):');
                console.log(nextUrl);
                
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
                        // If there's a next page, show its URL preview
                        if (nextUrl) {
                            console.log('\nNext page URL preview:');
                            console.log('Human readable:');
                            console.log(decodeURIComponent(nextUrl));
                            console.log('\nEncoded:');
                            console.log(nextUrl);
                        }
                    }
                }
                
                if (!nextUrl) {
                    console.log('\nNo more pages available');
                }
            }

            console.log(`\nTotal ${resourceType} results retrieved: ${allResults.length}`);
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
            // Remove the redundant patient logging since it's now handled in getAllResourceData
            let url = `${this.epicEndpoint}${resourceType}`;
            const params = new URLSearchParams({
                _format: 'application/fhir+json',
                _count: this.config.api_settings.page_size
            });

            if (resourceType === 'Patient') {
                url = `${this.epicEndpoint}Patient/${patientId}`;
            } 
            else if (resourceType === 'Observation') {
                params.append('patient', patientId);
                params.append('category', 'vital-signs,laboratory');
                params.append('_sort', '-date');
            }
            else {
                params.append('patient', patientId);
            }

            // Log the actual API request being made
            console.log(`  • Querying Epic's FHIR API: ${url}?${params}`);

            const response = await axios.get(`${url}?${params}`, {
                headers: {
                    'Authorization': `Bearer ${accessToken}`,
                    'Accept': 'application/fhir+json'
                }
            });

            let results = [];
            
            if (response.data) {
                if (response.data.resourceType === 'Bundle' && Array.isArray(response.data.entry)) {
                    results = response.data.entry.map(entry => entry.resource);
                    console.log(`  • Retrieved ${results.length} results`);
                } else if (response.data.resourceType === resourceType) {
                    results = [response.data];
                    console.log('  • Retrieved single resource');
                }
            }

            console.log(`  ✓ Total ${resourceType} results: ${results.length}`);
            return results;

        } catch (error) {
            console.error(`  ✗ Error: ${error.message}`);
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
                    // Single patient log entry with both name and ID
                    console.log(`\n  Processing: ${patient.name} (ID: ${patient.fhir_id})`);
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

    let reportString = '';
    const exportDir = path.resolve(config.paths.epic_data_export_folder);
    
    try {
        const observationFile = getLatestObservationFile(exportDir);
        const observations = readNDJSON(observationFile);
        const patientStats = analyzeObservations(observations);
        reportString = generateReport(patientStats);

        // Log the report
        console.log('\nObservation Analysis Report');
        console.log('=========================');
        console.log(reportString);
    } catch (error) {
        console.log('No observation data available for analysis yet');
        reportString = 'No observation data available for analysis.';
    }

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
        const timestampA = new Date(a.match(/_(\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}\.\d{3}Z)/)?.[1] || '');
        const timestampB = new Date(b.match(/_(\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}\.\d{3}Z)/)?.[1] || '');
        return timestampB - timestampA; // Sort descending
    });

    return path.join(directory, observationFiles[0]);
}

// Define standard reference ranges with LOINC codes
const VITAL_SIGNS_RANGES = {
    'BP': {
        systolic: { min: 90, max: 140 },
        diastolic: { min: 60, max: 90 }
    },
    'Temp': { min: 36.5, max: 37.5 },
    'Pulse': { min: 60, max: 100 }
};

const LAB_REFERENCE_RANGES = {
    'Cholesterol [Mass/volume] in Serum or Plasma': {
        type: 'max',
        value: 200,
        unit: 'mg/dL'
    }
};

// LOINC code mapping for vital signs
const VITAL_SIGNS_CODE_MAP = {
    // BP codes
    '55284-4': 'BP',       // Blood pressure systolic and diastolic
    '85354-9': 'BP',       // Blood pressure panel
    '8480-6': 'BP',        // Systolic blood pressure
    '8462-4': 'BP',        // Diastolic blood pressure
    
    // Temperature codes
    '8310-5': 'Temp',      // Body temperature
    
    // Pulse codes
    '8867-4': 'Pulse'      // Heart rate
};

function analyzeObservations(observations) {
    const patientStats = {};

    observations.forEach(obs => {
        try {
            if (obs.resourceType !== 'Observation') {
                return;
            }

            // Get patient info
            const patientId = obs.subject?.reference?.split('/')[1];
            const patientName = obs.subject?.display || 'Unknown Patient';
            
            if (!patientId) {
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

            // Determine observation type
            let observationType = null;
            const observationId = obs.id;

            // Try to identify type from code.text
            if (['BP', 'Temp', 'Pulse'].includes(obs.code?.text)) {
                observationType = obs.code.text;
            }

            // If type is still null, search coding for known codes
            if (!observationType) {
                const codingArray = obs.code?.coding || [];
                for (const coding of codingArray) {
                    if (VITAL_SIGNS_CODE_MAP[coding.code]) {
                        observationType = VITAL_SIGNS_CODE_MAP[coding.code];
                        break;
                    }
                }
            }

            // Get observation date
            const dateField = obs.effectiveDateTime || 
                            obs.effectivePeriod?.start || 
                            obs.effectiveInstant || 
                            obs.issued || 
                            obs.meta?.lastUpdated || 
                            obs.date || 
                            obs.performedDateTime || 
                            obs.performedPeriod?.start || 
                            obs.recordedDate;

            const formattedDate = dateField ? 
                new Date(dateField).toISOString().split('T')[0] : 
                'No date';

            // Handle BP observations
            if (observationType === 'BP') {
                const systolicComponent = obs.component?.find(comp =>
                    comp.code?.coding?.some(coding => coding.code === '8480-6')
                );
                const diastolicComponent = obs.component?.find(comp =>
                    comp.code?.coding?.some(coding => coding.code === '8462-4')
                );

                const systolic = systolicComponent?.valueQuantity?.value;
                const diastolic = diastolicComponent?.valueQuantity?.value;

                if (systolic && diastolic) {
                    const ranges = VITAL_SIGNS_RANGES.BP;
                    const isAbnormal =
                        systolic > ranges.systolic.max ||
                        systolic < ranges.systolic.min ||
                        diastolic > ranges.diastolic.max ||
                        diastolic < ranges.diastolic.min;

                    const observationRecord = {
                        observationId,
                        type: observationType,
                        value: `${systolic}/${diastolic} mmHg`,
                        referenceRange: '90-140/60-90',
                        status: isAbnormal ? 'ABNORMAL' : 'NORMAL',
                        date: formattedDate
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

            // Handle other vital signs and lab results
            if (obs.valueQuantity) {
                const value = obs.valueQuantity.value;
                const unit = obs.valueQuantity.unit;
                let referenceText = '';
                let status = 'NORMAL';

                // Get reference range based on observation type
                if (observationType && VITAL_SIGNS_RANGES[observationType]) {
                    const range = VITAL_SIGNS_RANGES[observationType];
                    referenceText = `${range.min}-${range.max}`;
                    if (value < range.min) {
                        status = 'ABNORMAL (Low)';
                    } else if (value > range.max) {
                        status = 'ABNORMAL (High)';
                    }
                } else if (LAB_REFERENCE_RANGES[obs.code?.coding?.[0]?.display]) {
                    const range = LAB_REFERENCE_RANGES[obs.code.coding[0].display];
                    referenceText = `<=${range.value} ${range.unit}`;
                    if (value > range.value) {
                        status = 'ABNORMAL (High)';
                    }
                } else if (obs.referenceRange?.[0]) {
                    referenceText = obs.referenceRange[0].text || '';
                }

                const observationRecord = {
                    observationId,
                    type: observationType || obs.code?.coding?.[0]?.display || 'Unknown Type',
                    value: `${value}${unit ? ' ' + unit : ''}`,
                    referenceRange: referenceText || 'No range specified',
                    status,
                    date: formattedDate
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
            console.warn(`Error processing observation ${obs?.id || 'unknown'}: ${error.message} [Source: backend_epic_using_jwt.js]`);
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
        
        // Initialize configuration
        const configManager = new ConfigManager();
        config = await configManager.loadConfig();
        
        // Clear export directory
        const exportDir = config.paths.epic_data_export_folder;
        console.log(`\nClearing export directory: ${exportDir}`);
        await logger.clearExportDirectory();
        
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
            if (!success) {
                process.exit(1);
            }
        }
    }
}

// Application entry point
main();

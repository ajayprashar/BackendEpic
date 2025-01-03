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

// Create a single logger instance
let loggerInstance = null;

class Logger {
    constructor() {
        if (loggerInstance) {
            return loggerInstance;
        }
        
        this.LOG_FILE = 'backend_epic.log';
        this.MAX_LOG_SIZE = 10 * 1024 * 1024; // 10MB
        this.logStream = null;
        this.initialized = false;
        this.recentMessages = new Set(); // Track recent messages to prevent duplicates
        this.recentMessageTimeout = 1000; // Clear messages after 1 second
        this.initializeLogStream();
        
        loggerInstance = this;
        return loggerInstance;
    }

    initializeLogStream() {
        if (this.initialized) {
            return;
        }

        try {
            // Check if log file needs rotation
            if (fs.existsSync(this.LOG_FILE)) {
                const stats = fs.statSync(this.LOG_FILE);
                if (stats.size >= this.MAX_LOG_SIZE) {
                    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
                    fs.renameSync(this.LOG_FILE, `${this.LOG_FILE}.${timestamp}`);
                }
            }

            // Create write stream and set up console overrides
            this.logStream = fs.createWriteStream(this.LOG_FILE, { flags: 'a' });
            this.setupConsoleOverrides();

            // Write session start directly to stream to avoid duplication
            const timestamp = new Date().toISOString();
            this.logStream.write([
                '',
                '='.repeat(80),
                `New Session Started: ${timestamp}`,
                '='.repeat(80),
                '',
                ''
            ].join('\n'));

            this.initialized = true;
        } catch (error) {
            console.error(`Failed to initialize log stream: ${error.message}`);
            throw error;
        }
    }

    setupConsoleOverrides() {
        const originalLog = console.log;
        const originalWarn = console.warn;
        const originalError = console.error;

        console.log = (...args) => this.writeLog('INFO', args, originalLog);
        console.warn = (...args) => this.writeLog('WARN', args, originalWarn);
        console.error = (...args) => this.writeLog('ERROR', args, originalError);
    }

    getCallerInfo() {
        const stack = new Error().stack;
        const callerLine = stack.split('\n')[3]; // Skip 3 lines to get actual caller
        const match = callerLine?.match(/[\/\\]([\w-]+\.js):(\d+):(\d+)/);
        
        return {
            file: match?.[1] || 'unknown.js',
            line: match?.[2] || '?',
            column: match?.[3] || '?'
        };
    }

    formatMessage(level, args) {
        const timestamp = new Date().toISOString();
        
        // Format any JSON objects in the message
        const formattedArgs = args.map(arg => {
            if (typeof arg === 'object' && arg !== null) {
                return '\n' + JSON.stringify(arg, null, 2) + '\n';
            }
            return String(arg);
        });
        
        // Join all arguments with spaces and trim any extra whitespace
        let message = formattedArgs.join(' ').trim();
        
        // Remove redundant level prefix if it exists
        message = message.replace(new RegExp(`^${level}:\\s*`, 'i'), '');
        
        // For tutorial content, return as is without any prefixes
        if (level === 'TUTORIAL') {
            return message;
        }
        
        // For regular log messages, only add timestamp for errors
        if (level === 'ERROR') {
            return `[${timestamp}] ${message}`;
        }
        
        // Check for duplicate messages
        const messageKey = `${level}:${message}`;
        if (this.recentMessages.has(messageKey)) {
            return null; // Skip duplicate message
        }
        
        // Add message to recent set and schedule cleanup
        this.recentMessages.add(messageKey);
        setTimeout(() => {
            this.recentMessages.delete(messageKey);
        }, this.recentMessageTimeout);
        
        return message;
    }

    writeLog(level, args, originalMethod) {
        try {
            const formattedMessage = this.formatMessage(level, args);
            
            // Skip if message is null (duplicate) or empty
            if (!formattedMessage) {
                return;
            }
            
            // Write to file with newline
            this.logStream.write(formattedMessage + '\n');
            
            // Write to console with color
            switch (level) {
                case 'WARN':
                    originalMethod('\x1b[33m' + formattedMessage + '\x1b[0m'); // Yellow
                    break;
                case 'ERROR':
                    originalMethod('\x1b[31m' + formattedMessage + '\x1b[0m'); // Red
                    break;
                default:
                    originalMethod(formattedMessage);
            }
        } catch (error) {
            // Fallback to original console if logging fails
            originalMethod(...args);
            originalMethod(`Logger error: ${error.message}`);
        }
    }

    clearExportDirectory() {
        const exportDir = 'epic_data_export';
        
        try {
            if (fs.existsSync(exportDir)) {
                const files = fs.readdirSync(exportDir);
                files.forEach(file => {
                    try {
                        fs.unlinkSync(path.join(exportDir, file));
                    } catch (error) {
                        console.error(`Failed to delete file ${file}: ${error.message}`);
                    }
                });
            } else {
                fs.mkdirSync(exportDir, { recursive: true });
            }
            console.log('Export directory prepared');
        } catch (error) {
            console.error(`Failed to prepare export directory: ${error.message}`);
            throw error;
        }
    }

    close() {
        if (this.logStream) {
            this.logStream.end('\n=== End of Session ===\n');
            this.logStream.close();
        }
    }

    // Static method to get logger instance
    static getInstance() {
        if (!loggerInstance) {
            loggerInstance = new Logger();
        }
        return loggerInstance;
    }
}

// Create a single logger instance
const logger = Logger.getInstance();

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

// Export logger instance
module.exports = logger;

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
        this.logger = Logger.getInstance();
    }

    async getAccessToken() {
        try {
            const logger = Logger.getInstance();
            
            // Tutorial header
            logger.writeLog('TUTORIAL', ['\n================================================================================'], console.log);
            logger.writeLog('TUTORIAL', ['                         Epic OAuth 2.0 Token Request Tutorial                   '], console.log);
            logger.writeLog('TUTORIAL', ['================================================================================\n'], console.log);

            logger.writeLog('TUTORIAL', ['STEP 1: JWT ASSERTION GENERATION'], console.log);
            logger.writeLog('TUTORIAL', ['--------------------------------------------------------------------------------'], console.log);
            
            // Generate JWT with claims
            const currentTime = Math.floor(Date.now() / 1000);
            const expiryTime = currentTime + (this.expiryMinutes * 60);
            
            logger.writeLog('TUTORIAL', ['Timestamp Configuration:'], console.log);
            logger.writeLog('TUTORIAL', [`  Current time (iat): ${new Date(currentTime * 1000).toISOString()}`], console.log);
            logger.writeLog('TUTORIAL', [`  Not Before (nbf) : ${new Date(currentTime * 1000).toISOString()}`], console.log);
            logger.writeLog('TUTORIAL', [`  Expiry time (exp): ${new Date(expiryTime * 1000).toISOString()}`], console.log);
            logger.writeLog('TUTORIAL', [`  Token validity   : ${this.expiryMinutes} minutes\n`], console.log);
            
            const claims = {
                iss: this.clientId,
                sub: this.clientId,
                aud: this.tokenEndpoint,
                jti: uuidv4(),
                exp: expiryTime,
                nbf: currentTime,
                iat: currentTime
            };

            logger.writeLog('TUTORIAL', ['JWT Claims:'], console.log);
            logger.writeLog('TUTORIAL', ['\n', claims, '\n'], console.log);
            
            logger.writeLog('TUTORIAL', ['Required Claims Explanation:'], console.log);
            logger.writeLog('TUTORIAL', ['  iss (Issuer)  : Client ID assigned by Epic'], console.log);
            logger.writeLog('TUTORIAL', ['  sub (Subject) : Same as Issuer for backend services'], console.log);
            logger.writeLog('TUTORIAL', ['  aud (Audience): Epic\'s token endpoint'], console.log);
            logger.writeLog('TUTORIAL', ['  jti (JWT ID)  : Unique identifier for this JWT'], console.log);
            logger.writeLog('TUTORIAL', ['  exp          : Expiration time'], console.log);
            logger.writeLog('TUTORIAL', ['  nbf          : Not valid before time'], console.log);
            logger.writeLog('TUTORIAL', ['  iat          : Time when JWT was issued\n'], console.log);

            // Generate JWT silently (without additional logging)
            const jwt = this.generateJWTSilent();
            
            logger.writeLog('TUTORIAL', ['STEP 2: PREPARING TOKEN REQUEST'], console.log);
            logger.writeLog('TUTORIAL', ['--------------------------------------------------------------------------------'], console.log);
            logger.writeLog('TUTORIAL', ['Request Configuration:'], console.log);
            logger.writeLog('TUTORIAL', [`  Token Endpoint       : ${this.tokenEndpoint}`], console.log);
            logger.writeLog('TUTORIAL', [`  Grant Type          : ${this.config.oauth_settings.grant_type}`], console.log);
            logger.writeLog('TUTORIAL', [`  Client Assertion Type: ${this.config.oauth_settings.client_assertion_type}\n`], console.log);
            
            const requestBody = {
                grant_type: this.config.oauth_settings.grant_type,
                client_assertion_type: this.config.oauth_settings.client_assertion_type,
                client_assertion: jwt
            };
            
            logger.writeLog('TUTORIAL', ['Request Body:'], console.log);
            logger.writeLog('TUTORIAL', ['\n', requestBody, '\n'], console.log);
            
            logger.writeLog('TUTORIAL', ['STEP 3: SENDING TOKEN REQUEST'], console.log);
            logger.writeLog('TUTORIAL', ['--------------------------------------------------------------------------------'], console.log);
            logger.writeLog('TUTORIAL', ['Understanding the Token Request Process:'], console.log);
            logger.writeLog('TUTORIAL', ['\n1. What happens when we send this request:'], console.log);
            logger.writeLog('TUTORIAL', ['   • Our JWT (shown above) is sent to Epic\'s authorization server'], console.log);
            logger.writeLog('TUTORIAL', ['   • The JWT contains our identity claims and is signed with our private key'], console.log);
            logger.writeLog('TUTORIAL', ['   • Epic\'s server receives our request and begins the validation process'], console.log);
            logger.writeLog('TUTORIAL', ['\n2. How Epic validates our request:'], console.log);
            logger.writeLog('TUTORIAL', ['   • Epic retrieves our registered public key using the key ID in the JWT header'], console.log);
            logger.writeLog('TUTORIAL', ['   • They verify the JWT\'s signature using this public key'], console.log);
            logger.writeLog('TUTORIAL', ['   • They check the JWT\'s claims (expiry time, issuer, etc.)'], console.log);
            logger.writeLog('TUTORIAL', ['\n3. What happens after successful validation:'], console.log);
            logger.writeLog('TUTORIAL', ['   • Epic generates a new access token specifically for our session'], console.log);
            logger.writeLog('TUTORIAL', ['   • This token grants us access to Epic\'s FHIR API endpoints'], console.log);
            logger.writeLog('TUTORIAL', ['   • The token will be valid for 60 minutes'], console.log);
            logger.writeLog('TUTORIAL', ['   • We must include this token in all subsequent API requests'], console.log);
            logger.writeLog('TUTORIAL', ['\nNow sending the request with these parameters:'], console.log);
            logger.writeLog('TUTORIAL', ['• URL: ' + this.tokenEndpoint], console.log);
            logger.writeLog('TUTORIAL', ['• Method: POST'], console.log);
            logger.writeLog('TUTORIAL', ['• Headers:'], console.log);
            logger.writeLog('TUTORIAL', ['    Content-Type: application/x-www-form-urlencoded'], console.log);
            logger.writeLog('TUTORIAL', ['• Request Body Parameters:'], console.log);
            logger.writeLog('TUTORIAL', ['    1. grant_type: client_credentials'], console.log);
            logger.writeLog('TUTORIAL', ['    2. client_assertion_type: JWT Bearer Token'], console.log);
            logger.writeLog('TUTORIAL', ['    3. client_assertion: [Generated JWT containing claims shown above]\n'], console.log);
            
            const response = await axios.post(this.tokenEndpoint, 
                new URLSearchParams(requestBody), 
                {
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded'
                    }
                }
            );

            if (!response.data.access_token) {
                throw new Error('No access token received in response');
            }

            logger.writeLog('TUTORIAL', ['STEP 4: TOKEN RESPONSE'], console.log);
            logger.writeLog('TUTORIAL', ['--------------------------------------------------------------------------------'], console.log);
            logger.writeLog('TUTORIAL', ['✓ Access token received successfully'], console.log);
            logger.writeLog('TUTORIAL', ['================================================================================\n'], console.log);

            return response.data.access_token;
        } catch (error) {
            const logger = Logger.getInstance();
            logger.writeLog('ERROR', ['❌ Error in token request process:'], console.error);
            logger.writeLog('ERROR', ['--------------------------------------------------------------------------------'], console.error);
            logger.writeLog('ERROR', ['Error Details:'], console.error);
            logger.writeLog('ERROR', ['\n', {
                message: error.message,
                status: error.response?.status,
                data: error.response?.data
            }, '\n'], console.error);
            logger.writeLog('ERROR', ['================================================================================\n'], console.error);
            throw error;
        }
    }

    // Silent version of generateJWT that doesn't output tutorial messages
    generateJWTSilent() {
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
            header: header
        });
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
            const accessToken = await this.jwtManager.getAccessToken();
            return accessToken;
        } catch (error) {
            throw error;
        }
    }

    async loadPatientRoster() {
        try {
            const rosterPath = this.patientRosterPath;
            
            if (!fs.existsSync(rosterPath)) {
                throw new Error(`Patient roster file not found at: ${rosterPath}`);
            }

            const fileContent = fs.readFileSync(rosterPath, 'utf-8');
            const records = csv.parse(fileContent, {
                columns: true,
                skip_empty_lines: true
            });

            return records;
        } catch (error) {
            logger.writeLog('ERROR', ['Error loading patient roster:', error.message], console.error);
            throw error;
        }
    }

    async loadResourcesList() {
        try {
            const resourcesPath = this.resourcesListPath;
            
            if (!fs.existsSync(resourcesPath)) {
                throw new Error(`Resources list file not found at: ${resourcesPath}`);
            }

            const fileContent = fs.readFileSync(resourcesPath, 'utf-8');
            const records = csv.parse(fileContent, {
                columns: true,
                skip_empty_lines: true
            });

            return records;
        } catch (error) {
            logger.writeLog('ERROR', ['Error loading resources list:', error.message], console.error);
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
        
        // Add to exported files list
        this.exportedFiles.push({
            name: fileName,
            size: fileSizeInKB,
            path: filePath
        });
    }

    async getResourceDataForPatient(resourceType, patientId, accessToken) {
        try {
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
                } else if (response.data.resourceType === resourceType) {
                    results = [response.data];
                }
            }

            return results;

        } catch (error) {
            throw error;
        }
    }

    async getAllResourceData(accessToken) {
        const logger = Logger.getInstance();
        try {
            this.exportedFiles = [];
            
            const patients = await this.loadPatientRoster();
            const resources = await this.loadResourcesList();
            
            logger.writeLog('INFO', ['\nProcessing Resources'], console.log);
            
            for (const resource of resources) {
                let allResourceResults = [];
                
                // Process each patient silently
                for (const patient of patients) {
                    try {
                        const patientData = await this.getResourceDataForPatient(
                            resource.resource, 
                            patient.fhir_id, 
                            accessToken
                        );
                        
                        if (patientData && patientData.length > 0) {
                            allResourceResults = allResourceResults.concat(patientData);
                        }
                    } catch (error) {
                        logger.writeLog('ERROR', [`Error processing ${resource.resource} for patient ${patient.fhir_id}: ${error.message}`], console.error);
                    }
                }
                
                // Only log once when we have results
                if (allResourceResults.length > 0) {
                    await this.saveResourceData(resource.resource, allResourceResults);
                    // Use process.stdout.write to ensure atomic write
                    process.stdout.write(`${resource.resource} (${resource.description}): ${allResourceResults.length} records exported\n`);
                }
            }
            
            // Log completion once at the end
            logger.writeLog('INFO', [`\n${scriptName} completed successfully`], console.log);
            
            return this.exportedFiles;
            
        } catch (error) {
            logger.writeLog('ERROR', ['Error in data retrieval process:', error.message], console.error);
            throw error;
        }
    }

    logExportSummary(files) {
        if (files.length === 0) {
            console.log('No files were exported');
            return;
        }
        
        console.log('\nExported Files Summary');
        console.log('=====================');
        files.forEach(file => {
            // Count lines in the file
            const content = fs.readFileSync(file.path, 'utf8');
            const lineCount = content.split('\n').filter(line => line.trim()).length;
            
            console.log(`${file.name} | ${file.size} KB | ${lineCount} records`);
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
        
        // Log the observation report to the file
        console.log('\nObservation Analysis Report');
        console.log('=========================');
        console.log(reportString);
    } catch (error) {
        reportString = 'No observation data available for analysis.';
        console.log('\nObservation Analysis Report');
        console.log('=========================');
        console.log(reportString);
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
        console.error(`Error sending email: ${error.message}`);
        return { success: false, reportString };
    }
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
        diastolic: { min: 60, max: 90 },
        unit: 'mmHg'
    },
    'Temp': { 
        min: 36.5, 
        max: 37.5,
        unit: '°C'
    },
    'Pulse': { 
        min: 60, 
        max: 100,
        unit: 'bpm'
    }
};

const LAB_REFERENCE_RANGES = {
    'Cholesterol [Mass/volume] in Serum or Plasma': {
        type: 'max',
        value: 200,
        unit: 'mg/dL'
    }
};

// LOINC code mapping for vital signs with descriptions
const VITAL_SIGNS_CODE_MAP = {
    // BP codes
    '55284-4': { type: 'BP', description: 'Blood pressure systolic and diastolic' },
    '85354-9': { type: 'BP', description: 'Blood pressure panel' },
    '8480-6':  { type: 'BP', description: 'Systolic blood pressure' },
    '8462-4':  { type: 'BP', description: 'Diastolic blood pressure' },
    
    // Temperature codes
    '8310-5':  { type: 'Temp', description: 'Body temperature' },
    
    // Pulse codes
    '8867-4':  { type: 'Pulse', description: 'Heart rate' }
};

function getObservationType(observation) {
    // Try to identify type from code.text
    if (observation.code?.text && ['BP', 'Temp', 'Pulse'].includes(observation.code.text)) {
        return observation.code.text;
    }

    // Search coding for known codes
    const codingArray = observation.code?.coding || [];
    for (const coding of codingArray) {
        const mappedCode = VITAL_SIGNS_CODE_MAP[coding.code];
        if (mappedCode) {
            return mappedCode.type;
        }
    }

    return observation.code?.coding?.[0]?.display || 'Unknown Type';
}

function getObservationDate(observation) {
    const dateFields = [
        { field: 'effectiveDateTime', value: observation.effectiveDateTime },
        { field: 'effectivePeriod.start', value: observation.effectivePeriod?.start },
        { field: 'effectiveInstant', value: observation.effectiveInstant },
        { field: 'issued', value: observation.issued },
        { field: 'meta.lastUpdated', value: observation.meta?.lastUpdated },
        { field: 'date', value: observation.date },
        { field: 'performedDateTime', value: observation.performedDateTime },
        { field: 'performedPeriod.start', value: observation.performedPeriod?.start },
        { field: 'recordedDate', value: observation.recordedDate }
    ];

    for (const { field, value } of dateFields) {
        if (value) {
            try {
                const date = new Date(value);
                if (!isNaN(date)) {
                    return date.toISOString().split('T')[0];
                }
            } catch (error) {
                // Silently continue to next field
            }
        }
    }

    return 'No date';
}

function analyzeObservations(observations) {
    const patientStats = {};

    observations.forEach((obs) => {
        try {
            if (obs.resourceType !== 'Observation') return;

            // Get patient info
            const patientId = obs.subject?.reference?.split('/')[1];
            const patientName = obs.subject?.display || 'Unknown Patient';
            
            if (!patientId) return;

            // Initialize patient stats if not exists
            if (!patientStats[patientId]) {
                patientStats[patientId] = {
                    name: patientName,
                    normalCount: 0,
                    abnormalCount: 0,
                    normalObservations: [],
                    abnormalReadings: [],
                    lastProcessed: new Date().toISOString()
                };
            }

            const observationId = obs.id;
            const observationType = getObservationType(obs);
            const formattedDate = getObservationDate(obs);

            // Handle BP observations
            if (observationType === 'BP') {
                const systolicComponent = obs.component?.find(comp =>
                    comp.code?.coding?.some(coding => coding.code === '8480-6')
                );
                const diastolicComponent = obs.component?.find(comp =>
                    comp.code?.coding?.some(coding => coding.code === '8462-4')
                );

                if (!systolicComponent || !diastolicComponent) return;

                const systolic = systolicComponent.valueQuantity?.value;
                const diastolic = diastolicComponent.valueQuantity?.value;

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
                        value: `${systolic}/${diastolic} ${ranges.unit}`,
                        referenceRange: `${ranges.systolic.min}-${ranges.systolic.max}/${ranges.diastolic.min}-${ranges.diastolic.max} ${ranges.unit}`,
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
                    referenceText = `${range.min}-${range.max} ${range.unit}`;
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
                    type: observationType,
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
            console.error(`Error processing observation ${obs?.id || 'unknown'}: ${error.message}`);
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
        
        // All subsequent logging will go through the Logger class
        logger.writeLog('INFO', [`Starting ${scriptName}...`], console.log);
        
        // Initialize configuration
        const configManager = new ConfigManager();
        config = await configManager.loadConfig();
        
        // Clear export directory
        await logger.clearExportDirectory();
        
        // Initialize key manager
        const keyManager = new KeyManager(config);
        await keyManager.generateKeyPair();
        
        // Initialize EPIC client and get data
        const epicClient = new EpicClient(config);
        const accessToken = await epicClient.getAccessToken();
        exportedFiles = await epicClient.getAllResourceData(accessToken);
        
        success = true;
        logger.writeLog('INFO', [`\n${scriptName} completed successfully`], console.log);
        
    } catch (error) {
        logger.writeLog('ERROR', ['Application error:', error.message], console.error);
        if (error.response) {
            logger.writeLog('ERROR', ['Response data:', error.response.data], console.error);
            logger.writeLog('ERROR', ['Response status:', error.response.status], console.error);
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

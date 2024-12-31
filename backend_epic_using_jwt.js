/**
 * EPIC FHIR Backend Authentication Demo
 * ====================================
 * Author: Ajay Prashar
 * Date: 12/30/2024
 * Version: 1.0.0
 * 
 * Description:
 * This application demonstrates the backend authentication process for EPIC's FHIR API
 * using JWT (JSON Web Tokens). It implements the OAuth 2.0 client credentials flow
 * with JWT assertion as specified in EPIC's documentation.
 * 
 * Authentication Flow:
 * 1. Generate/Load RSA Key Pair
 * 2. Create JWT with required claims
 * 3. Request access token using JWT
 * 4. Use access token for FHIR API requests
 * 
 * Key Components:
 * - ConfigManager: Handles configuration loading and variable resolution
 * - KeyManager: Manages RSA key pair generation and storage
 * - JWTManager: Creates properly formatted JWTs for authentication
 * - EpicClient: Handles API communication with EPIC's FHIR server
 * 
 * Dependencies:
 * - fs: File system operations
 * - path: Path manipulation
 * - crypto: RSA key pair generation
 * - ini: Configuration file parsing
 * - axios: HTTP requests
 * - jsonwebtoken: JWT creation and signing
 * - uuid: Unique identifier generation for JWT
 * - csv: CSV parsing
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
            originalLog(...args); // Keep console output for development
        };
        
        // Replace console.error with indented file logging
        const originalError = console.error;
        console.error = (...args) => {
            const indent = '  '.repeat(this.indentLevel);
            const message = indent + 'ERROR: ' + util.format(...args) + '\n';
            this.logStream.write(message);
            originalError(...args); // Keep console output for development
        };

        // Add group methods to console
        console.startGroup = (name) => {
            console.log(`[START] ${name}`);
            this.indentLevel++;
        };

        console.endGroup = (name) => {
            this.indentLevel--;
            console.log(`[END] ${name}`);
        };
    }

    listExportedFiles() {
        const exportDir = 'epic_data_export';
        if (fs.existsSync(exportDir)) {
            const files = fs.readdirSync(exportDir);
            console.log('\nExported Files:');
            console.log('-'.repeat(40));
            files.forEach(file => {
                const stats = fs.statSync(path.join(exportDir, file));
                console.log(`${file} (${(stats.size/1024).toFixed(2)} KB)`);
            });
            console.log('-'.repeat(40));
        }
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

/**
 * Configuration Management
 * ======================
 * Handles loading and processing of configuration values from INI file.
 * Supports variable substitution using ${variable} syntax.
 * 
 * Key Functions:
 * - loadConfig: Loads/creates configuration file
 * - resolveVariables: Processes variable substitutions
 * - createDefaultConfig: Creates initial configuration if none exists
 */
class ConfigManager {
    constructor() {
        this.configPath = 'backend_epic_using_jwt.ini';
        this.config = null;
    }

    async loadConfig() {
        console.log('Loading configuration...');
        try {
            let configSource = 'INI file';
            
            if (!fs.existsSync(this.configPath)) {
                console.log('No configuration file found, creating with defaults...');
                await this.createDefaultConfig();
                configSource = 'Default values';
            }
            
            const configFile = fs.readFileSync(this.configPath, 'utf-8');
            this.config = ini.parse(configFile);
            
            // Log original values before resolution
            console.log('\nConfiguration values before resolution:');
            this.logConfigValues(this.config, configSource);
            
            // Resolve environment variables
            const originalConfig = JSON.parse(JSON.stringify(this.config));
            this.config = this.resolveVariables(this.config);
            
            // Log which values were changed by resolution
            console.log('\nConfiguration values after resolution:');
            this.logConfigValues(this.config, configSource, originalConfig);
            
            return this.config;
        } catch (error) {
            console.error('Error loading configuration:', error);
            throw error;
        }
    }

    logConfigValues(config, source, originalConfig = null) {
        const logValue = (key, value, prefix = '') => {
            if (typeof value === 'object' && value !== null) {
                // Handle nested sections
                Object.entries(value).forEach(([subKey, subValue]) => {
                    const fullKey = prefix ? `${prefix}.${key}.${subKey}` : `${key}.${subKey}`;
                    if (originalConfig) {
                        const origValue = originalConfig[key]?.[subKey];
                        const valueSource = process.env[fullKey.toUpperCase()] ? 'Environment variable' :
                                         subValue !== origValue ? 'Variable substitution' :
                                         source;
                        console.log(`${fullKey}: ${subValue} (Source: ${valueSource})`);
                    } else {
                        console.log(`${fullKey}: ${subValue} (Source: ${source})`);
                    }
                });
            } else {
                const fullKey = prefix ? `${prefix}.${key}` : key;
                if (originalConfig) {
                    const origValue = originalConfig[key];
                    const valueSource = process.env[fullKey.toUpperCase()] ? 'Environment variable' :
                                     value !== origValue ? 'Variable substitution' :
                                     source;
                    console.log(`${fullKey}: ${value} (Source: ${valueSource})`);
                } else {
                    console.log(`${fullKey}: ${value} (Source: ${source})`);
                }
            }
        };

        Object.entries(config).forEach(([key, value]) => logValue(key, value));
    }

    resolveVariables(config) {
        const resolve = (obj) => {
            const resolved = {};
            for (const [key, value] of Object.entries(obj)) {
                if (typeof value === 'object' && value !== null) {
                    resolved[key] = resolve(value);
                } else if (typeof value === 'string') {
                    resolved[key] = value.replace(/\${([^}]+)}/g, (_, name) => {
                        return this.config[name] || process.env[name] || '';
                    });
                } else {
                    resolved[key] = value;
                }
            }
            return resolved;
        };
        return resolve(config);
    }

    async createDefaultConfig() {
        console.log('\nCreating default configuration:');
        
        const homeDir = require('os').homedir();
        
        const defaultConfig = {
            app_folder_name: path.join(homeDir, 'FHIR', 'BackendEpic'),
            private_key: '${app_folder_name}/private.key',
            public_key: '${app_folder_name}/public.key',
            base64_public_key: '${app_folder_name}/base64_public_key.pem',
            test_patient_id: process.env.EPIC_TEST_PATIENT_ID || 'erXuFYUfucBZaryVksYEcMg3',
            epic_endpoint: process.env.EPIC_FHIR_ENDPOINT || 'https://fhir.epic.com/interconnect-fhir-oauth/api/FHIR/R4/',
            jwt_expiry_minutes: process.env.JWT_EXPIRY_MINUTES || '5'
        };

        // Log default values and their sources
        Object.entries(defaultConfig).forEach(([key, value]) => {
            const source = process.env[key] ? 'Environment variable' : 'Default value';
            console.log(`${key}: ${value} (Source: ${source})`);
        });

        // Create the configuration file with comments
        const configContent = `; EPIC FHIR Backend Authentication Configuration
; Source: EPIC FHIR Documentation and Implementation Guide

; Application folder path (default: user's home directory)
app_folder_name = ${defaultConfig.app_folder_name}

; Key file paths (relative to app_folder_name)
private_key = ${defaultConfig.private_key}
public_key = ${defaultConfig.public_key}
base64_public_key = ${defaultConfig.base64_public_key}

; EPIC test patient ID (override with EPIC_TEST_PATIENT_ID environment variable)
test_patient_id = ${defaultConfig.test_patient_id}

; EPIC FHIR endpoint (override with EPIC_FHIR_ENDPOINT environment variable)
epic_endpoint = ${defaultConfig.epic_endpoint}
`;

        fs.writeFileSync(this.configPath, configContent);
        console.log('Default configuration file created');
    }

    validateConfig(config) {
        const requiredFields = [
            'test_patient_id',
            'epic_endpoint',
            'client_id',
            'token_endpoint',
            'jwt_expiry_minutes'
        ];
        
        for (const field of requiredFields) {
            if (!config[field]) {
                throw new Error(`Missing required configuration field: ${field}`);
            }
        }
        
        // Validate that jwt_expiry_minutes is a positive number
        const expiryMinutes = parseInt(config.jwt_expiry_minutes);
        if (isNaN(expiryMinutes) || expiryMinutes <= 0) {
            throw new Error('jwt_expiry_minutes must be a positive number');
        }
    }
}

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
        this.config = config;
    }

    async generateKeyPair() {
        console.log('Checking for existing key pair...');
        
        if (!fs.existsSync(this.config.private_key)) {
            console.log('Generating new RSA key pair...');
            const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
                modulusLength: 2048,
                publicKeyEncoding: {
                    type: 'spki',
                    format: 'pem'
                },
                privateKeyEncoding: {
                    type: 'pkcs8',
                    format: 'pem'
                }
            });

            // Ensure directory exists
            fs.mkdirSync(path.dirname(this.config.private_key), { recursive: true });
            
            // Save keys
            fs.writeFileSync(this.config.private_key, privateKey);
            fs.writeFileSync(this.config.public_key, publicKey);
            
            // Create base64 encoded public key
            const base64PublicKey = Buffer.from(publicKey).toString('base64');
            fs.writeFileSync(this.config.base64_public_key, base64PublicKey);
            
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
        this.config = config;
        this.privateKey = fs.readFileSync(this.config.private_key);
    }

    generateJWT() {
        console.log('Generating JWT...');
        
        const currentTime = Math.floor(Date.now() / 1000);
        const expiryMinutes = parseInt(this.config.jwt_expiry_minutes) || 5; // Default to 5 if not specified
        
        console.log(`Setting JWT expiry to ${expiryMinutes} minutes from now`);
        
        const claims = {
            iss: this.config.client_id,
            sub: this.config.client_id,
            aud: this.config.token_endpoint,
            jti: uuidv4(),
            exp: currentTime + (expiryMinutes * 60), // Convert minutes to seconds
            nbf: currentTime,
            iat: currentTime
        };

        console.log('JWT Claims:', claims);
        console.log(`JWT will expire at: ${new Date(claims.exp * 1000).toISOString()}`);

        const token = jwt.sign(claims, this.privateKey, {
            algorithm: 'RS384',
            header: {
                alg: 'RS384',
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
        this.config = config;
        this.jwtManager = new JWTManager(config);
    }

    async getAccessToken() {
        console.log('Requesting access token...');
        
        const jwt = this.jwtManager.generateJWT();
        
        // Use token endpoint from configuration
        console.log(`Using token endpoint: ${this.config.token_endpoint}`);
        
        const params = new URLSearchParams();
        params.append('grant_type', 'client_credentials');
        params.append('client_assertion_type', 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer');
        params.append('client_assertion', jwt);

        try {
            const response = await axios.post(this.config.token_endpoint, params, {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                }
            });
            
            console.log('Access token received:', response.data);
            return response.data.access_token;
        } catch (error) {
            console.error(`Error getting access token from ${this.config.token_endpoint}:`, 
                          error.response?.data || error.message);
            throw error;
        }
    }

    async loadPatientRoster() {
        console.log('Loading patient roster from CSV...');
        const rosterPath = this.config.epic_sandbox_roster;
        
        try {
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
        console.log('Loading resources list from CSV...');
        const resourcesPath = this.config.epic_sandbox_resources;
        
        try {
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
        
        const baseEndpoint = this.config.epic_endpoint.replace(/\/$/, '');
        const queryParams = new URLSearchParams();
        queryParams.append('patient', patientId);
        queryParams.append('_format', this.config.data_export.format);
        queryParams.append('_count', this.config.api_settings.page_size);

        // Handle special cases for different resources
        let endpoint = `${baseEndpoint}${resourceType}`;
        if (resourceType === 'Patient') {
            endpoint = `${baseEndpoint}Patient/${patientId}`;
        } else if (resourceType === 'Observation') {
            // Handle different observation types with category parameter
            queryParams.append('patient', patientId);
            queryParams.append('category', this.config.lab_data_category);
        }
        
        queryParams.append('_format', 'application/fhir+json');
        queryParams.append('_count', '100');

        try {
            let allResults = [];
            let nextUrl = `${endpoint}${queryParams.toString() ? '?' + queryParams.toString() : ''}`;
            let pageCount = 0;

            while (nextUrl && pageCount < this.config.api_settings.max_pages) {
                pageCount++;
                console.startGroup(`Page ${pageCount}`);
                console.log('URL:', nextUrl);
                
                const response = await axios.get(nextUrl, {
                    headers: {
                        'Authorization': `Bearer ${accessToken}`,
                        'Accept': 'application/fhir+json'
                    }
                });

                // Handle single resource response (like Patient)
                if (!response.data.entry && response.data.resourceType === resourceType) {
                    allResults.push(response.data);
                    console.log('Retrieved single resource');
                    console.endGroup(`Page ${pageCount}`);
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
                console.endGroup(`Page ${pageCount}`);
            }

            // Keep indentation level for total results message
            console.log(`\nTotal ${resourceType} results retrieved: ${allResults.length}`);
            return allResults;

        } catch (error) {
            console.error(`Error getting ${resourceType} data:`, 
                error.response?.data || error.message);
            throw error;
        }
    }

    async saveResourceData(resourceType, data) {
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const filename = `${resourceType}_data_${timestamp}.ndjson`;
        const filepath = path.join(this.config.epic_data_export_folder, filename);

        const ndjsonData = data.map(result => JSON.stringify(result)).join('\n');
        fs.writeFileSync(filepath, ndjsonData);
        
        console.log(`Exported ${data.length} records to: ${filepath}`);
    }

    async getAllResourceData(accessToken) {
        console.log('Getting data for all resources and patients...');
        
        // Load patients and resources lists
        const patients = await this.loadPatientRoster();
        const resources = await this.loadResourcesList();
        
        console.startGroup('Resource Processing');
        
        // Process each resource type
        for (const resource of resources) {
            console.startGroup(`Resource: ${resource.resource}`);
            let allResourceResults = [];
            
            // Get data for each patient
            for (const patient of patients) {
                console.startGroup(`Patient: ${patient.name} (${patient.fhir_id})`);
                try {
                    const data = await this.getResourceData(
                        accessToken, 
                        resource.resource, 
                        patient.fhir_id
                    );
                    allResourceResults = allResourceResults.concat(data);
                    console.log(`Retrieved ${data.length} records`);
                } catch (error) {
                    console.error(`Error: ${error.message}`);
                }
                console.endGroup(`Patient: ${patient.name}`);
            }

            // Save results for this resource type
            await this.saveResourceData(resource.resource, allResourceResults);
            console.endGroup(`Resource: ${resource.resource}`);
        }
        
        console.endGroup('Resource Processing');
        console.log('Completed processing all resources');
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
async function sendCompletionEmail(success, startTime, endTime, exportedFiles) {
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

    const exportDir = path.resolve('epic_data_export');
    const filesList = exportedFiles.map(file => 
        `${file.name} (${file.size} KB)`
    ).join('\n    ');

    const mailOptions = {
        from: process.env.PROTON_MAIL_USER,
        to: 'ajay@aprashar.com',
        subject: `EPIC FHIR Sync ${success ? 'Success' : 'Failed'}`,
        text: `
EPIC FHIR Sync Job Report
========================
Start Time: ${startTime}
End Time: ${endTime}
Duration: ${Math.round((new Date(endTime) - new Date(startTime))/1000)} seconds
Status: ${success ? 'Successful' : 'Failed'}

Export Directory:
${exportDir}

Exported Files:
    ${filesList}

Log File:
${path.resolve('backend_epic.log')}

For more details, check the logs at the paths above.
        `
    };

    try {
        await transporter.sendMail(mailOptions);
        console.log('Completion email sent via ProtonMail Bridge');
    } catch (error) {
        console.error('Error sending email:', error);
        console.error('Error details:', error.message);
    }
}

async function main() {
    const startTime = new Date().toISOString();
    let success = false;
    let exportedFiles = [];
    
    try {
        // Initialize logger first
        const logger = new Logger();
        
        console.log('Starting EPIC FHIR Backend Authentication Demo...');
        
        // Clear export directory before starting
        logger.clearExportDirectory();
        
        // Initialize configuration and get access token
        const configManager = new ConfigManager();
        const config = await configManager.loadConfig();
        const keyManager = new KeyManager(config);
        await keyManager.generateKeyPair();
        const epicClient = new EpicClient(config);
        const accessToken = await epicClient.getAccessToken();
        
        // Get data for all resources and patients
        await epicClient.getAllResourceData(accessToken);
        
        // List exported files
        logger.listExportedFiles();
        
        // Get list of exported files for email
        const exportDir = 'epic_data_export';
        exportedFiles = fs.readdirSync(exportDir).map(file => {
            const stats = fs.statSync(path.join(exportDir, file));
            return {
                name: file,
                size: (stats.size/1024).toFixed(2)
            };
        });
        
        success = true;
        console.log('\nDemo completed successfully');

    } catch (error) {
        console.error('Application error:', error);
        success = false;
    } finally {
        // Send completion email regardless of success/failure
        const endTime = new Date().toISOString();
        await sendCompletionEmail(success, startTime, endTime, exportedFiles);
        
        if (!success) {
            process.exit(1);
        }
    }
}

// Application entry point
main();

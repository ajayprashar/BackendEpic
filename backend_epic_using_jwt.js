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
}

// Load configuration from INI file
const configPath = path.resolve(__dirname, 'backend_epic_using_jwt.ini');
const config = ini.parse(fs.readFileSync(configPath, 'utf-8'));

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
    }

    async loadConfig() {
        console.log('Loading configuration...');
        try {
            if (!fs.existsSync(this.configPath)) {
                throw new Error('Configuration file not found: ' + this.configPath);
            }

            const configFile = fs.readFileSync(this.configPath, 'utf-8');
            const config = ini.parse(configFile);

            // Log original values before resolution
            console.log('\nConfiguration values before resolution:');
            this.logConfigValues(config, 'INI file');

            // Resolve variables
            const resolvedConfig = this.resolveVariables(config);

            // Log resolved values
            console.log('\nConfiguration values after resolution:');
            this.logConfigValues(resolvedConfig, 'Variable substitution');

            // Validate required configurations
            this.validateConfig(resolvedConfig);

            return resolvedConfig;
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
        // First, flatten the config object
        function flattenConfig(obj, prefix = '') {
            const flattened = {};
            for (const [key, value] of Object.entries(obj)) {
                const fullKey = prefix ? `${prefix}.${key}` : key;
                if (typeof value === 'object' && value !== null) {
                    Object.assign(flattened, flattenConfig(value, fullKey));
                } else {
                    flattened[fullKey] = value;
                }
            }
            return flattened;
        }

        // Flatten the config
        const flatConfig = flattenConfig(config);
        
        // First pass: resolve variables
        const resolved = {};
        for (const [key, value] of Object.entries(flatConfig)) {
            if (typeof value === 'string') {
                resolved[key] = value.replace(/\${([^}]+)}/g, (match, varName) => {
                    // Look for the variable in both flattened paths
                    const fullPath = `paths.${varName}`;
                    return flatConfig[fullPath] || flatConfig[varName] || match;
                });
            } else {
                resolved[key] = value;
            }
        }

        // Second pass: reconstruct paths
        const result = {};
        for (const [key, value] of Object.entries(resolved)) {
            const parts = key.split('.');
            let current = result;
            for (let i = 0; i < parts.length - 1; i++) {
                current[parts[i]] = current[parts[i]] || {};
                current = current[parts[i]];
            }
            // For paths, ensure proper path joining
            if (key.startsWith('paths.') || key.includes('_folder') || key.includes('_path')) {
                current[parts[parts.length - 1]] = path.normalize(value);
            } else {
                current[parts[parts.length - 1]] = value;
            }
        }

        return result;
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
        const required = {
            paths: ['app_folder_name', 'private_key', 'public_key'],
            oauth_settings: ['client_id', 'token_endpoint'],
            jwt_settings: ['jwt_algorithm', 'jwt_expiry_minutes'],
            epic_settings: ['epic_endpoint']
        };

        for (const [section, fields] of Object.entries(required)) {
            if (!config[section]) {
                throw new Error(`Missing required configuration section: ${section}`);
            }
            for (const field of fields) {
                if (!config[section][field]) {
                    throw new Error(`Missing required configuration: ${section}.${field}`);
                }
            }
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
    const filesList = exportedFiles.map(file => 
        `${file.name} (${file.size} KB)`
    ).join('\n    ');

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
        console.log('Completion email sent successfully');
    } catch (error) {
        console.error('Error sending email:', error);
        console.error('Error details:', error.message);
    }
}

function logExportSummary(files) {
    console.log('=== Begin Export Summary ===');
    files.forEach(file => {
        console.log(`Exported: ${file.name} (${file.size} KB)`);
    });
    console.log('=== End Export Summary ===');
}

async function main() {
    const startTime = new Date().toISOString();
    let success = false;
    let exportedFiles = [];
    let config = null;
    
    try {
        // Initialize logger first
        const logger = new Logger();
        
        console.log(`Starting ${scriptName}...`);
        
        // Clear export directory before starting
        logger.clearExportDirectory();
        
        // Initialize configuration
        console.log('Loading configuration...');
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
            await sendCompletionEmail(success, startTime, endTime, exportedFiles, config);
        }
        
        if (!success) {
            process.exit(1);
        }
    }
}

// Application entry point
main();

/**
 * Epic FHIR Client Class
 * ====================
 * Handles communication with Epic's FHIR API endpoints.
 * 
 * Features:
 * - OAuth 2.0 token management
 * - FHIR resource retrieval
 * - Automatic retry logic
 * - Rate limiting compliance
 * - Data export functionality
 * 
 * Example Usage:
 * ```javascript
 * const epicClient = new EpicClient(config, jwtManager);
 * const accessToken = await epicClient.getAccessToken();
 * const patientData = await epicClient.getResourceData(accessToken, 'Patient', 'example-id');
 * ```
 * 
 * Supported Resources:
 * - Patient
 * - Observation
 * - Condition
 * - AllergyIntolerance
 * - DocumentReference
 * - MedicationRequest
 * - Procedure
 * - Immunization
 * - DiagnosticReport
 * - Goal
 * - Device
 */

const fs = require('fs');
const path = require('path');
const axios = require('axios');
const csv = require('csv-parse/sync');

class EpicClient {
    constructor(config, jwtManager) {
        this.config = config;
        this.jwtManager = jwtManager;
        this.accessToken = null;
        this.tokenExpiryTime = null;
        this.baseUrl = config.epic_settings.epic_endpoint;
        this.exportDir = config.paths.epic_data_export_folder;
        
        // Ensure export directory exists
        if (!fs.existsSync(this.exportDir)) {
            fs.mkdirSync(this.exportDir, { recursive: true });
        }
    }

    async getAccessToken() {
        console.log('Requesting access token from Epic...');
        try {
            const jwt = await this.jwtManager.generateJWT();
            
            const tokenResponse = await this.requestAccessToken(jwt);
            if (!tokenResponse || !tokenResponse.access_token) {
                const error = tokenResponse?.error || 'Unknown error';
                const description = tokenResponse?.error_description || 'No description provided';
                console.error(`Failed to obtain access token. Error: ${error}, Description: ${description}`);
                console.error('Token request failed. Stopping further processing.');
                process.exit(1); // Exit with error code
            }

            this.accessToken = tokenResponse.access_token;
            // Set token expiry time if provided, otherwise default to 5 minutes
            const expiresIn = tokenResponse.expires_in || 300;
            this.tokenExpiryTime = Date.now() + (expiresIn * 1000);
            
            console.log('Successfully obtained access token');
            console.log(`Token will expire in ${expiresIn} seconds`);
            
            return this.accessToken;
        } catch (error) {
            console.error('Critical error in token acquisition:');
            console.error('Error details:', error.message);
            if (error.response) {
                console.error('Server response:', {
                    status: error.response.status,
                    statusText: error.response.statusText,
                    data: error.response.data
                });
            }
            console.error('Token request failed. Stopping further processing.');
            process.exit(1); // Exit with error code
        }
    }

    async requestAccessToken(jwt) {
        try {
            const response = await fetch(this.config.oauth_settings.token_endpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
                body: new URLSearchParams({
                    grant_type: this.config.oauth_settings.grant_type,
                    client_assertion_type: this.config.oauth_settings.client_assertion_type,
                    client_assertion: jwt
                })
            });

            const data = await response.json();
            
            if (!response.ok) {
                console.error('Token request failed with status:', response.status);
                console.error('Response headers:', response.headers);
                console.error('Response body:', data);
                return data; // Return error response for proper handling
            }

            return data;
        } catch (error) {
            console.error('Network error during token request:', error.message);
            throw error;
        }
    }

    async loadPatientRoster() {
        console.log('Loading patient roster...');
        try {
            const rosterPath = this.config.data_sources.epic_sandbox_roster;
            const fileContent = fs.readFileSync(rosterPath, 'utf-8');
            const records = csv.parse(fileContent, {
                columns: true,
                skip_empty_lines: true
            });
            
            console.log(`Loaded ${records.length} patients from roster`);
            return records;
        } catch (error) {
            console.error('Error loading patient roster:', error);
            throw error;
        }
    }

    async loadResourcesList() {
        console.log('Loading resources list...');
        try {
            const resourcesPath = this.config.data_sources.epic_sandbox_resources;
            const fileContent = fs.readFileSync(resourcesPath, 'utf-8');
            const records = csv.parse(fileContent, {
                columns: true,
                skip_empty_lines: true
            });
            
            console.log(`Loaded ${records.length} resources`);
            return records;
        } catch (error) {
            console.error('Error loading resources list:', error);
            throw error;
        }
    }

    async getResourceData(accessToken, resourceType, patientId) {
        // Remove trailing slash from baseUrl if present and ensure resourceType doesn't start with a slash
        const cleanBaseUrl = this.baseUrl.replace(/\/$/, '');
        const cleanResourceType = resourceType.replace(/^\//, '');
        const url = `${cleanBaseUrl}/${cleanResourceType}`;
        
        // Build query parameters based on resource type
        const params = {};
        if (resourceType === 'Patient') {
            params._id = patientId;
        } else {
            params.patient = patientId;
        }

        // Add category parameter for Observation queries
        if (resourceType === 'Observation') {
            params.category = this.config.lab_data_settings.lab_data_category;
        }
        
        console.log(`\nGET Request Details:`);
        console.log(`URL: ${url}`);
        console.log(`Parameters:`, params);
        console.log(`Headers: Authorization=Bearer ${accessToken.substring(0, 10)}...`);
        console.log(`         Accept=${this.config.lab_data_settings.lab_data_format}`);
        
        try {
            const response = await axios.get(url, {
                headers: {
                    'Authorization': `Bearer ${accessToken}`,
                    'Accept': this.config.lab_data_settings.lab_data_format
                },
                params
            });

            return response.data;
        } catch (error) {
            console.error(`Error fetching ${resourceType} data:`, error.response?.data || error.message);
            throw error;
        }
    }

    async saveResourceData(resourceType, data) {
        const timestamp = new Date().toISOString().replace(/:/g, '-');
        const filename = `${resourceType}_data_${timestamp}.ndjson`;
        const filepath = path.join(this.exportDir, filename);

        console.log(`Saving ${resourceType} data to ${filename}...`);
        try {
            let content;
            if (Array.isArray(data)) {
                content = data.map(item => JSON.stringify(item)).join('\n');
            } else if (data.entry && Array.isArray(data.entry)) {
                content = data.entry.map(item => JSON.stringify(item.resource)).join('\n');
            } else {
                content = JSON.stringify(data);
            }

            fs.writeFileSync(filepath, content);
            console.log(`Saved ${resourceType} data successfully`);
            return filepath;
        } catch (error) {
            console.error(`Error saving ${resourceType} data:`, error);
            throw error;
        }
    }

    async getResourceDataForPatient(resourceType, patientId, accessToken) {
        console.log(`Processing ${resourceType} data for patient ${patientId}...`);
        
        const maxAttempts = parseInt(this.config.lab_data_settings.lab_data_max_attempts);
        const checkInterval = parseInt(this.config.lab_data_settings.lab_data_check_interval);
        let attempts = 0;

        while (attempts < maxAttempts) {
            try {
                const data = await this.getResourceData(accessToken, resourceType, patientId);
                return data;
            } catch (error) {
                attempts++;
                if (attempts >= maxAttempts) {
                    console.error(`Failed to fetch ${resourceType} data after ${maxAttempts} attempts`);
                    throw error;
                }
                
                console.log(`Attempt ${attempts} failed, retrying in ${checkInterval/1000} seconds...`);
                await new Promise(resolve => setTimeout(resolve, checkInterval));
            }
        }
    }

    cleanExportDirectory() {
        console.log(`\nClearing export directory: ${this.exportDir}`);
        if (fs.existsSync(this.exportDir)) {
            const files = fs.readdirSync(this.exportDir);
            files.forEach(file => {
                const filePath = path.join(this.exportDir, file);
                fs.unlinkSync(filePath);
                console.log(`Deleted: ${file}`);
            });
            console.log('Export directory cleared');
        } else {
            fs.mkdirSync(this.exportDir, { recursive: true });
            console.log('Created empty export directory');
        }
    }

    async getAllResourceData(accessToken) {
        // Clean export directory before starting
        this.cleanExportDirectory();
        
        console.log('Starting data export process...');
        const startTime = new Date();
        const exportedFiles = [];

        try {
            const patients = await this.loadPatientRoster();
            const resources = await this.loadResourcesList();

            // Process each resource type
            for (const resource of resources) {
                const resourceType = resource.resource;
                let resourceData = [];

                // Get data for each patient
                for (const patient of patients) {
                    console.log(`\nProcessing patient: ${patient.fhir_id}`);
                    
                    try {
                        const data = await this.getResourceDataForPatient(
                            resourceType,
                            patient.fhir_id,
                            accessToken
                        );

                        if (data) {
                            // Extract resources from the response
                            if (Array.isArray(data)) {
                                resourceData.push(...data);
                            } else if (data.entry && Array.isArray(data.entry)) {
                                resourceData.push(...data.entry.map(item => item.resource));
                            } else {
                                resourceData.push(data);
                            }
                        }
                    } catch (error) {
                        console.error(`Failed to process ${resourceType} for patient ${patient.fhir_id}:`, error.message);
                    }
                }

                // Save the resource data if we have any
                if (resourceData.length > 0) {
                    const filepath = await this.saveResourceData(resourceType, resourceData);
                    exportedFiles.push(filepath);
                }
            }

            const endTime = new Date();
            console.log('\nData export completed successfully');
            console.log(`Start time: ${startTime.toISOString()}`);
            console.log(`End time: ${endTime.toISOString()}`);
            console.log(`Duration: ${(endTime - startTime) / 1000} seconds`);

            return {
                success: true,
                startTime,
                endTime,
                exportedFiles
            };
        } catch (error) {
            console.error('Data export failed:', error);
            return {
                success: false,
                startTime,
                endTime: new Date(),
                exportedFiles,
                error: error.message
            };
        }
    }
}

module.exports = EpicClient; 
/**
 * Configuration Manager Class
 * =========================
 * Handles loading and processing of configuration values from INI files.
 * Supports environment variable overrides and variable substitution.
 * 
 * Features:
 * - INI file loading and parsing
 * - Environment variable support
 * - Variable substitution using ${variable} syntax
 * - Configuration validation
 * - Default configuration creation
 * 
 * Example Usage:
 * ```javascript
 * const configManager = new ConfigManager('config.ini');
 * const config = await configManager.loadConfig();
 * console.log(config.paths.app_folder_name);
 * ```
 * 
 * Variable Substitution:
 * In the INI file, you can use ${variable} syntax to reference other config values:
 * ```ini
 * [paths]
 * app_folder_name = C:\FHIR\BackendEpic
 * epic_data_export_folder = ${app_folder_name}\epic_data_export
 * ```
 */

const fs = require('fs');
const ini = require('ini');
const path = require('path');
const Logger = require('../utils/Logger');

class ConfigManager {
    constructor(configPath = 'backend_epic_using_jwt.ini') {
        this.configPath = configPath;
    }

    async loadConfig() {
        const logger = Logger.getInstance();
        logger.writeDirectly('\n================================================================================\n');
        logger.writeDirectly('                         Configuration Loading Tutorial                          \n');
        logger.writeDirectly('================================================================================\n\n');
        logger.writeDirectly('Loading configuration from: ' + this.configPath + '\n');
        logger.writeDirectly('Understanding Configuration Sources:\n');
        logger.writeDirectly('----------------------------------\n');
        logger.writeDirectly('When you see a value in the configuration, it will show its source:\n\n');
        logger.writeDirectly('1. (Source: INI file)\n');
        logger.writeDirectly('   • Values read directly from the INI configuration file\n');
        logger.writeDirectly('   • These are the raw, unprocessed values\n\n');
        logger.writeDirectly('2. (Source: Variable substitution)\n');
        logger.writeDirectly('   • Values that contained variables (${variable}) that have been resolved\n');
        logger.writeDirectly('   • Example: ${app_folder_name}/epic_data_export → C:/FHIR/BackendEpic/epic_data_export\n\n');
        logger.writeDirectly('3. (Source: Environment variable)\n');
        logger.writeDirectly('   • Values that were overridden by environment variables\n');
        logger.writeDirectly('   • Useful for sensitive information like API keys\n\n');
        logger.writeDirectly('Now loading the configuration values...\n');
        logger.writeDirectly('--------------------------------------------------------------------------------\n\n');

        try {
            if (!fs.existsSync(this.configPath)) {
                console.log('Configuration file not found, creating default configuration...');
                await this.createDefaultConfig();
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
        // First, create a flattened version of the config for variable lookup
        const flatConfig = {};
        const flatten = (obj, prefix = '') => {
            for (const [key, value] of Object.entries(obj)) {
                const fullKey = prefix ? `${prefix}.${key}` : key;
                if (typeof value === 'object' && value !== null) {
                    flatten(value, fullKey);
                } else {
                    flatConfig[fullKey] = value;
                    // Also store just the key for simpler lookups
                    flatConfig[key] = value;
                }
            }
        };
        flatten(config);

        // Function to resolve a single value
        const resolveValue = (value) => {
            if (typeof value !== 'string') return value;
            
            return value.replace(/\${([^}]+)}/g, (match, variable) => {
                // First try the flattened config
                if (flatConfig[variable] !== undefined) {
                    const resolved = flatConfig[variable];
                    // If the resolved value also contains variables, resolve them too
                    return typeof resolved === 'string' ? 
                        resolveValue(resolved) : 
                        resolved;
                }
                // Then try environment variables
                if (process.env[variable] !== undefined) {
                    return process.env[variable];
                }
                // Special case for ResourceType and Timestamp in file patterns
                if (variable === 'ResourceType' || variable === 'Timestamp') {
                    return match; // Keep these as template variables
                }
                // If not found anywhere, log a warning and return the original value
                console.warn(`Warning: Variable ${variable} not found in configuration or environment`);
                return flatConfig.app_folder_name || process.cwd();
            });
        };

        // Deep clone the config to avoid modifying the original
        const resolvedConfig = JSON.parse(JSON.stringify(config));

        // Recursively resolve all values in the config
        const processObject = (obj) => {
            for (const [key, value] of Object.entries(obj)) {
                if (typeof value === 'object' && value !== null) {
                    processObject(value);
                } else {
                    obj[key] = resolveValue(value);
                }
            }
            return obj;
        };

        return processObject(resolvedConfig);
    }

    async createDefaultConfig() {
        const appFolder = process.cwd();
        const defaultConfig = {
            paths: {
                app_folder_name: appFolder,
                epic_data_export_folder: path.join(appFolder, 'epic_data_export'),
                private_key: path.join(appFolder, 'private.key'),
                public_key: path.join(appFolder, 'public.key'),
                base64_public_key: path.join(appFolder, 'base64_public_key.pem')
            },
            rsa_settings: {
                rsa_key_size: '2048',
                rsa_public_encoding: 'spki',
                rsa_private_encoding: 'pkcs8'
            },
            jwt_settings: {
                jwt_algorithm: 'RS384',
                jwt_expiry_minutes: '5'
            },
            oauth_settings: {
                client_id: '',
                token_endpoint: 'https://fhir.epic.com/interconnect-fhir-oauth/oauth2/token',
                grant_type: 'client_credentials',
                client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            },
            epic_settings: {
                epic_endpoint: 'https://fhir.epic.com/interconnect-fhir-oauth/api/FHIR/R4/',
                test_patient_id: ''
            },
            data_sources: {
                epic_sandbox_roster: path.join(appFolder, 'epic_sandbox_roster.csv'),
                epic_sandbox_resources: path.join(appFolder, 'epic_sandbox_resources.csv')
            },
            lab_data_settings: {
                lab_data_category: 'laboratory',
                lab_data_format: 'application/fhir+ndjson',
                lab_data_fallback_formats: 'application/json,application/fhir+json',
                lab_data_max_attempts: '30',
                lab_data_check_interval: '5000',
                lab_data_timeout: '150000'
            },
            api_settings: {
                page_size: '100',
                max_pages: '100'
            },
            data_export: {
                format: 'application/fhir+json',
                ndjson_format: 'application/fhir+ndjson',
                json_format: 'application/json',
                default_count: '100'
            },
            file_patterns: {
                resource_data_file: '${ResourceType}_data_${Timestamp}.ndjson',
                timestamp_format: 'YYYY-MM-DDTHH-mm-ss-SSSZ'
            }
        };

        const configString = ini.stringify(defaultConfig);
        fs.writeFileSync(this.configPath, configString, 'utf-8');
        console.log(`Created default configuration file: ${this.configPath}`);
        return defaultConfig;
    }

    validateConfig(config) {
        // Check required fields
        const requiredFields = [
            ['paths', 'app_folder_name'],
            ['paths', 'epic_data_export_folder'],
            ['paths', 'private_key'],
            ['paths', 'public_key'],
            ['oauth_settings', 'client_id'],
            ['oauth_settings', 'token_endpoint'],
            ['epic_settings', 'epic_endpoint']
        ];

        for (const [section, field] of requiredFields) {
            if (!config[section]?.[field]) {
                throw new Error(`Missing required configuration: ${section}.${field}`);
            }
        }

        // Ensure required directories exist
        const requiredDirs = [
            path.dirname(config.paths.epic_data_export_folder),
            path.dirname(config.paths.private_key),
            path.dirname(config.paths.public_key),
            path.dirname(config.paths.base64_public_key)
        ];

        for (const dir of requiredDirs) {
            if (!fs.existsSync(dir)) {
                console.log(`Creating directory: ${dir}`);
                fs.mkdirSync(dir, { recursive: true });
            }
        }

        // Create epic_data_export directory if it doesn't exist
        if (!fs.existsSync(config.paths.epic_data_export_folder)) {
            console.log(`Creating export directory: ${config.paths.epic_data_export_folder}`);
            fs.mkdirSync(config.paths.epic_data_export_folder, { recursive: true });
        }

        return config;
    }
}

module.exports = ConfigManager; 
module.exports = ConfigManager; 
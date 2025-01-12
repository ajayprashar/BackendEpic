const fs = require('fs');
const path = require('path');

function loadConfig() {
    const configPath = path.join(__dirname, 'backend_epic_using_jwt.ini');
    if (!fs.existsSync(configPath)) {
        throw new Error(`Configuration file not found at ${configPath}`);
    }

    const configContent = fs.readFileSync(configPath, 'utf8');
    const config = {};
    let currentSection = null;

    // Parse INI file manually
    configContent.split(/\r?\n/).forEach(line => {
        line = line.trim();
        if (!line || line.startsWith(';')) return;

        const sectionMatch = line.match(/^\[(.*)\]$/);
        if (sectionMatch) {
            currentSection = sectionMatch[1];
            config[currentSection] = {};
            return;
        }

        if (currentSection) {
            const [key, ...valueParts] = line.split('=');
            if (key) {
                const trimmedKey = key.trim();
                const value = valueParts.join('=').trim();
                config[currentSection][trimmedKey] = value;
            }
        }
    });

    // First pass: resolve app_folder_name
    if (config.paths && config.paths.app_folder_name) {
        const appFolderName = config.paths.app_folder_name;
        
        // Second pass: resolve all other variables
        Object.entries(config).forEach(([section, values]) => {
            Object.entries(values).forEach(([key, value]) => {
                if (typeof value === 'string') {
                    // Replace ${app_folder_name} with actual value
                    config[section][key] = value.replace(/\${app_folder_name}/g, appFolderName);
                }
            });
        });
    }

    return config;
}

module.exports = { loadConfig }; 
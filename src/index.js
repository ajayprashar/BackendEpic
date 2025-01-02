const KeyManager = require('./auth/KeyManager');
const TokenManager = require('./auth/TokenManager');
const EpicClient = require('./clients/EpicClient');
const ConfigManager = require('./config/ConfigManager');
const ObservationAnalyzer = require('./services/ObservationAnalyzer');
const Logger = require('./utils/Logger');

async function main() {
    try {
        const logger = new Logger();
        const config = await new ConfigManager().loadConfig();
        const keyManager = new KeyManager(config);
        const tokenManager = new TokenManager(config, keyManager);
        const epicClient = new EpicClient(config, tokenManager);
        
        // Rest of the application flow...
    } catch (error) {
        console.error('Application error:', error.message);
    }
}

main(); 
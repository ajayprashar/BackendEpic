/**
 * Logger Class
 * ===========
 * A utility class for handling logging operations throughout the application.
 * 
 * Features:
 * - File-based logging with timestamps
 * - Console mirroring
 * - Indentation support for hierarchical logging
 * - Export directory management
 * - Report generation
 * 
 * Example Usage:
 * ```javascript
 * const logger = new Logger();
 * logger.log('Starting application...');
 * logger.indent();
 * logger.log('Loading configuration...'); // Will be indented
 * logger.unindent();
 * ```
 */

const fs = require('fs');
const path = require('path');

let loggerInstance = null;

class Logger {
    constructor(config = null, scriptName = null) {
        if (loggerInstance) {
            return loggerInstance;
        }
        
        this.config = config;
        this.LOG_FILE = scriptName ? 
            scriptName.replace('.js', '.log') : 
            'backend_epic.log';
        this.MAX_LOG_SIZE = 10 * 1024 * 1024; // 10MB
        this.logStream = null;
        this.initialized = false;
        this.recentMessages = new Set(); // Track recent messages to prevent duplicates
        this.recentMessageTimeout = 5000; // Increased to 5 seconds to better handle tutorial messages
        this.initializeLogStream();
        
        loggerInstance = this;
        return loggerInstance;
    }

    // Reset the singleton instance (useful when switching between scripts)
    static resetInstance() {
        if (loggerInstance && loggerInstance.logStream) {
            loggerInstance.close();
        }
        loggerInstance = null;
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

            // Create write stream
            this.logStream = fs.createWriteStream(this.LOG_FILE, { flags: 'a' });

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

    formatMessage(level, args) {
        if (!args || args.length === 0) {
            return null;
        }
        
        const timestamp = new Date().toISOString();
        let message = '';
        
        if (Array.isArray(args)) {
            // Handle array of messages
            message = args.map(arg => {
                if (typeof arg === 'object') {
                    return JSON.stringify(arg, null, 2);
                }
                return arg.toString();
            }).join('\n');
        } else {
            // Handle single message
            message = typeof args === 'object' ? JSON.stringify(args, null, 2) : args.toString();
        }
        
        // Add timestamp for ERROR level
        if (level === 'ERROR') {
            message = `[${timestamp}] ${message}`;
        }
        
        return message;
    }

    writeLog(level, args) {
        if (!this.initialized || !this.logStream) {
            this.initializeLogStream();
        }

        try {
            const formattedMessage = this.formatMessage(level, args);
            
            // Skip if message is null (duplicate) or empty
            if (!formattedMessage) {
                return;
            }
            
            // For tutorial messages, check for duplicates within a longer timeframe
            if (level === 'TUTORIAL') {
                const messageKey = `${level}:${formattedMessage}`;
                if (this.recentMessages.has(messageKey)) {
                    return; // Skip duplicate tutorial message
                }
                this.recentMessages.add(messageKey);
                setTimeout(() => {
                    this.recentMessages.delete(messageKey);
                }, this.recentMessageTimeout);
            }

            // Check for duplicate messages regardless of level
            const messageKey = `${level}:${formattedMessage}`;
            if (this.recentMessages.has(messageKey)) {
                return; // Skip duplicate message
            }
            this.recentMessages.add(messageKey);
            setTimeout(() => {
                this.recentMessages.delete(messageKey);
            }, this.recentMessageTimeout);
            
            // Write to file with newline
            this.logStream.write(formattedMessage + '\n');
            
            // Write to console with color
            switch (level) {
                case 'WARN':
                    console.log('\x1b[33m' + formattedMessage + '\x1b[0m'); // Yellow
                    break;
                case 'ERROR':
                    console.error('\x1b[31m' + formattedMessage + '\x1b[0m'); // Red
                    break;
                default:
                    console.log(formattedMessage);
            }
        } catch (error) {
            // Fallback to basic console if logging fails
            console.error(...args);
            console.error(`Logger error: ${error.message}`);
        }
    }

    writeDirectly(message) {
        if (!this.initialized || !this.logStream) {
            this.initializeLogStream();
        }
        this.logStream.write(message);
    }

    clearExportDirectory() {
        const exportDir = this.config?.paths?.epic_data_export_folder || 'epic_data_export';
        
        try {
            if (fs.existsSync(exportDir)) {
                const files = fs.readdirSync(exportDir);
                files.forEach(file => {
                    const filePath = path.join(exportDir, file);
                    fs.unlinkSync(filePath);
                });
                this.writeLog('INFO', [`Cleared ${files.length} files from ${exportDir}`]);
            } else {
                fs.mkdirSync(exportDir, { recursive: true });
                this.writeLog('INFO', [`Created export directory: ${exportDir}`]);
            }
        } catch (error) {
            throw new Error(`Failed to clear export directory: ${error.message}`);
        }
    }

    close() {
        if (this.logStream) {
            this.logStream.write('\n=== End of Session ===\n');
            this.logStream.end();
        }
    }

    // Static method to get logger instance
    static getInstance(config = null, scriptName = null) {
        if (!loggerInstance) {
            loggerInstance = new Logger(config, scriptName);
        }
        return loggerInstance;
    }
}

module.exports = Logger; 
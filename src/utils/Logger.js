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
        this.recentMessageTimeout = 5000; // Increased to 5 seconds to better handle tutorial messages
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
        
        return message;
    }

    writeLog(level, args, originalMethod) {
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

    // Add a method for direct writing to log file
    writeDirectly(message) {
        if (!this.initialized || !this.logStream) {
            this.initializeLogStream();
        }
        this.logStream.write(message);
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

module.exports = Logger; 
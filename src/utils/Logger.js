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
const util = require('util');

class Logger {
    constructor(logFilePath = 'backend_epic.log') {
        this.logFilePath = logFilePath;
        this.indentLevel = 0;
        this.initializeLogger();
    }

    initializeLogger() {
        const timestamp = new Date().toISOString();
        const divider = '\n' + '='.repeat(80) + '\n' + 
                       `New Session Started: ${timestamp}` + 
                       '\n' + '='.repeat(80) + '\n';
        
        this.logStream = fs.createWriteStream(this.logFilePath, { flags: 'a' });
        this.logStream.write(divider);
        
        // Store original console methods
        this.originalLog = console.log;
        this.originalError = console.error;
        
        // Override console methods
        console.log = (...args) => this.log(...args);
        console.error = (...args) => this.error(...args);
    }

    log(...args) {
        const indent = '  '.repeat(this.indentLevel);
        const message = indent + util.format(...args) + '\n';
        this.logStream.write(message);
        this.originalLog(...args);
    }

    error(...args) {
        const indent = '  '.repeat(this.indentLevel);
        const message = indent + 'ERROR: ' + util.format(...args) + '\n';
        this.logStream.write(message);
        this.originalError(...args);
    }

    indent() {
        this.indentLevel++;
    }

    unindent() {
        if (this.indentLevel > 0) {
            this.indentLevel--;
        }
    }

    clearExportDirectory(exportDir = 'epic_data_export') {
        this.log(`\nClearing export directory: ${exportDir}`);
        
        if (fs.existsSync(exportDir)) {
            const files = fs.readdirSync(exportDir);
            files.forEach(file => {
                const filePath = path.join(exportDir, file);
                fs.unlinkSync(filePath);
                this.log(`Deleted: ${file}`);
            });
            this.log('Export directory cleared');
        } else {
            fs.mkdirSync(exportDir, { recursive: true });
            this.log('Created empty export directory');
        }
    }

    logReport(reportString) {
        const separator = '='.repeat(80);
        const content = `
${separator}
Observation Analysis Report
${separator}
${reportString}
${separator}
`;
        fs.appendFileSync(this.logFilePath, content);
    }
}

module.exports = Logger; 
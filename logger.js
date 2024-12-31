const winston = require('winston');
const path = require('path');

// Define log file path
const logFilePath = path.join(__dirname, 'backend_epic.log');

// Create a Winston logger instance
const logger = winston.createLogger({
    level: 'info', // Set the minimum log level
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.printf(({ timestamp, level, message }) => {
            return `${timestamp} [${level.toUpperCase()}]: ${message}`;
        })
    ),
    transports: [
        // Write logs to file
        new winston.transports.File({ filename: logFilePath }),
        // Optionally, write logs to console
        new winston.transports.Console()
    ],
});

module.exports = logger;

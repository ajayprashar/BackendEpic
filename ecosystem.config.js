module.exports = {
  apps: [{
    name: "epic-fhir-sync",
    script: "./backend_epic_using_jwt.js",
    cron_restart: "0 2 * * *",
    autorestart: false
  }]
} 
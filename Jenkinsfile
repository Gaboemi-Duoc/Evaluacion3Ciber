pipeline {
    agent any
    
    tools {
        // Define tools you'll use
        sonarqubeScanner 'SonarQube Scanner'
    }
    
    environment {
        // Set environment variables
        APP_URL = 'http://localhost:5000'
    }
    
    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }
        
        stage('Setup Database') {
            steps {
                sh 'python create_db.py'
            }
        }
        
        stage('Dependency Check') {
            steps {
                dependencyCheck additionalArguments: '--scan . --disableAssembly --format HTML --format JSON --out reports/dependency-check/', odcInstallation: 'Dependency-Check'
                dependencyCheckPublisher pattern: 'reports/dependency-check/dependency-check-report.json'
            }
        }
        
        stage('Start App & Security Scan') {
            steps {
                script {
                    // Start the Flask app in background
                    sh 'python vulnerable_flask_app.py &'
                    sleep time: 30, unit: 'SECONDS'
                    
                    // Run ZAP scan
                    zapScan zapHome: '/usr/share/zap', target: "${APP_URL}"
                }
            }
        }
        
        stage('SonarQube Analysis') {
            steps {
                withSonarQubeEnv('SonarQube') {
                    sh 'sonar-scanner -Dsonar.projectKey=flask-app -Dsonar.sources=. -Dsonar.host.url=${SONARQUBE_URL} -Dsonar.login=${SONARQUBE_TOKEN}'
                }
            }
        }
    }
    
    post {
        always {
            // Stop the Flask app
            sh 'pkill -f "python vulnerable_flask_app.py" || true'
            // Archive reports
            archiveArtifacts artifacts: 'reports/**/*', allowEmptyArchive: true
        }
    }
}
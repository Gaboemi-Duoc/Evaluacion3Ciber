// Jenkinsfile for Simple Flask App Security Scanning
pipeline {
    agent any

    environment {
        APP_PORT = '5000'
        VENV_DIR = "${WORKSPACE}/venv"
    }

    options {
        timeout(time: 30, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '5'))
    }

    stages {
        stage('Checkout') {
            steps {
                echo 'Checking out code...'
                checkout scm
            }
        }

        stage('Setup Environment') {
            steps {
                echo 'Setting up Python environment...'
                sh '''
                    python3 -m venv ${VENV_DIR} || python -m venv ${VENV_DIR}
                    . ${VENV_DIR}/bin/activate
                    pip install --upgrade pip
                    
                    # Install app dependencies
                    if [ -f requirements.txt ]; then
                        pip install -r requirements.txt
                    else
                        # Basic Flask dependencies
                        pip install flask flask-wtf bcrypt
                    fi
                    
                    # Create database if needed
                    if [ -f create_db.py ]; then
                        python create_db.py
                    fi
                '''
            }
        }

        stage('OWASP Dependency Check') {
            steps {
                echo '🔍 Running OWASP Dependency Check...'
                dependencyCheck arguments: '''
                    --scan . \
                    --format HTML \
                    --format JSON \
                    --out . \
                    --project "Flask Security App"
                ''', odcInstallation: 'OWASP-Dependency-Check'
                
                // Publish HTML report
                publishHTML([
                    allowMissing: false,
                    alwaysLinkToLastBuild: true,
                    keepAll: true,
                    reportDir: '.',
                    reportFiles: 'dependency-check-report.html',
                    reportName: 'Dependency Check Report'
                ])
            }
        }

        stage('SonarQube Analysis') {
            steps {
                echo 'Running SonarQube analysis...'
                withSonarQubeEnv('SonarQube') {
                    sh '''
                        . ${VENV_DIR}/bin/activate
                        # Install test dependencies for coverage
                        pip install pytest pytest-cov bandit
                        
                        # Run tests with coverage if test files exist
                        if [ -d tests ] || [ -f test_*.py ]; then
                            python -m pytest --cov=. --cov-report=xml:coverage.xml tests/ test_*.py || true
                        fi
                        
                        # Run bandit for security analysis
                        bandit -r . -f json -o bandit-report.json || true
                    '''
                    
                    // SonarQube scanner
                    sh '''
                        sonar-scanner \
                            -Dsonar.projectKey=flask-app \
                            -Dsonar.projectName="Flask Application" \
                            -Dsonar.sources=. \
                            -Dsonar.host.url=${SONARQUBE_URL} \
                            -Dsonar.login=${SONARQUBE_TOKEN} \
                            -Dsonar.python.coverage.reportPaths=coverage.xml \
                            -Dsonar.python.bandit.reportPaths=bandit-report.json
                    '''
                }
            }
        }

        stage('OWASP ZAP Scan') {
            steps {
                echo 'Running OWASP ZAP Security Scan...'
                script {
                    // Start the Flask app in background
                    sh """
                    . ${VENV_DIR}/bin/activate
                    python vulnerable_flask_app.py &
                    APP_PID=\$!
                    echo \$APP_PID > app.pid
                    
                    # Wait for app to start
                    sleep 15
                    
                    # Verify app is running
                    curl -f http://localhost:${APP_PORT} || exit 1
                    """
                    
                    // Run ZAP baseline scan
                    sh """
                    docker run --rm \\
                        -v ${WORKSPACE}:/zap/wrk/:rw \\
                        -t owasp/zap2docker-stable zap-baseline.py \\
                        -t http://host.docker.internal:${APP_PORT} \\
                        -g gen.conf \\
                        -r zap-report.html \\
                        -J zap-report.json \\
                        -w zap-report.md
                    """
                    
                    // Stop the Flask app
                    sh '''
                    if [ -f app.pid ]; then
                        kill $(cat app.pid) || true
                        rm -f app.pid
                    fi
                    pkill -f "python vulnerable_flask_app" || true
                    '''
                }
                
                // Publish ZAP report
                publishHTML([
                    allowMissing: false,
                    alwaysLinkToLastBuild: true,
                    keepAll: true,
                    reportDir: '.',
                    reportFiles: 'zap-report.html',
                    reportName: 'ZAP Security Report'
                ])
            }
            
            post {
                always {
                    // Cleanup any remaining processes
                    sh 'pkill -f "python vulnerable_flask_app" || true'
                }
            }
        }

        stage('Security Reports') {
            steps {
                echo 'Generating security reports summary...'
                sh '''
                    echo "# Security Scan Summary" > security-summary.md
                    echo "## Build: ${BUILD_NUMBER}" >> security-summary.md
                    echo "## Date: $(date)" >> security-summary.md
                    echo "" >> security-summary.md
                    echo "### Scans Completed:" >> security-summary.md
                    echo "- OWASP Dependency Check" >> security-summary.md
                    echo "- SonarQube Analysis" >> security-summary.md
                    echo "- OWASP ZAP Dynamic Scan" >> security-summary.md
                    echo "" >> security-summary.md
                    echo "### Reports Generated:" >> security-summary.md
                    ls -la *.html *.json *.md | grep -E "(dependency-check|zap-report|bandit|security)" >> security-summary.md
                '''
                
                publishHTML([
                    allowMissing: false,
                    alwaysLinkToLastBuild: true,
                    keepAll: true,
                    reportDir: '.',
                    reportFiles: 'security-summary.md',
                    reportName: 'Security Summary'
                ])
            }
        }
    }

    post {
        always {
            echo '🧹 Cleaning up workspace...'
            sh '''
                pkill -f "python vulnerable_flask_app" || true
                rm -f app.pid
            '''
            
            // Archive all reports
            archiveArtifacts artifacts: '*.html, *.json, *.md, *.xml'
        }
        
        success {
            echo 'Security scan completed successfully!'
            emailext (
                subject: "SUCCESS: Security Scan Build ${env.BUILD_NUMBER}",
                body: "Flask app security scanning completed successfully.\nView reports: ${env.BUILD_URL}",
                to: "dev-team@company.com"
            )
        }
        
        failure {
            echo 'Security scan failed!'
            emailext (
                subject: "FAILED: Security Scan Build ${env.BUILD_NUMBER}",
                body: "Flask app security scanning failed.\nCheck logs: ${env.BUILD_URL}",
                to: "dev-team@company.com"
            )
        }
    }
}
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
                sh 'mkdir -p reports'
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
                        pip install flask flask-wtf bcrypt markupsafe bleach
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
                echo 'Running OWASP Dependency Check...'
                dependencyCheck pattern: '**/requirements.txt'
                
                script {
                    // Publish dependency check results
                    dependencyCheckPublisher pattern: 'dependency-check-report.xml'
                }
            }
        }

        stage('SonarQube Analysis') {
            steps {
                echo 'Running SonarQube analysis...'
                script {
                    withSonarQubeEnv('SonarQube') {
                        sh '''
                            . ${VENV_DIR}/bin/activate
                            # Install analysis tools
                            pip install bandit pylint
                            
                            # Run bandit security analysis
                            bandit -r . -f json -o reports/bandit-report.json || true
                            
                            # Run pylint for code quality
                            pylint *.py > reports/pylint-report.txt || true
                        '''
                        
                        // Simple sonar-scanner execution
                        sh 'sonar-scanner -Dsonar.projectKey=flask-app -Dsonar.sources=.'
                    }
                }
            }
        }

        stage('OWASP ZAP Scan') {
            steps {
                echo 'Running OWASP ZAP Security Scan...'
                script {
                    // Start Flask app
                    sh """
                    . ${VENV_DIR}/bin/activate
                    python vulnerable_flask_app.py &
                    echo \$! > app.pid
                    sleep 10
                    """
                    
                    // Run ZAP scan using command line
                    sh """
                    docker run --rm \\
                        -v ${WORKSPACE}/reports:/zap/wrk/:rw \\
                        owasp/zap2docker-stable zap-baseline.py \\
                        -t http://host.docker.internal:${APP_PORT} \\
                        -r zap-report.html \\
                        -J zap-report.json \\
                        -w zap-report.md \\
                        -a
                    """
                    
                    // Stop Flask app
                    sh '''
                    if [ -f app.pid ]; then
                        kill $(cat app.pid) || true
                        rm -f app.pid
                    fi
                    '''
                }
                
                // Publish ZAP report
                publishHTML([
                    allowMissing: true,
                    alwaysLinkToLastBuild: true,
                    keepAll: true,
                    reportDir: 'reports',
                    reportFiles: 'zap-report.html',
                    reportName: 'ZAP Security Report'
                ])
            }
        }

        stage('Generate Reports') {
            steps {
                echo 'Consolidating security reports...'
                sh '''
                    echo "# Security Scan Summary" > reports/security-summary.md
                    echo "## Build Number: ${BUILD_NUMBER}" >> reports/security-summary.md
                    echo "## Date: $(date)" >> reports/security-summary.md
                    echo "" >> reports/security-summary.md
                    echo "### Security Tools Executed:" >> reports/security-summary.md
                    echo "- OWASP Dependency Check" >> reports/security-summary.md
                    echo "- SonarQube Static Analysis" >> reports/security-summary.md  
                    echo "- OWASP ZAP Dynamic Analysis" >> reports/security-summary.md
                    echo "" >> reports/security-summary.md
                    echo "### Generated Reports:" >> reports/security-summary.md
                    ls -la reports/ >> reports/security-summary.md
                '''
            }
        }
    }

    post {
        always {
            echo 'Cleaning up...'
            sh '''
                pkill -f "python vulnerable_flask_app" || true
                rm -f app.pid
            '''
            
            // Archive all reports
            archiveArtifacts artifacts: 'reports/*.*, *.xml, *.json'
            
            // Publish final summary
            publishHTML([
                allowMissing: true,
                alwaysLinkToLastBuild: true,
                keepAll: true,
                reportDir: 'reports',
                reportFiles: 'security-summary.md',
                reportName: 'Security Summary'
            ])
        }
        
        success {
            echo 'All security scans completed successfully!'
        }
        
        failure {
            echo 'Some security scans failed!'
        }
    }
}
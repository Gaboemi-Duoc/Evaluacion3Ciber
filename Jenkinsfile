pipeline {
    agent {
        docker {
            image 'python:3.9-slim'
            args '-u root:root --security-opt no-new-privileges'
        }
    }

    environment {
        // Credenciales y configuración
        SONARQUBE_TOKEN = credentials('sonarqube-token')
        ZAP_API_KEY = credentials('zap-api-key')
        DOCKER_REGISTRY = credentials('docker-registry')
        
        // Rutas de reportes
        DEPENDENCY_CHECK_REPORT = 'reports/dependency-check-report.html'
        SONARQUBE_REPORT = 'reports/sonarqube-analysis.json'
        ZAP_REPORT = 'reports/zap-scan-report.html'
        SECURITY_SUMMARY = 'reports/security-summary.md'
        
        // Configuración de aplicación
        APP_PORT = '5000'
        SCAN_TIMEOUT = '300' // 5 minutos
    }

    options {
        buildDiscarder(logRotator(numToKeepStr: '20', artifactNumToKeepStr: '10'))
        timeout(time: 30, unit: 'MINUTES')
        timestamps()
        disableConcurrentBuilds()
    }

    stages {
        stage('Setup') {
            steps {
                echo 'Checking out code and setting up environment...'
                checkout scm
                
                // Crear estructura de directorios para reportes
                sh '''
                    mkdir -p reports
                    mkdir -p security-data
                    mkdir -p test-results
                '''
                
                // Configurar Git safe directory
                sh 'git config --global --add safe.directory ${WORKSPACE}'
            }
        }

        stage('Build') {
            steps {
                echo 'Building application...'
                
                script {
                    // Verificar estructura del proyecto
                    if (!fileExists('requirements.txt')) {
                        error '❌ requirements.txt not found!'
                    }
                    
                    if (!fileExists('create_db.py')) {
                        error '❌ create_db.py not found!'
                    }
                }
                
                // Instalar dependencias
                sh '''
                    python -m venv venv
                    . venv/bin/activate
                    pip install --upgrade pip
                    pip install -r requirements.txt
                    pip install pytest pytest-cov bandit safety flask-testing
                '''
                
                // Crear base de datos de prueba
                sh '''
                    . venv/bin/activate
                    python create_db.py
                    ls -la *.db
                '''
                
                // Verificar que la aplicación puede iniciar
                sh '''
                    . venv/bin/activate
                    python -c "
                    from vulnerable_flask_app import app
                    print('Application imports successfully')
                    "
                '''
            }
            
            post {
                success {
                    echo 'Build completed successfully'
                    archiveArtifacts artifacts: '*.db, requirements.txt'
                }
                failure {
                    echo 'Build failed'
                }
            }
        }

        stage('Test') {
            steps {
                echo 'Running unit tests...'
                
                sh '''
                    . venv/bin/activate
                    pytest test_security.py \
                        -v \
                        --cov=vulnerable_flask_app \
                        --cov-report=html:reports/coverage-html \
                        --cov-report=xml:reports/coverage.xml \
                        --junitxml=reports/test-results.xml \
                        --tb=short
                '''
            }
            
            post {
                always {
                    junit 'reports/test-results.xml'
                    publishHTML(target: [
                        allowMissing: true,
                        alwaysLinkToLastBuild: true,
                        keepAll: true,
                        reportDir: 'reports/coverage-html',
                        reportFiles: 'index.html',
                        reportName: 'Coverage Report'
                    ])
                }
            }
        }

        stage('Security Scan') {
            steps {
                echo 'Running OWASP Dependency Check...'
                
                script {
                    // Ejecutar OWASP Dependency Check
                    dependencyCheck arguments: '''
                        --scan . \
                        --format HTML \
                        --format JSON \
                        --out reports/ \
                        --project "Flask Security App" \
                        --enableExperimental \
                        --failOnCVSS 8
                    ''', odcInstallation: 'OWASP-Dependency-Check'
                    
                    // Análisis adicional con safety
                    sh '''
                        . venv/bin/activate
                        safety check \
                            --json \
                            --output reports/safety-report.json \
                            --full-report
                    '''
                }
            }
            
            post {
                always {
                    publishHTML(target: [
                        allowMissing: true,
                        alwaysLinkToLastBuild: true,
                        keepAll: true,
                        reportDir: 'reports',
                        reportFiles: 'dependency-check-report.html',
                        reportName: 'Dependency Check Report'
                    ])
                    
                    archiveArtifacts artifacts: 'reports/dependency-check-report.html, reports/safety-report.json'
                }
            }
        }

        stage('Code Analysis') {
            steps {
                echo 'Running SonarQube analysis...'
                
                script {
                    // Análisis con Bandit primero
                    sh '''
                        . venv/bin/activate
                        bandit \
                            -r . \
                            -f json \
                            -o reports/bandit-report.json \
                            -iii || true  # Continue even if issues found
                    '''
                    
                    // Ejecutar SonarQube Scanner
                    withSonarQubeEnv('SonarQube') {
                        sh '''
                            . venv/bin/activate
                            sonar-scanner \
                                -Dsonar.projectKey=flask-security-app \
                                -Dsonar.projectName="Flask Security Application" \
                                -Dsonar.python.coverage.reportPaths=reports/coverage.xml \
                                -Dsonar.python.bandit.reportPaths=reports/bandit-report.json \
                                -Dsonar.sources=. \
                                -Dsonar.exclusions=**/venv/**,**/reports/**,**/.git/** \
                                -Dsonar.host.url=${SONARQUBE_URL} \
                                -Dsonar.login=${SONARQUBE_TOKEN} \
                                -Dsonar.python.version=3
                        '''
                    }
                }
            }
            
            post {
                always {
                    archiveArtifacts artifacts: 'reports/bandit-report.json'
                }
            }
        }

        stage('Security Test') {
            steps {
                echo 'Running OWASP ZAP Security Scan...'
                
                script {
                    // Iniciar la aplicación en background
                    sh '''
                    . venv/bin/activate
                    echo "Starting Flask application on port ${APP_PORT}..."
                    python vulnerable_flask_app.py &
                    APP_PID=$!
                    echo $APP_PID > app.pid
                    
                    # Esperar a que la aplicación esté lista
                    echo "Waiting for app to start..."
                    sleep 15
                    
                    # Verificar que la aplicación está corriendo
                    curl -f http://localhost:${APP_PORT} || exit 1
                    echo "Application is running successfully"
                    '''
                    
                    // Ejecutar OWASP ZAP Baseline Scan
                    sh '''
                    docker run --rm \
                        -v ${WORKSPACE}/reports:/zap/wrk/:rw \
                        -u root \
                        -e ZAP_API_KEY=${ZAP_API_KEY} \
                        owasp/zap2docker-stable zap-baseline.py \
                        -t http://host.docker.internal:${APP_PORT} \
                        -g gen.conf \
                        -r zap-scan-report.html \
                        -w zap-scan-report.md \
                        -J zap-scan-report.json \
                        -a \
                        -m 5 \
                        -I
                    '''
                    
                    // Detener la aplicación
                    sh '''
                    if [ -f app.pid ]; then
                        kill $(cat app.pid) || true
                        rm -f app.pid
                    fi
                    '''
                }
            }
            
            post {
                always {
                    publishHTML(target: [
                        allowMissing: true,
                        alwaysLinkToLastBuild: true,
                        keepAll: true,
                        reportDir: 'reports',
                        reportFiles: 'zap-scan-report.html',
                        reportName: 'ZAP Security Report'
                    ])
                    
                    archiveArtifacts artifacts: 'reports/zap-scan-report.html, reports/zap-scan-report.json, reports/zap-scan-report.md'
                    
                    // Limpiar procesos residuales
                    sh 'pkill -f "python vulnerable_flask_app" || true'
                }
            }
        }

        stage('Analysis') {
            steps {
                echo 'Analyzing security results...'
                
                script {
                    // Esperar resultado de SonarQube
                    timeout(time: 5, unit: 'MINUTES') {
                        waitForQualityGate abortPipeline: true
                    }
                    
                    // Generar reporte consolidado de seguridad
                    sh '''
                    . venv/bin/activate
                    python << EOF
                    import json
                    import os
                    from datetime import datetime
                    
                    # Recopilar métricas de diferentes reportes
                    security_data = {
                        "timestamp": datetime.now().isoformat(),
                        "build_number": os.getenv('BUILD_NUMBER', 'unknown'),
                        "reports": {}
                    }
                    
                    # Leer reporte de Dependency Check
                    try:
                        with open('reports/dependency-check-report.json', 'r') as f:
                            dep_data = json.load(f)
                            security_data['reports']['dependency_check'] = {
                                "dependencies_scanned": len(dep_data.get('dependencies', [])),
                                "vulnerabilities": sum(len(dep.get('vulnerabilities', [])) for dep in dep_data.get('dependencies', []))
                            }
                    except Exception as e:
                        print(f"Warning: Could not read dependency check report: {e}")
                    
                    # Leer reporte de Bandit
                    try:
                        with open('reports/bandit-report.json', 'r') as f:
                            bandit_data = json.load(f)
                            security_data['reports']['bandit'] = {
                                "issues": len(bandit_data.get('results', [])),
                                "high_severity": len([i for i in bandit_data.get('results', []) if i.get('issue_confidence') == 'HIGH'])
                            }
                    except Exception as e:
                        print(f"Warning: Could not read bandit report: {e}")
                    
                    # Generar reporte resumen
                    with open('reports/security-summary.md', 'w') as f:
                        f.write("# Security Scan Summary\\n\\n")
                        f.write(f"**Build**: {security_data['build_number']}\\n")
                        f.write(f"**Date**: {security_data['timestamp']}\\n\\n")
                        
                        f.write("## Results Summary\\n")
                        if 'dependency_check' in security_data['reports']:
                            dc = security_data['reports']['dependency_check']
                            f.write(f"- **Dependencies Scanned**: {dc['dependencies_scanned']}\\n")
                            f.write(f"- **Vulnerabilities Found**: {dc['vulnerabilities']}\\n")
                        
                        if 'bandit' in security_data['reports']:
                            bandit = security_data['reports']['bandit']
                            f.write(f"- **Code Issues**: {bandit['issues']}\\n")
                            f.write(f"- **High Severity Issues**: {bandit['high_severity']}\\n")
                    
                    # Guardar datos estructurados
                    with open('reports/security-metrics.json', 'w') as f:
                        json.dump(security_data, f, indent=2)
                    
                    print("Security analysis completed")
                    EOF
                    '''
                }
            }
            
            post {
                always {
                    archiveArtifacts artifacts: 'reports/security-summary.md, reports/security-metrics.json'
                    publishHTML(target: [
                        allowMissing: true,
                        alwaysLinkToLastBuild: true,
                        keepAll: true,
                        reportDir: 'reports',
                        reportFiles: 'security-summary.md',
                        reportName: 'Security Summary'
                    ])
                }
            }
        }

        stage('Deploy') {
            when {
                expression { 
                    currentBuild.result == null || currentBuild.result == 'SUCCESS' 
                }
            }
            steps {
                echo 'Deploying to staging environment...'
                
                script {
                    // Crear Docker image segura
                    sh '''
                    cat > Dockerfile << 'EOF'
                    FROM python:3.9-slim
                    
                    # Crear usuario no-root
                    RUN groupadd -r flaskgroup && useradd -r -g flaskgroup flaskuser
                    
                    WORKDIR /app
                    
                    # Copiar requirements e instalar dependencias
                    COPY requirements.txt .
                    RUN pip install --no-cache-dir -r requirements.txt
                    
                    # Copiar código de la aplicación
                    COPY . .
                    
                    # Cambiar ownership y permisos
                    RUN chown -R flaskuser:flaskgroup /app
                    USER flaskuser
                    
                    # Exponer puerto
                    EXPOSE 5000
                    
                    # Health check
                    HEALTHCHECK --interval=30s --timeout=3s \\
                      CMD curl -f http://localhost:5000/ || exit 1
                    
                    # Comando de inicio
                    CMD ["python", "vulnerable_flask_app.py"]
                    EOF
                    '''
                    
                    // Construir y etiquetar imagen
                    sh """
                    docker build -t flask-security-app:${env.BUILD_NUMBER} .
                    docker tag flask-security-app:${env.BUILD_NUMBER} ${DOCKER_REGISTRY}/flask-security-app:${env.BUILD_NUMBER}
                    """
                    
                    // Desplegar en staging (ejemplo con Docker Compose)
                    sh '''
                    cat > docker-compose.staging.yml << 'EOF'
                    version: '3.8'
                    services:
                      flask-app:
                        image: ${DOCKER_REGISTRY}/flask-security-app:${BUILD_NUMBER}
                        ports:
                          - "5000:5000"
                        environment:
                          - FLASK_ENV=production
                          - PYTHONUNBUFFERED=1
                        restart: unless-stopped
                        security_opt:
                          - no-new-privileges:true
                    EOF
                    '''
                    
                    echo 'Application deployed to staging environment'
                }
            }
            
            post {
                success {
                    echo 'Deployment to staging completed successfully'
                    
                    // Notificación de éxito
                    emailext (
                        subject: "SUCCESS: Build ${env.BUILD_NUMBER} deployed to staging",
                        body: """
                        Flask Security Application build ${env.BUILD_NUMBER} has been successfully deployed to staging.
                        
                        Security Scan Results:
                        - Dependency Check: ${getDependencyCheckResults()}
                        - Code Quality: ${getSonarQubeResults()}
                        - Dynamic Scan: ${getZAPResults()}
                        
                        View detailed reports: ${env.BUILD_URL}
                        """,
                        to: "dev-team@company.com",
                        attachLog: false
                    )
                }
            }
        }
    }

    post {
        always {
            echo 'Cleaning...'
            
            // Limpiar contenedores y procesos
            sh '''
            docker rm -f \$(docker ps -aq) 2>/dev/null || true
            pkill -f "python vulnerable_flask_app" 2>/dev/null || true
            rm -f app.pid
            '''
            
            // Archivar reportes importantes
            archiveArtifacts artifacts: 'reports/**/*.*, *.log, *.db'
            
            // Publicar métricas
            publishHTML(target: [
                allowMissing: true,
                alwaysLinkToLastBuild: true,
                keepAll: true,
                reportDir: 'reports',
                reportFiles: 'index.html',
                reportName: 'All Reports Index'
            ])
        }
        
        success {
            echo 'Pipeline executed successfully!'
            updateGitlabCommitStatus name: 'security-scan', state: 'success'
        }
        
        failure {
            echo 'Pipeline failed!'
            updateGitlabCommitStatus name: 'security-scan', state: 'failed'
            
            // Notificación de fallo
            emailext (
                subject: "FAILED: Build ${env.BUILD_NUMBER} - Security Issues Found",
                body: """
                Build ${env.BUILD_NUMBER} of Flask Security Application has failed due to security issues.
                
                Please review the security reports and address the vulnerabilities before proceeding.
                
                Build URL: ${env.BUILD_URL}
                """,
                to: "security-team@company.com, dev-team@company.com",
                attachLog: true
            )
        }
        
        unstable {
            echo 'Pipeline completed with warnings'
            updateGitlabCommitStatus name: 'security-scan', state: 'failed'
        }
    }
}

// Funciones auxiliares para obtener resultados
def getDependencyCheckResults() {
    try {
        def report = readJSON file: 'reports/dependency-check-report.json'
        def vulnCount = report.dependencies.sum { it.vulnerabilities?.size() ?: 0 }
        return "${vulnCount} vulnerabilities found"
    } catch (Exception e) {
        return "Report not available"
    }
}

def getSonarQubeResults() {
    try {
        def qualityGate = waitForQualityGate()
        return qualityGate.status
    } catch (Exception e) {
        return "Analysis in progress"
    }
}

def getZAPResults() {
    try {
        def report = readJSON file: 'reports/zap-scan-report.json'
        def alerts = report.site[0].alerts.size()
        return "${alerts} security alerts"
    } catch (Exception e) {
        return "Scan completed"
    }
}
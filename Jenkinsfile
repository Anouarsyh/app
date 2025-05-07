pipeline {
    agent {
        docker {
            image 'python:3.9'
            args '-v /var/run/docker.sock:/var/run/docker.sock'
        }
    }
    
    environment {
        SONAR_HOST_URL = 'http://sonarqube:9000'
        SONAR_TOKEN = credentials('sonar-token')
        GITHUB_REPO = 'https://github.com/Anouarsyh/app.git'
    }
    
    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }
        
        stage('Install Dependencies') {
            steps {
                sh 'pip install -r requirements.txt'
                sh 'pip install pylint bandit safety'
            }
        }
        
        stage('Linting') {
            steps {
                sh 'pylint --disable=C0111,C0103,C0303,C0301,W1202,C0330,C0326,W0702,R0914,R0913,R0915,R0912,R0801,W0612,W0613,W0621,W0703 *.py || true'
            }
        }
        
        stage('Secret Detection') {
            steps {
                sh '''
                pip install detect-secrets
                detect-secrets scan --baseline .secrets.baseline || true
                '''
            }
        }
        
        stage('SCA - Dependency Check') {
            steps {
                sh 'safety check -r requirements.txt --output text'
            }
        }
        
        stage('SAST - Bandit') {
            steps {
                sh 'bandit -r . -f json -o bandit-results.json || true'
            }
        }
        
        stage('SAST - SonarQube Analysis') {
            steps {
                withSonarQubeEnv('SonarQube') {
                    sh '''
                    pip install sonar-scanner-cli
                    sonar-scanner \
                      -Dsonar.projectKey=edr-automation \
                      -Dsonar.projectName="EDR Automation" \
                      -Dsonar.sources=. \
                      -Dsonar.python.coverage.reportPaths=coverage.xml \
                      -Dsonar.host.url=${SONAR_HOST_URL} \
                      -Dsonar.login=${SONAR_TOKEN}
                    '''
                }
            }
        }
        
        stage('Quality Gate') {
            steps {
                timeout(time: 10, unit: 'MINUTES') {
                    waitForQualityGate abortPipeline: false
                }
            }
        }
        
        stage('Build Docker Image') {
            steps {
                sh 'docker build -t edr-automation:${BUILD_NUMBER} .'
            }
        }
        
        stage('Security Scan Docker Image') {
            steps {
                sh '''
                docker pull aquasec/trivy:latest
                docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy:latest image edr-automation:${BUILD_NUMBER}
                '''
            }
        }
    }
    
    post {
        always {
            archiveArtifacts artifacts: 'bandit-results.json', allowEmptyArchive: true
            cleanWs()
        }
        success {
            echo 'Pipeline completed successfully!'
        }
        failure {
            echo 'Pipeline failed!'
        }
    }
}

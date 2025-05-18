pipeline {
    agent any
    
    tools {
        python 'Python3'
    }
    
    environment {
        SONAR_HOST_URL = 'http://sonarqube:9000'
        SONAR_LOGIN = credentials('SONAR_TOKEN')
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
                sh 'pip install pylint pytest safety bandit'
            }
        }
        
        stage('Linting') {
            steps {
                sh 'pylint --exit-zero --output-format=parseable app/ > pylint-report.txt'
                recordIssues tools: [pyLint(pattern: 'pylint-report.txt')]
            }
        }
        
        stage('Security Checks') {
            parallel {
                stage('Dependency Check') {
                    steps {
                        sh 'mkdir -p reports'
                        sh 'safety check -r requirements.txt --json > reports/dependency-check.json || true'
                    }
                }
                
                stage('SAST with Bandit') {
                    steps {
                        sh 'bandit -r app/ -f json -o reports/bandit-report.json || true'
                    }
                }
            }
        }
        
        stage('Unit Tests') {
            steps {
                sh 'pytest --junitxml=test-results.xml || true'
                junit 'test-results.xml'
            }
        }
        
        stage('SonarQube Analysis') {
            steps {
                withSonarQubeEnv('SonarQube') {
                    sh '''
                        sonar-scanner \
                        -Dsonar.projectKey=streamlit-app \
                        -Dsonar.projectName='Streamlit API Automation App' \
                        -Dsonar.sources=. \
                        -Dsonar.python.coverage.reportPaths=coverage.xml \
                        -Dsonar.python.xunit.reportPath=test-results.xml \
                        -Dsonar.python.pylint.reportPath=pylint-report.txt \
                        -Dsonar.python.bandit.reportPaths=reports/bandit-report.json
                    '''
                }
                timeout(time: 2, unit: 'MINUTES') {
                    waitForQualityGate abortPipeline: false
                }
            }
        }
    }
    
    post {
        always {
            archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true
            recordIssues enabledForFailure: true, tools: [pyLint(pattern: 'pylint-report.txt')]
            cleanWs()
        }
    }
}

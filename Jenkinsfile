pipeline {
    agent any

    environment {
        SONAR_HOST_URL = 'http://192.168.1.73:9000'
        SONAR_TOKEN = credentials('sonar-token')
        GITHUB_REPO = 'https://github.com/Anouarsyh/app.git'
    }
    
    stages {
        stage('Setup Environment') {
            steps {
                sh 'bash setup.sh || echo "Creating setup script" && echo "#!/bin/bash\\necho \\"Setup environment executed\\"" > setup.sh && chmod +x setup.sh'
            }
        }

        stage('Checkout') {
            steps {
                git branch: 'main', url: "${GITHUB_REPO}"
            }
        }

        stage('Install Dependencies') {
            steps {
                sh '''
                python3 -m venv venv
                source venv/bin/activate
                pip install --upgrade pip
                pip install -r requirements.txt
                pip install pylint bandit safety detect-secrets pytest pytest-cov
                '''
            }
        }

        stage('Linting') {
            steps {
                catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                    sh '''
                    source venv/bin/activate
                    pylint --disable=C0111,C0103,C0303,C0301,W1202,C0330,C0326,W0702,R0914,R0913,R0915,R0912,R0801,W0612,W0613,W0621,W0703 *.py || true
                    '''
                }
            }
        }

        stage('Secret Detection') {
            steps {
                catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                    sh '''
                    source venv/bin/activate
                    if [ ! -f .secrets.baseline ]; then
                        detect-secrets scan > .secrets.baseline
                    fi
                    detect-secrets scan --baseline .secrets.baseline
                    '''
                }
            }
        }

        stage('Unit Tests') {
            steps {
                sh '''
                source venv/bin/activate
                pytest --cov=. --cov-report=xml || echo "No tests found or tests failed"
                '''
            }
        }

        stage('SCA - Dependency Check') {
            steps {
                catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                    sh '''
                    source venv/bin/activate
                    safety check -r requirements.txt --output text
                    '''
                }
            }
        }

        stage('SAST - Bandit') {
            steps {
                catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                    sh '''
                    source venv/bin/activate
                    bandit -r . -f json -o bandit-results.json
                    '''
                }
            }
        }

        stage('SAST - SonarQube Analysis') {
            steps {
                withSonarQubeEnv('SonarQube') {
                    sh '''
                    source venv/bin/activate
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
                    waitForQualityGate abortPipeline: true
                }
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'bandit-results.json, coverage.xml', allowEmptyArchive: true
            cleanWs()
        }
        success {
            echo '✅ Pipeline completed successfully!'
        }
        failure {
            echo '❌ Pipeline failed.'
        }
    }
}

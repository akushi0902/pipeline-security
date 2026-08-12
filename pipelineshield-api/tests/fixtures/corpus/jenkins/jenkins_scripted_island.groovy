pipeline {
    agent any
    stages {
        stage('Security Scan') {
            steps {
                sh 'gitleaks detect --source . --exit-code 1'
                sh 'trivy fs --exit-code 1 .'
            }
        }
        stage('Legacy Scripted Block') {
            steps {
                // Intentional scripted island — content is Not Assessable
                script {
                    def legacyConfig = [:]
                    legacyConfig['endpoint'] = env.DEPLOY_ENDPOINT ?: 'https://deploy.example.com'
                    legacyConfig['token'] = env.SERVICE_ACCOUNT_TOKEN
                    if (legacyConfig['token']) {
                        sh "curl -H 'Authorization: Bearer ${legacyConfig['token']}' ${legacyConfig['endpoint']}/deploy"
                    } else {
                        error 'SERVICE_ACCOUNT_TOKEN is required'
                    }
                }
            }
        }
        stage('Build') {
            steps {
                sh 'mvn clean package'
                sh 'docker build -t myapp:latest .'
            }
        }
    }
}

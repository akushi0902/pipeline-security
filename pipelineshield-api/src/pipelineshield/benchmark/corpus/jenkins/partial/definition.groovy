pipeline {
    agent any
    stages {
        stage('Security Scan') {
            steps {
                sh 'gitleaks detect --source . --exit-code 1'
                sh 'semgrep --config=auto .'
                sh 'trivy fs --exit-code 1 .'
            }
        }
        stage('Build') {
            steps {
                sh 'mvn clean package'
                sh 'docker build -t myapp:$BUILD_NUMBER .'
                sh 'docker push myapp:$BUILD_NUMBER'
            }
        }
        stage('Deploy') {
            steps {
                sh "kubectl apply -f k8s/"
            }
        }
    }
    post {
        always {
            sh 'echo "token=hardcoded_service_token_value" >> /etc/app.conf'
        }
    }
}

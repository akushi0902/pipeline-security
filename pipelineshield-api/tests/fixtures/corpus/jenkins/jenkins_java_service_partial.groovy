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
                sh 'mvn clean package -DskipTests'
                sh 'docker build -t myapp:$GIT_COMMIT .'
                sh 'docker push myapp:$GIT_COMMIT'
            }
        }
        stage('Deploy') {
            steps {
                withCredentials([string(credentialsId: 'k8s-token', variable: 'K8S_TOKEN')]) {
                    sh "SERVICE_KEY=EXAMPLE_hardcoded_service_key_jenkins_xyz kubectl apply -f k8s/"
                }
            }
        }
    }
}

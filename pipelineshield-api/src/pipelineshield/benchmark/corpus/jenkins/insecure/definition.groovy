pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                sh 'mvn clean package'
                sh 'docker build -t myapp:latest .'
                sh 'docker push myapp:latest'
            }
        }
        stage('Deploy') {
            steps {
                withCredentials([string(credentialsId: 'deploy-token', variable: 'TOKEN')]) {
                    sh "kubectl apply -f k8s/"
                }
            }
        }
    }
    post {
        always {
            sh 'echo "password=hardcoded_deploy_password_value" > /tmp/deploy.cfg'
        }
    }
}

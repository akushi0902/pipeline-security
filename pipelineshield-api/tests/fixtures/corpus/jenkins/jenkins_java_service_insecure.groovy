pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                sh 'mvn clean package -DskipTests'
                sh 'docker build -t myapp:latest .'
                sh 'docker push myapp:latest'
            }
        }
        stage('Test') {
            steps {
                sh 'mvn test'
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
            sh 'echo "db_password=EXAMPLE_hardcoded_db_password_jenkins_abc" > /tmp/cfg'
        }
    }
}

pipeline {
    agent {
        kubernetes {
            yaml '''
apiVersion: v1
kind: Pod
spec:
  serviceAccountName: jenkins-sa-restricted
  containers:
  - name: build
    image: maven:3.9-eclipse-temurin-21@sha256:abc123def456789abcdef0123456789abcdef0123456789
    command: [cat]
    tty: true
'''
        }
    }
    stages {
        stage('Security Scan') {
            steps {
                sh 'gitleaks detect --source . --exit-code 1'
                sh 'semgrep --config=auto .'
                sh 'trivy fs --exit-code 1 .'
                sh 'trivy image --exit-code 1 myapp:latest'
                sh 'checkov -d . --quiet'
            }
        }
        stage('Build') {
            steps {
                sh 'mvn clean package -DskipTests'
                sh 'docker build -t myapp:$GIT_COMMIT .'
                sh 'syft myapp:$GIT_COMMIT -o cyclonedx-json > sbom.json'
                sh 'docker push myapp:$GIT_COMMIT'
            }
        }
        stage('Sign') {
            steps {
                sh 'cosign sign --key env://COSIGN_KEY myapp:$GIT_COMMIT'
                sh 'cosign attest --predicate provenance.json myapp:$GIT_COMMIT'
            }
        }
        stage('Deploy') {
            when { branch 'main' }
            input {
                message 'Deploy to production?'
                ok 'Deploy'
            }
            steps {
                withCredentials([[
                    $class: 'AmazonWebServicesCredentialsBinding',
                    credentialsId: 'aws-oidc-role',
                    accessKeyVariable: 'AWS_ACCESS_KEY_ID',
                    secretKeyVariable: 'AWS_SECRET_ACCESS_KEY'
                ]]) {
                    sh 'kubectl apply -f k8s/'
                }
            }
        }
    }
}

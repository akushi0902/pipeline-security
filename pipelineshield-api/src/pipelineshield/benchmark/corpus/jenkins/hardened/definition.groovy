pipeline {
    agent any
    stages {
        stage('Security Scan') {
            steps {
                sh 'gitleaks detect --source . --exit-code 1'
                sh 'semgrep --config=auto .'
                sh 'trivy fs --exit-code 1 .'
                sh 'checkov -d . --quiet'
            }
        }
        stage('Build') {
            steps {
                sh 'mvn clean package'
                sh 'docker build -t myapp:${BUILD_NUMBER} .'
            }
        }
        stage('Generate SBOM') {
            steps {
                sh 'syft myapp:${BUILD_NUMBER} -o cyclonedx-json > sbom.json'
                sh 'docker push myapp:${BUILD_NUMBER}'
            }
        }
        stage('Sign') {
            steps {
                sh 'cosign sign --key env://COSIGN_KEY myapp:${BUILD_NUMBER}'
                sh 'cosign attest --predicate provenance.json myapp:${BUILD_NUMBER}'
            }
        }
        stage('Approval Gate') {
            steps {
                timeout(time: 60, unit: 'MINUTES') {
                    input 'Deploy to production?'
                }
            }
        }
        stage('Deploy') {
            steps {
                sh 'kubectl apply -f k8s/'
            }
        }
    }
}

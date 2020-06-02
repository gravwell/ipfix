pipeline {
    agent {
        docker { image 'golang:latest' }
    }

    environment {
        GOPATH=pwd()
    }

    stages {
        stage('Pull') {
            steps {
                dir('src/github.com/gravwell/ipfix') {
                    checkout scm
                }
            }
        }

        stage('Test') {
            steps {
                sh 'cd src/github.com/gravwell/ipfix && go test'
            }
        }
    }
}
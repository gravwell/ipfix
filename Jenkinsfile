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
                dir('src/github.com/floren/ipfix') {
                    checkout scm
                }
            }
        }

        stage('Test') {
            steps {
                sh 'cd src/github.com/floren/ipfix && go test'
            }
        }
    }
}
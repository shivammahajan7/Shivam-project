pipeline {
    agent any
    stages {
        stage ('SCM checkout') {
            steps {
                git branch: 'main', url: 'https://github.com/ghorpadesaloni/securefiletransfersystem1.git'
            }
        }
        stage ('docker image build') {
            steps {
                        sh 'docker-compose build'
                    }
        }    
        stage ('docker login') {
            steps {
                sh 'echo  | /usr/bin/docker login -u salonighorpade --password-stdin'
            }
        }
        stage ('docker image push') {
            steps {
                sh 'docker image push salonighorpade/securefrontend'
            }
        }
        stage ('get the confirmation from user') {
            steps {
                input 'Do you want to deploy this application?'
            }
        }
        stage ('remove existing service') {
            steps {
                sh 'docker-compose down'
            }
        }
        stage ('create docker service') {
            steps {
                sh 'docker-compose up -d'
            }
        }
    }
}

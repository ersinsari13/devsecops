pipeline {
    agent any
    tools {
        jdk 'jdk11'
        maven 'maven'
    }
    stages {
        stage("Git Checkout") {
            steps {
                git branch: 'main', changelog: false, poll: false, url: 'https://github.com/ersinsari13/devsecops.git'
            }
        }
        stage("Compile") {
            steps {
                sh "mvn clean compile"
            }
        }
        stage("Test Cases") {
            steps {
                sh "mvn test"
            }
        }
        stage("Sonarqube Analysis") {
            steps {
                withSonarQubeEnv('sonar-server') {
                    sh ''' 
                        mvn clean verify sonar:sonar \
                        -Dsonar.projectKey=Petclinic
                    '''
                }
            }
        }
        stage("Quality Gate") {
            steps {
                timeout(time: 2, unit: 'MINUTES') {
                    script {
                        waitForQualityGate abortPipeline: true
                    }
                }
            }
        }
        stage("Build"){
            steps{
                sh " mvn clean install"
            }
        }
        stage('OWASP FS SCAN') {
            steps {
                withEnv(["PATH+DC=${tool 'DP-Check'}/bin"]) {
                    dependencyCheck additionalArguments: '--scan ./ --disableYarnAudit --disableNodeAudit', odcInstallation: 'DP-Check'
                    dependencyCheckPublisher pattern: '**/dependency-check-report.xml'
        }
    }
}

    }
}

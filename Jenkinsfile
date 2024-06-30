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
        stage("Build") {
            steps {
                sh "mvn clean install"
            }
        }
        stage('OWASP-Dependency-Check') {
            steps {
                sh "mvn dependency-check:check"
            }
            post {
                always {
                    dependencyCheckPublisher pattern: 'target/dependency-check-report.xml'
                }
            }
        }
        
        stage('Scan Dockerfile with conftest') {
            steps {
                echo 'Scanning Dockerfile'
                sh "docker run --rm -v $(pwd):/project openpolicyagent/conftest test --policy dockerfile-conftest.rego Dockerfile"
            }
        }
        
        stage('Prepare Tags for Docker Images') {
            steps {
                echo 'Preparing Tags for Docker Images'
                script {
                    MVN_VERSION=sh(script:'. ${WORKSPACE}/target/maven-archiver/pom.properties && echo $version', returnStdout:true).trim()
                    env.IMAGE_TAG_DEVSECOPS="ersinsari/devsecops:${MVN_VERSION}-b${BUILD_NUMBER}"
                }
            }
        }
        stage('Build App Docker Images') {
            steps {
                echo 'Building App Dev Images'
                sh "docker build --force-rm -t ${IMAGE_TAG_DEVSECOPS} ."
                sh 'docker image ls'
            }
        }
        stage('Scan Image with Trivy') {
            steps {
                script {
                    def scanResult = sh(script: "trivy image --severity CRITICAL --exit-code 1 ${IMAGE_TAG_DEVSECOPS}", returnStatus: true)
                    if (scanResult != 0) {
                        error "Critical vulnerabilities found in Docker image. Failing the pipeline."
                    }
                }
            }
        }
    }
}
node {
  stage('SCM') {
    checkout scm
  }
  stage('SonarQube Analysis') {
    def scannerHome = tool 'SonarScanner';
    withSonarQubeEnv() {
      sh "${scannerHome}/bin/sonar-scanner"
    }
  }
  stage('SCA - OWASP Dependency-Check') {
      steps {
        sh 'mkdir -p reports/dependency-check .dc-cache'
        dependencyCheck(
          odcInstallation: 'Dependency-Check',
          additionalArguments: """
            --scan .
            --out reports/dependency-check
            --format XML
            --format HTML
            --format SARIF
            --data .dc-cache
            --nvdApiKey=${NVD_API_KEY}
            --disableAssembly
          """.trim()
        )
      }
    }
}

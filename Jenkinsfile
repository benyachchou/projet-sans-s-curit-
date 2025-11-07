node {
  stage('SCM') {
    checkout scm
  }

  stage('SonarQube Analysis') {
    // Le nom doit correspondre à ton Tool SonarQube Scanner (d'après tes logs: "SonarQube")
    def scannerHome = tool 'SonarQube'
    // Si ton serveur Sonar s'appelle "SonarQube" dans Jenkins → Configure System
    withSonarQubeEnv('SonarQube') {
      sh """
        "${scannerHome}/bin/sonar-scanner" \
          -Dsonar.projectKey=secure-api \
          -Dsonar.projectName=secure-api \
          -Dsonar.sources=. \
          -Dsonar.sourceEncoding=UTF-8 \
          -Dsonar.exclusions=**/node_modules/**,**/*.test.js,**/*.spec.js,**/coverage/**,**/*.map
      """
    }
  }

  stage('Quality Gate') {
    timeout(time: 15, unit: 'MINUTES') {
      def qg = waitForQualityGate()
      if (qg.status != 'OK') {
        error "Quality Gate: ${qg.status}"
      }
    }
  }

  stage('SCA - OWASP Dependency-Check') {
    // Binder la clé NVD stockée en credential "NVD_API_KEY"
    withCredentials([string(credentialsId: 'NVD_API_KEY', variable: 'NVD_API_KEY')]) {
      // Créer les dossiers nécessaires
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

      // Publications (résultats visibles dans le job)
      dependencyCheckPublisher(
        pattern: 'reports/dependency-check/dependency-check-report.xml',
        stopBuild: false
      )
      publishHTML(target: [
        reportDir: 'reports/dependency-check',
        reportFiles: 'dependency-check-report.html',
        reportName: 'OWASP Dependency-Check',
        allowMissing: true,
        keepAll: true
      ])
      recordIssues(
        tools: [sarif(pattern: 'reports/dependency-check/dependency-check-report.sarif')],
        qualityGates: [[threshold: 1, type: 'TOTAL', unstable: true]]
      )
      archiveArtifacts artifacts: 'reports/dependency-check/**', allowEmptyArchive: true
    }
  }

  stage('Deploy (if OK)') {
    echo 'Déploiement…'
    // docker build/push, kubectl apply, etc.
  }
}

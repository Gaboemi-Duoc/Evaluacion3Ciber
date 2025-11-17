pipeline {
    agent any

    stages {
        stage(&#39;Build&#39;) {
            steps {
                echo &#39;Compilando el código fuente...&#39;
                // Para un proyecto real, aquí irían comandos como:
                // sh &#39;mvn clean install&#39; o &#39;npm install&#39;
            }
        }
        stage(&#39;Test&#39;) {
            steps {
            echo &#39;Ejecutando pruebas unitarias...&#39;
            // Aquí irían comandos para ejecutar pruebas, como:
            // sh &#39;mvn test&#39;
            }
        }
        stage(&#39;Deploy&#39;) {
            steps {
                echo &#39;Desplegando la aplicación a un entorno de prueba...&#39;
                // En un escenario real, esto podría construir una imagen Docker
                // y desplegarla en un servidor.
                archiveArtifacts artifacts: &#39;index.html&#39;, followSymlinks: false
            }
        }
    }
    post {
        success {
            echo &#39;Pipeline ejecutado exitosamente!&#39;
        }
        failure {
            echo &#39;El pipeline ha fallado.&#39;
        }
    }
}
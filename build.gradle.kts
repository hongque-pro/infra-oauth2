plugins {
    id("com.labijie.infra") version Versions.infraPlugin
}

allprojects {
    group = "com.labijie.infra"
    version = "2.1.0"

    infra {
        useDefault {
            includeSource = true
            includeDocument = true
            infraBomVersion = Versions.infraBom
            kotlinVersion = Versions.kotlin
            useMavenProxy = false
        }
    }
}
subprojects {
    if(!project.name.startsWith("dummy")){
        infra {
            publishing {
                pom {
                    description = "infrastructure for oauth2 library"
                    githubUrl("hongque-pro", "infra-oauth2")
                }

                toGithubPackages("hongque-pro", "infra-oauth2")
            }
        }
    }
}




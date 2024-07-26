plugins {
    id("com.labijie.infra") version Versions.infraPlugin
}

allprojects {
    group = "com.labijie.infra"
    version = "2.0.3"

    infra {
        useDefault {
            includeSource = true
            includeDocument = true
            infraBomVersion = Versions.infraBom
            kotlinVersion = Versions.kotlin
            useMavenProxy = false
            jvmVersion = "17"
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




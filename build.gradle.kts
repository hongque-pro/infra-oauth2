plugins {
    id("com.labijie.infra") version Versions.infraPlugin
}

allprojects {
    group = "com.labijie.infra"
    version = "1.2.4"

    infra {
        useDefault {
            includeSource = true
            infraBomVersion = Versions.infraBom
            kotlinVersion = Versions.kotlin
            useMavenProxy = false

            addHongQueGitHubPackages()
        }

        useNexusPublish()
    }
}
subprojects {
    if(!project.name.startsWith("dummy")){
        infra {
            usePublish {
                description = "infrastructure for oauth2 library"
                githubUrl("hongque-pro", "infra-oauth2")
            }

            useGitHubPackages("hongque-pro", "infra-oauth2")
        }
    }
}




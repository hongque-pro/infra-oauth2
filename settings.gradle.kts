rootProject.name = "infra-oauth2"

include("oauth2-commons")
include("oauth2-authorization-server-starter")
include("oauth2-resource-server-starter")
include("dummy-server")
pluginManagement {
    repositories {
        mavenLocal()
        gradlePluginPortal()
    }
}
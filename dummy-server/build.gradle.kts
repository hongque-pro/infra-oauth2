dependencies {
    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation(project(":oauth2-authorization-server-starter"))
    implementation(project(":oauth2-resource-server-starter"))
}
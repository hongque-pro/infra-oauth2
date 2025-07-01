dependencies {
    api(project(":oauth2-commons"))
    api("org.springframework.security:spring-security-oauth2-resource-server")
    api("org.springframework.security:spring-security-oauth2-jose")
    api("org.springframework.boot:spring-boot-starter-security")
    api("org.springframework.boot:spring-boot-starter-web")
    api("org.springframework.boot:spring-boot-starter-oauth2-client")


    compileOnly("org.springframework.boot:spring-boot-starter-actuator")

    implementation("com.labijie:caching-kotlin-core-starter:${Versions.infraCaching}")
    //testImplementation(project(":oauth2-auth-server-starter"))
    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation(project(":dummy-auth-server-starter"))
}
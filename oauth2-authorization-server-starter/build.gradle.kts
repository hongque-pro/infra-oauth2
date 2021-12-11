dependencies {
    api(project(":oauth2-commons"))
    api("org.springframework.boot:spring-boot-starter-security")
    api("org.springframework.security:spring-security-oauth2-authorization-server:${Versions.springAuthorizationServer}")


    implementation("org.springframework:spring-jdbc")


    implementation("com.labijie:caching-kotlin:${Versions.infraCaching}")

    compileOnly("com.labijie:caching-kotlin-redis-starter:${Versions.infraCaching}")
    compileOnly("org.springframework.boot:spring-boot-starter-actuator")

    testImplementation("com.labijie:caching-kotlin-core-starter:${Versions.infraCaching}")
    testImplementation("org.springframework.boot:spring-boot-starter-web")
    testImplementation("org.springframework.boot:spring-boot-starter-test")
}
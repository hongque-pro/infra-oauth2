dependencies {
    api(project(":oauth2-commons"))
    api("org.springframework.boot:spring-boot-starter-jdbc")
    api("org.springframework.boot:spring-boot-starter-security")
    api("org.springframework.boot:spring-boot-starter-web")
    api("org.springframework.security:spring-security-oauth2-authorization-server")
    compileOnly("com.esotericsoftware:kryo")

    implementation("com.labijie:caching-kotlin:${Versions.infraCaching}")

    compileOnly("com.labijie:caching-kotlin-redis-starter:${Versions.infraCaching}")
    compileOnly("org.springframework.boot:spring-boot-starter-actuator")

    testImplementation("com.labijie:caching-kotlin-redis-starter:${Versions.infraCaching}")
    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("com.esotericsoftware:kryo")
}
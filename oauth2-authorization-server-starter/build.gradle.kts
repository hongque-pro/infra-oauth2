infra {
    useKotlinSerializationPlugin()
    //useSpringConfigurationProcessor()
}

dependencies {
    api(project(":oauth2-commons"))
    api("org.springframework.boot:spring-boot-starter-jdbc")
    api("org.springframework.boot:spring-boot-starter-security")
    api("org.springframework.boot:spring-boot-starter-web")
    api("org.springframework.security:spring-security-oauth2-authorization-server")
    api("org.springframework.boot:spring-boot-starter-oauth2-client")
    api("jakarta.validation:jakarta.validation-api")


    compileOnly("com.esotericsoftware:kryo")
    compileOnly("org.jetbrains.kotlinx:kotlinx-serialization-json")
    compileOnly("org.jetbrains.kotlinx:kotlinx-serialization-protobuf")

    implementation("com.labijie:caching-kotlin:${Versions.infraCaching}")

    compileOnly("com.labijie:caching-kotlin-redis-starter:${Versions.infraCaching}")
    compileOnly("org.springframework.boot:spring-boot-starter-actuator")

    testImplementation("com.labijie:caching-kotlin-redis-starter:${Versions.infraCaching}")
    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("com.esotericsoftware:kryo")
    testImplementation("org.jetbrains.kotlinx:kotlinx-serialization-json")
    testImplementation("org.jetbrains.kotlinx:kotlinx-serialization-protobuf")
}
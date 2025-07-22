
dependencies {
    api("com.labijie.infra:commons-core:${Versions.infraCommons}")
    api("org.springframework.boot:spring-boot-starter-web")
//    api 'javax.xml.bind:jaxb-api'
//    api 'com.sun.xml.bind:jaxb-core'
//    api 'com.sun.xml.bind:jaxb-impl'
//    api("com.nimbusds:nimbus-jose-jwt:$nimbus_jose_jwt_version")

//    api "org.springframework.security:spring-security-oauth2-core: $spring_security_version"
    api("org.springframework.security:spring-security-oauth2-core")
    api("com.nimbusds:oauth2-oidc-sdk:${Versions.oauth2OidcSdk}")
    api("com.fasterxml.jackson.dataformat:jackson-dataformat-smile")

    api("org.springframework.boot:spring-boot-starter-oauth2-client")

    compileOnly("org.springframework.security:spring-security-web")
    compileOnly("org.springframework.security:spring-security-config")

    compileOnly("org.graalvm.nativeimage:svm:${Versions.graalvmSvm}")
}
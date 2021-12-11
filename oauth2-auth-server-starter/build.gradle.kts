dependencies {
  api(project(":oauth2-commons"))
  api("org.springframework.boot:spring-boot-starter-security")
  api("org.springframework.security.oauth.boot:spring-security-oauth2-autoconfigure:${Versions.springSecurityOauth2}")
  compileOnly("org.springframework.boot:spring-boot-starter-data-redis")
  testImplementation("org.springframework.boot:spring-boot-starter-web")
  testImplementation ("org.springframework.boot:spring-boot-starter-test")
}
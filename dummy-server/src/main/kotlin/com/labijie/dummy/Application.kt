package com.labijie.dummy

import org.springframework.boot.SpringApplication
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity

/**
 *
 * @Author: Anders Xiao
 * @Date: 2021/12/11
 * @Description:
 */
@EnableWebSecurity
@SpringBootApplication
class Application


fun main(){
    SpringApplication.run(Application::class.java)
}
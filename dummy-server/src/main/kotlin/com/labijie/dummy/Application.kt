package com.labijie.dummy

import org.springframework.boot.SpringApplication
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

/**
 *
 * @Author: Anders Xiao
 * @Date: 2021/12/11
 * @Description:
 */
@EnableWebSecurity
@RestController
@SpringBootApplication(exclude = [DataSourceAutoConfiguration::class])
class Application{

    @GetMapping("/test")
    fun startSource(): String {
        return "dummy application"
    }

    @GetMapping("/test2")
    fun t2(): String {
        return "permitted"
    }
}

fun main(){
    SpringApplication.run(Application::class.java)
}
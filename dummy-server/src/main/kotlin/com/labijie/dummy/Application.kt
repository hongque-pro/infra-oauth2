package com.labijie.dummy

import com.labijie.infra.oauth2.annotation.DisableWebSecurity
import org.springframework.boot.SpringApplication
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration

/**
 *
 * @Author: Anders Xiao
 * @Date: 2021/12/11
 * @Description:
 */
@SpringBootApplication(exclude = [DataSourceAutoConfiguration::class])
@DisableWebSecurity
class Application


fun main(){
    SpringApplication.run(Application::class.java)
}
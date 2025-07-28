package com.labijie.dummy

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
class Application


fun main(){
    SpringApplication.run(Application::class.java)
}
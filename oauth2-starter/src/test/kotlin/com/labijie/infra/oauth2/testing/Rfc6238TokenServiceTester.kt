package com.labijie.infra.oauth2.testing

import com.labijie.infra.security.Rfc6238TokenService
import org.junit.Assert
import org.junit.Test
import java.io.Console
import java.util.*

/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-07-14
 */
class Rfc6238TokenServiceTester {

    private val rfc6238TokenService = Rfc6238TokenService()
    private val securityToken = UUID.randomUUID().toString().toByteArray()

    @Test
    fun generateTest(){
        repeat(100000){
            val modifier = UUID.randomUUID().toString()
            val code =  rfc6238TokenService.generateCodeString(securityToken.toString(Charsets.UTF_8),  modifier)
            Assert.assertTrue(code.length == 6)
            System.out.println(code)
            val valid = rfc6238TokenService.validateCodeString(code, securityToken.toString(Charsets.UTF_8), modifier)
            Assert.assertTrue(valid)
        }
    }

    @Test
    fun test(){
        val code = rfc6238TokenService.generateCode(securityToken)
        Assert.assertEquals(true, rfc6238TokenService.validateCode(code, securityToken))


        val code2 = rfc6238TokenService.generateCode(securityToken)
        Assert.assertEquals(false, rfc6238TokenService.validateCode(code2 + 2, securityToken))

        val modifier = UUID.randomUUID().toString()
        val code3 = rfc6238TokenService.generateCode(securityToken, modifier)
        Assert.assertEquals(true, rfc6238TokenService.validateCode(code3, securityToken, modifier))
        Assert.assertEquals(false, rfc6238TokenService.validateCode(code3, securityToken, modifier + "ccc"))
    }
}
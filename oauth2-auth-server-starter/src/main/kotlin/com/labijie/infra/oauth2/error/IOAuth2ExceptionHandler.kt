package com.labijie.infra.oauth2.error

import org.springframework.security.oauth2.common.exceptions.OAuth2Exception
import org.springframework.security.oauth2.provider.error.WebResponseExceptionTranslator

/**
 * Created with IntelliJ IDEA.
 * @author Anders Xiao
 * @date 2019-07-18
 */
interface IOAuth2ExceptionHandler : WebResponseExceptionTranslator<OAuth2Exception>
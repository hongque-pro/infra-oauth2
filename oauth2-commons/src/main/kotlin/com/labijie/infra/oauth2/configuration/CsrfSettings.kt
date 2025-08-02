package com.labijie.infra.oauth2.configuration

/**
 *
 * @Author: Anders Xiao
 * @Date: 2025/8/2
 *
 */
class CsrfSettings {
    var disabled: Boolean = true
    var repository: CsrfRepository = CsrfRepository.Cookie
}

enum class CsrfRepository {
    Cookie,
    Session,
}
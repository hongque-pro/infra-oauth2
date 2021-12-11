package com.labijie.infra.oauth2


/**
 *
 * @Auther: AndersXiao
 * @Date: 2021-04-21 19:34
 * @Description:
 */

fun copyAttributesTo(source: Map<String, Any>, key: String, destination: MutableMap<String, Any>) {
    val value = source.getOrDefault(key, "").toString()
    if (!value.isBlank()) {
        if (value == "true" || value == "false") {
            destination[key] = value.toBoolean()
        } else {
            destination[key] = value
        }
    }
}





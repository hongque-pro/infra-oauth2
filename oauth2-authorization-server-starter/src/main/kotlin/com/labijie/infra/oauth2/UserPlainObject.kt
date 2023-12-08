package com.labijie.infra.oauth2

data class UserPlainObject(
    var userid:String = "",
    var username:String = "",
    var credentialsNonExpired:Boolean = false,
    var enabled:Boolean = false,
    var password:String = "",
    var accountNonExpired:Boolean = false,
    var accountNonLocked:Boolean = false,
    var twoFactorEnabled: Boolean = false,
    var authorities: ArrayList<String> = arrayListOf(),
    var attachedFields: HashMap<String, String> = hashMapOf()
)
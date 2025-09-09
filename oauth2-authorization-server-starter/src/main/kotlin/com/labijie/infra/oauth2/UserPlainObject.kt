package com.labijie.infra.oauth2

class UserPlainObject(
    var userid:String = "",
    var username:String = "",
    var credentialsNonExpired:Boolean = false,
    var enabled:Boolean = false,
    var password:String = "",
    var accountNonExpired:Boolean = false,
    var accountNonLocked:Boolean = false,
    var twoFactorEnabled: Boolean = false,
    var authorities: ArrayList<String> = ArrayList(0),
    var attachedFields: HashMap<String, String> = HashMap(0)
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as UserPlainObject

        if (credentialsNonExpired != other.credentialsNonExpired) return false
        if (enabled != other.enabled) return false
        if (accountNonExpired != other.accountNonExpired) return false
        if (accountNonLocked != other.accountNonLocked) return false
        if (twoFactorEnabled != other.twoFactorEnabled) return false
        if (userid != other.userid) return false
        if (username != other.username) return false
        if (password != other.password) return false
        if (authorities != other.authorities) return false
        if (attachedFields != other.attachedFields) return false

        return true
    }

    override fun hashCode(): Int {
        var result = credentialsNonExpired.hashCode()
        result = 31 * result + enabled.hashCode()
        result = 31 * result + accountNonExpired.hashCode()
        result = 31 * result + accountNonLocked.hashCode()
        result = 31 * result + twoFactorEnabled.hashCode()
        result = 31 * result + userid.hashCode()
        result = 31 * result + username.hashCode()
        result = 31 * result + password.hashCode()
        result = 31 * result + authorities.hashCode()
        result = 31 * result + attachedFields.hashCode()
        return result
    }


}
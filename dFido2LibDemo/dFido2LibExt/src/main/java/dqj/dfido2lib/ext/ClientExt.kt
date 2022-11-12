package dqj.dfido2lib.ext

import android.content.Context
import com.google.gson.Gson
import dqj.dfido2lib.core.Accounts
import dqj.dfido2lib.core.client.Fido2Core
import dqj.dfido2lib.core.internal.KeyTools

class ClientExt(var context: Context) {
    fun listAccounts(fido2SvrURL: String, rpid: String) : Accounts? {
        val keyTool=KeyTools(context)
        val accountsData = keyTool.retrieveKey(Fido2Core.AccountsKeyId, rpid)
        if (null != accountsData) {
            return Gson().fromJson(accountsData, Accounts::class.java)
        }
        return null
    }
}
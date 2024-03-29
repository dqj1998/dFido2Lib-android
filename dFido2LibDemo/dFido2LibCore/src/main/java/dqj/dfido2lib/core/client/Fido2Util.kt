package dqj.dfido2lib.core.client

import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL

class Fido2Util {
    companion object {
        fun getDefaultRegisterOptions(username: String , displayname: String, rpid: String, userVerification: String = "preferred"): HashMap<String, Any>{

            var authenticatorSelection = HashMap<String, Any>()
            authenticatorSelection["userVerification"] = userVerification

            var attestationOptions = HashMap<String, Any>()
            attestationOptions["username"] = username
            attestationOptions["displayName"] = displayname
            attestationOptions["authenticatorSelection"] = authenticatorSelection

            if( null!=rpid ){
                var rp = HashMap<String, Any>()
                rp["id"] = rpid
                attestationOptions["rp"] = rp
            }

            return attestationOptions
        }

        fun getDefaultAuthenticateOptions(username: String = "", rpid: String, userVerification: String = "preferred") : HashMap<String, Any> {

            var authenticatorSelection = HashMap<String, Any>()
            authenticatorSelection["userVerification"] = userVerification

            var assertionOptions = HashMap<String, Any>()
            if (username.isNotEmpty()) {
                assertionOptions["username"] = username
            } else {
                assertionOptions["mediation"] = "conditional"
            }

            assertionOptions["authenticatorSelection"] = authenticatorSelection

            if( null!=rpid ){
                var rp = HashMap<String, Any>()
                rp["id"] = rpid
                assertionOptions["rp"] = rp
            }

            return assertionOptions
        }
    }

}

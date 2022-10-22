package dqj.dfido2lib.core.client

import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL

class Fido2Util {
    companion object {
        fun getDefaultRegisterOptions(username: String , displayname: String): HashMap<String, Any>{

            var authenticatorSelection = HashMap<String, Any>()
            authenticatorSelection["userVerification"]="preferred"

            var attestationOptions = HashMap<String, Any>()
            attestationOptions["username"] = username
            attestationOptions["displayName"] = displayname
            attestationOptions["authenticatorSelection"] = authenticatorSelection

            return attestationOptions
        }

        fun getDefaultAuthenticateOptions(username: String = "") : HashMap<String, Any> {

            var authenticatorSelection = HashMap<String, Any>()
            authenticatorSelection["userVerification"]="preferred"

            var assertionOptions = HashMap<String, Any>()
            if (username.isNotEmpty()) {
                assertionOptions["username"] = username
            } else {
                assertionOptions["mediation"] = "conditional"
            }

            assertionOptions["authenticatorSelection"] = authenticatorSelection

            return assertionOptions
        }
    }

}

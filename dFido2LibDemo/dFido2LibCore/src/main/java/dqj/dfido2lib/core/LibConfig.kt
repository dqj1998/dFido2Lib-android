package dqj.dfido2lib.core

import dqj.dfido2lib.core.authenticator.Authenticator
import dqj.dfido2lib.core.authenticator.PlatformAuthenticator
import dqj.dfido2lib.core.client.Fido2Core
import dqj.dfido2lib.core.internal.Fido2Logger

class LibConfig {
    companion object{
        var aaguid: ByteArray = byteArrayOf(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

        var enterpriseRPIds = arrayOf<String>()

        var enableRooted: Boolean = false

        fun addEnterpriseRPIds(ids: Array<String>){
            enterpriseRPIds += ids
        }

        fun configAccountListExt(enable: Boolean = true) {
            Fido2Core.enableAccountsList = enable
        }

        fun setPlatformAuthenticatorAAGUID(id: String){
            aaguid = id.toByteArray()
        }

        /*
         Must wait for the timeout before sending excaption when cannot find authenticator according to the FIDO2 spec.
         You can enable/disable this feature.
         Default is enabled
         But be careful, disabling this feature may decrease the security level.
         */
        fun configExcaptionTimeoutWaiting(enable: Boolean){
            Fido2Core.waitCannotFindAuthenticatorTimeout = enable
        }

        /*
        Enable = Can register one device as mutiple authenticators through differet transports
        Default is false
        Refer spec 5.1.3 - 20.7: For each credential descriptor C in options.excludeCredentials
        */
        fun configMultipleCredByMultipleTransports(enable: Boolean){
            Fido2Core.canRegisterMultipleCredByMultipleTransports = enable
        }

        /*
         Config if the inside authenticator storage resident keys.
         Default is enabled.
         */
        fun configInsideAuthenticatorResidentStorage(enable: Boolean){
            PlatformAuthenticator.enableResidentStorage = enable
            if(!enable) {
                PlatformAuthenticator.enableSilentCredentialDiscovery = false
                Fido2Logger.info(Fido2Core::class.simpleName,"Auto disabled inside authenticator SilentCredentialDiscovery.")
            }
        }

        fun enabledInsideAuthenticatorResidentStorage() : Boolean{
            return PlatformAuthenticator.enableResidentStorage
        }

        /*
         Config if the inside authenticator can SilentCredentialDiscovery.
         Default is enabled.
         */
        fun configInsideAuthenticatorSilentCredentialDiscovery(enable: Boolean){
            PlatformAuthenticator.enableSilentCredentialDiscovery = enable
            if(enable) {
                PlatformAuthenticator.enableResidentStorage = true
                Fido2Logger.info(Fido2Core::class.simpleName,"Auto enabled inside authenticator ResidentStorage.")
            }
        }
    }
}
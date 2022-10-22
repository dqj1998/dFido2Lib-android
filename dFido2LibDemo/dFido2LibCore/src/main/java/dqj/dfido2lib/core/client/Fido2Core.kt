package dqj.dfido2lib.core.client

import android.content.Context
import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.databind.ObjectMapper
import com.google.gson.Gson
import com.google.gson.JsonElement
import com.google.gson.JsonParser
import dqj.dfido2lib.core.*
import dqj.dfido2lib.core.authenticator.AttestationObject
import dqj.dfido2lib.core.authenticator.Authenticator
import dqj.dfido2lib.core.authenticator.AuthenticatorAssertionResult
import dqj.dfido2lib.core.authenticator.PlatformAuthenticator
import dqj.dfido2lib.core.internal.ByteArrayUtil
import dqj.dfido2lib.core.internal.ByteArrayUtil.decodeBase64URL
import dqj.dfido2lib.core.internal.ByteArrayUtil.encodeBase64URL
import dqj.dfido2lib.core.internal.Fido2Logger
import dqj.dfido2lib.core.internal.LibUtil
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import java.net.URL


class Fido2Core(context: Context) {
    private val defaultTimeout: Long = 2 * 60 * 1000
    private val minTimeout: Long = 1000 //ms
    private val maxTimeout: Long = 30 * 60 * 1000  //ms

    private var curTimeout:Long = defaultTimeout //ms

    private var authenticatorPlatform: PlatformAuthenticator

    init {
        authenticatorPlatform = PlatformAuthenticator(context)
    }

    companion object{
        private var waitCannotFindAuthenticatorTimeout:Boolean = true

        private var canRegisterMultipleCredByMultipleTransports: Boolean = false

        /*
         Must wait for the timeout before sending excaption when cannot find authenticator according to the FIDO2 spec.
         You can enable/disable this feature.
         Default is enabled
         But be careful, disabling this feature may decrease the security level.
         */
        fun configExcaptionTimeoutWaiting(enable: Boolean){
            waitCannotFindAuthenticatorTimeout = enable
        }

        /*
        Enable = Can register one device as mutiple authenticators through differet transports
        Default is false
        Refer spec 5.1.3 - 20.7: For each credential descriptor C in options.excludeCredentials
        */
        fun configMultipleCredByMultipleTransports(enable: Boolean){
            canRegisterMultipleCredByMultipleTransports = enable
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

    fun reset(){
        waitCannotFindAuthenticatorTimeout = true
        canRegisterMultipleCredByMultipleTransports = false

        PlatformAuthenticator.enableResidentStorage = true
        PlatformAuthenticator.enableSilentCredentialDiscovery = true
        authenticatorPlatform.reset()

        //Client cannot reset/clear server-side according to WebAuthN spec.
        //Server can clear based on users' operation or inactivity check.
        //We may add some ext methods to support client-side management
    }

    fun clearKeys(rpId: String?){
        authenticatorPlatform.clearKeys(rpId)
    }

    //dqj TODO: cancel method(6.3.4. The authenticatorCancel Operation)

    suspend fun registerAuthenticator(fido2SvrURL:String,
                              attestationOptions: Map<String, Any>,
                              messageTitle: String, messageSubtitle: String,
                              allowDeviceSecure: Boolean): Boolean{
        var rtn = false

        try{
            val gson = Gson()
            val jsonStr = gson.toJson(attestationOptions).toString()
            Fido2Logger.debug(Fido2Core::class.simpleName, "</attestation/options> req: $jsonStr")

            val headers = HashMap<String,String>()
            headers["content-type"] = "application/json"

            var resp:Pair<String, List<String>>
            runBlocking {
                val respDefferred = async (Dispatchers.IO) { LibUtil.httpRequest(
                    "$fido2SvrURL/attestation/options", "POST", jsonStr.toByteArray(),
                    headers, false) }
                resp = respDefferred.await()
            }
            Fido2Logger.debug(Fido2Core::class.simpleName, "</attestation/options> resp text: ${resp.first}")

            val pubkCredCrtOpts = gson.fromJson(resp.first, PublicKeyCredentialCreationOptions::class.java)

            val pubkeyCredPair = createNewCredential(pubkCredCrtOpts, fido2SvrURL,
                messageTitle, messageSubtitle, allowDeviceSecure)

            val newCred = pubkeyCredPair.second

            var attResult:Pair<String, List<String>>
            val jsontxt = gson.toJson(newCred)
            headers["Cookie"] = LibUtil.buildCookesHeaderValue(resp.second)
            runBlocking {
               val attResultDeferred = async (Dispatchers.IO) { LibUtil.httpRequest(
                    "$fido2SvrURL/attestation/result", "POST", jsontxt.toByteArray(),
                    headers, false, curTimeout.toInt())}
                attResult = attResultDeferred.await()
            }
            Fido2Logger.debug(Fido2Core::class.simpleName, "</attestation/result> resp: ${attResult.first}")

            if(0< curTimeout && System.currentTimeMillis() - pubkeyCredPair.first > curTimeout){
                Fido2Logger.debug(Fido2Core::class.simpleName,"<registerAuthenticator> already timeout")
                throw Fido2Error.new(Fido2Error.Companion.ErrorType.timeout)
            }

            if(attResult.first.isNotEmpty()){
                try {
                    val jsonMap = Gson().fromJson(attResult.first, Map::class.java) as Map<String,String>
                    rtn = null != jsonMap["status"] && jsonMap["status"]!!.uppercase() == "OK"
                }catch (ex: Exception){
                    Fido2Logger.err(Fido2Core::class.simpleName, ex.localizedMessage+"|"+attResult);
                    throw Fido2Error.new( Fido2Error.Companion.ErrorType.unknown,
                        java.lang.Exception(ex.localizedMessage+"|"+attResult))
                }

                if(!rtn && !enabledInsideAuthenticatorResidentStorage()){
                    Fido2Logger.err(Fido2Core::class.simpleName,
                        "Most like your FIDO2 server does not really support non-resident Credentials, if you confirmed all other cases.")
                }
            } else {
                Fido2Logger.err(Fido2Core::class.simpleName,"registerAuthenticator: </attestation/result> resp empty.")
            }
        } catch (e: java.lang.Exception) {
            e.localizedMessage?.let { Fido2Logger.err(Fido2Core::class.simpleName, it) }
            throw e
        }

        return rtn
    }

    /// 5.1.3 - 4
    /// If the timeout member of options is present, check if its value lies within a reasonable
    /// range as defined by the client and if not, correct it to the closest value lying within that range.
    /// Set a timer lifetimeTimer to this adjusted value. If the timeout member of options is not present,
    /// then set lifetimeTimer to a client-specific default.
    private fun adjustLifetimeTimer(timeout: Long?=0,
                                    userVerification: UserVerificationRequirement?=UserVerificationRequirement.Discouraged): Long {
        if( null != timeout && 0 < timeout ) {
            return when {
                timeout < minTimeout -> minTimeout
                timeout > maxTimeout -> maxTimeout
                else -> timeout
            }
        }else {
            val t:Long = when (userVerification) {
                UserVerificationRequirement.Required, UserVerificationRequirement.Preferred -> 120
                UserVerificationRequirement.Discouraged -> 300
                else -> defaultTimeout
            }
            return when {
                t < minTimeout -> minTimeout
                t > maxTimeout -> maxTimeout
                else -> t
            }
        }
    }

    /// 5.1.3 - 8 If options.rpId is not present, then set rpId to effectiveDomain.
    private fun pickRelyingPartyID(rpId: String?, origin: String) : String {
        return if(null != rpId) {
            rpId
        } else {
            val url = URL(origin)
            if(null!=url.host) {
                url.host
            }else{
                origin
            }
        }
    }

    /// Registration methods
    /// https://w3c.github.io/webauthn/#sctn-createCredential
    @OptIn(ExperimentalUnsignedTypes::class)
    private fun createNewCredential(options: PublicKeyCredentialCreationOptions,
                                            origin: String, messageTitle: String, messageSubtitle: String,
                                            allowDeviceSecure: Boolean)
            : Pair<Long, PublicKeyCredential<AuthenticatorAttestationResponse>> {

        // 5.1.3 1-3 and 6-7: No need as a lib

        // 5.1.3 - 4
        curTimeout = adjustLifetimeTimer(
            options.timeout,
            options.authenticatorSelection?.userVerification,
        )

        // 5.1.3 - 5
        val idCount = options.user.id.toByteArray().size
        if(1 > idCount || 64 < idCount) {
            throw Fido2Error.new(Fido2Error.Companion.ErrorType.typeError)
        }

        // 5.1.3 - 8
        val rpId = pickRelyingPartyID(options.rp.id, origin)

        // 5.1.3 - 9,10
        // check options.pubKeyCredParmas
        // currently 'public-key' is only in specification.
        // do nothing

        // TODO Extension handling
        // 5.1.3 - 11
        // 5.1.3 - 12

        // 5.1.3 - 13,14,15 Prepare ClientData, JSON, Hash
        val clientDataTriple= generateClientData( CollectedClientDataType.WebAuthnCreate,
            options.challenge, origin)

        // 5.1.3 - 17 : dqj TODO: authenticators collection - support issuedRequests

        // 5.1.3 - 18 : dqj TODO: authenticators collection - support set of authenticators
        val authenticators = arrayOf(authenticatorPlatform)

        // 5.1.3 - 19 Start lifetimeTimer.
        val startTime = System.currentTimeMillis()

        // 5.1.3 - 20
        for(authenticator in authenticators) {
            if(0< curTimeout && System.currentTimeMillis() - startTime > curTimeout) {break;}

            // TODO: support cancel process

            // an authenticator becomes available
            val selection = options.authenticatorSelection
            if(null != selection)  {
                val attachment = selection.authenticatorAttachment
                if(null != attachment){
                    if(attachment != authenticator .attachment) {continue;}
                }

                val selResidentKey = selection.residentKey
                if(null != selResidentKey) {
                    if(selResidentKey == ResidentKey.Required
                            && !authenticator.canStoreResidentKey()) {continue;}
                } else {
                    if(null!=selection.requireResidentKey && selection.requireResidentKey!!
                            && !authenticator.canStoreResidentKey()) {continue;}
                }

                if(selection.userVerification ==  UserVerificationRequirement.Required
                            && !authenticator.canPerformUserVerification()) {continue;}
            }

            var requireResidentKey = options.authenticatorSelection?.requireResidentKey ?: false

            if (!requireResidentKey && (null != options.authenticatorSelection?.residentKey)) {
                requireResidentKey = when(options.authenticatorSelection?.residentKey){
                    ResidentKey.Required -> true
                    ResidentKey.Preferred -> authenticator.canStoreResidentKey()
                    ResidentKey.Discouraged -> false
                    else -> {
                        false
                    }
                }
            }

            //Use resident key when no client conf
            if(!requireResidentKey){requireResidentKey=authenticator.canStoreResidentKey()}

            val reqUserV =
                if(null!=options.authenticatorSelection)options.authenticatorSelection!!.userVerification
                else UserVerificationRequirement.Discouraged
            val userVerification = this.judgeUserVerificationExecution(authenticator, reqUserV)

            val userPresence = !userVerification //dqj: A miss of spec?

            val enterpriseAttestationPossible = false //TODO: support enterprise

            val excludeCredentialDescriptorList = ArrayList<PublicKeyCredentialDescriptor>()
            if(canRegisterMultipleCredByMultipleTransports && options.excludeCredentials != null) {
                options.excludeCredentials!!.forEach { excred ->
                    if(null==excred.transports
                        || excred.transports!!.contains<String>(authenticator.transport.rawValue)){
                        excludeCredentialDescriptorList.add(excred)
                    }
                }
            } else if(options.excludeCredentials != null){
                excludeCredentialDescriptorList.addAll(options.excludeCredentials!!)
            }

            val rpEntity = PublicKeyCredentialRpEntity(rpId, options.rp.name, options.rp.icon)

            var attestation: AttestationObject?
            runBlocking {
                val makeCredentialDeferred = async(Dispatchers.Default) {
                    authenticator.authenticatorMakeCredential(
                        messageTitle, messageSubtitle, allowDeviceSecure,
                        clientDataTriple.third, rpEntity, options.user, requireResidentKey,  userPresence,
                        userVerification, options.pubKeyCredParams.toTypedArray(),
                        excludeCredentialDescriptorList.toTypedArray(),
                        enterpriseAttestationPossible, HashMap(), //dqj TODO: support extensions
                        )
                }
                attestation = makeCredentialDeferred.await()
            }

            if (null == attestation) continue

            val attestedCred = attestation!!.authData.attestedCredentialData
            if(null == attestedCred){
                Fido2Logger.debug(Fido2Core::class.simpleName,
                        "attested credential data not found")
                throw Fido2Error.new(Fido2Error.Companion.ErrorType.unknown, "attested credential data not found")
            }

            val credentialId = attestedCred.credentialId

            var atts = attestation

            // XXX currently not support replacing attestation
            //     on "indirect" conveyance request

            var attestationObject: ByteArray
            if((options.attestation == AttestationConveyancePreference.None) && (null != attestation)
                    && !attestation!!.isSelfAttestation()) {
                atts = attestation!!.toNone()
                val bytes = atts.toBytes()
                if(null==bytes){
                    Fido2Logger.debug(Fido2Core::class.simpleName,"failed to build attestation-object")
                    throw Fido2Error.new(Fido2Error.Companion.ErrorType.unknown, "failed to build attestation-object")
                }
                attestationObject = ByteArray(0)
                attestationObject += bytes.copyOfRange(0, 37)
                for(i in 1..16){
                    attestationObject += 0
                }
                attestationObject += bytes.copyOfRange(37+16+1, bytes.size)
            } else {// direct or enterprise
                val bytes = atts!!.toBytes()
                if(null == bytes){
                    Fido2Logger.debug(Fido2Core::class.simpleName,
                        "<CreateOperation> failed to build attestation-object")
                    throw Fido2Error.new(Fido2Error.Companion.ErrorType.unknown)
                }
                attestationObject = bytes
            }

            val response = AuthenticatorAttestationResponse(
                encodeBase64URL(clientDataTriple.second.toByteArray()), //clientDataJSON,
                encodeBase64URL(attestationObject) //attestationObject
                //dqj TODO: support [[transports]]
                )

            // TODO support [[clientExtensionsResults]]
            val base64Id = encodeBase64URL(credentialId)
            val cred = PublicKeyCredential<AuthenticatorAttestationResponse>(
                PublicKeyCredentialType.PublicKey.rawValue,
                base64Id, base64Id, null,
                response, )

            return Pair(startTime, cred)
        }

        Fido2Logger.debug(Fido2Core::class.simpleName,
            "newCredential cannot found usable authenticator.")

        //Wait timeout and retrun according to WebAuthn spec
        if(waitCannotFindAuthenticatorTimeout && 0< curTimeout &&
                    (System.currentTimeMillis() - startTime < curTimeout)){
            val needWait = curTimeout - (System.currentTimeMillis() - startTime)
            Fido2Logger.debug(Fido2Core::class.simpleName,"needWait: $needWait")
            if(0 < needWait) {
                //withContext(Dispatchers.IO) {
                    Thread.sleep(needWait)
                //}
            }
        }
        throw Fido2Error.new(Fido2Error.Companion.ErrorType.notAllowed)
    }

    // 5.1.3 - 13,14,15 Prepare ClientData, JSON, Hash
    private fun generateClientData(
            type:      CollectedClientDataType,
            challenge: String,
            origin: String
            ) : Triple<CollectedClientData, String, ByteArray> {

        // TODO TokenBinding
        val clientData = CollectedClientData(
            type = type.type,
            challenge = challenge,
            origin = origin,
            tokenBinding = null,
        )

        val clientDataJSON = encodeJSON(clientData)
        val clientDataHash = ByteArrayUtil.sha256(clientDataJSON.toByteArray())

        return Triple(clientData, clientDataJSON, clientDataHash)
    }

    fun authenticate(fido2SvrURL:String, assertionOptions: Map<String, Any>,
            messageTitle: String, messageSubtitle: String, allowDeviceSecure: Boolean) : Boolean {
        var rtn: Boolean;

        try{
            val gson = Gson()
            var jsonStr = gson.toJson(assertionOptions).toString()
            Fido2Logger.debug(Fido2Core::class.simpleName, "</assertion/options> req: $jsonStr")

            val headers = HashMap<String,String>()
            headers["content-type"] = "application/json"

            var resp:Pair<String, List<String>>
            runBlocking {
                val respDefferred = async (Dispatchers.IO) { LibUtil.httpRequest(
                    "$fido2SvrURL/assertion/options", "POST", jsonStr.toByteArray(),
                    headers, false) }
                resp = respDefferred.await()
            }
            Fido2Logger.debug(Fido2Core::class.simpleName, "</assertion/options> resp text: ${resp.first}")

            val jsonOptsData = JsonParser.parseString(resp.first).asJsonObject
            if (jsonOptsData.get("challenge") == null)  {
                val msg: JsonElement = jsonOptsData.get("message")
                throw Fido2Error.new(Fido2Error.Companion.ErrorType.unknown, msg.asString)
            }

            var pubkCredReqOpts = gson.fromJson(resp.first, PublicKeyCredentialRequestOptions::class.java)
            Fido2Logger.debug(Fido2Core::class.simpleName,"</assertion/options> resp: $pubkCredReqOpts")

            //TODO: Support cross-platform authenocator
            if(null != assertionOptions["mediation"]){
                pubkCredReqOpts.mediation = CredentialMediationRequirement.valueOf(assertionOptions["mediation"] as String)
            }

            val pubkeyPair = discoverFromExternalSource(pubkCredReqOpts, fido2SvrURL,
                                    messageTitle,messageSubtitle, allowDeviceSecure)
            jsonStr = gson.toJson(pubkeyPair.second)
            Fido2Logger.debug(Fido2Core::class.simpleName,"</assertion/result> req: $jsonStr")
            headers["Cookie"] = LibUtil.buildCookesHeaderValue(resp.second)
            runBlocking {
                val respDefferred = async (Dispatchers.IO) { LibUtil.httpRequest(
                    "$fido2SvrURL/assertion/result", "POST", jsonStr.toByteArray(),
                    headers, false) }
                resp = respDefferred.await()
            }
            Fido2Logger.debug(Fido2Core::class.simpleName,"</assertion/result> resp: $resp")

            try {
                val jsonResultData = JsonParser.parseString(resp.first).asJsonObject
                if (null == jsonResultData) {
                    Fido2Logger.err(Fido2Core::class.simpleName, "failed to parse assResult")
                    throw Fido2Error.new(Fido2Error.Companion.ErrorType.badData)
                }

                if (0 < curTimeout && System.currentTimeMillis() - pubkeyPair.first > curTimeout) {
                    Fido2Logger.debug(Fido2Core::class.simpleName, "already timeout")
                    throw Fido2Error.new(Fido2Error.Companion.ErrorType.timeout)
                }

                rtn = null!=jsonResultData.get("status") && jsonResultData.get("status").asString.uppercase() == "OK"
            }catch (ex: Exception){
                Fido2Logger.err(Fido2Core::class.simpleName, ex.localizedMessage+"|"+resp);
                throw Fido2Error.new( Fido2Error.Companion.ErrorType.unknown,
                    java.lang.Exception(ex.localizedMessage+"|"+resp))
            }

            if(!rtn && !enabledInsideAuthenticatorResidentStorage()){
                Fido2Logger.err(Fido2Core::class.simpleName,
                    "Most like your FIDO2 server does not really support non-resident Credentials, if you confirmed all other cases.")
            }

        } catch(e: Exception) {
            e.localizedMessage?.let { Fido2Logger.err(Fido2Core::class.simpleName, it) }
            throw e
        }

        return rtn
    }

    /// Authentication methods
    /// https://w3c.github.io/webauthn/#sctn-discover-from-external-source
    @OptIn(ExperimentalUnsignedTypes::class)
    fun discoverFromExternalSource(options: PublicKeyCredentialRequestOptions, origin: String,
                                   messageTitle: String, messageSubtitle: String,
                                   allowDeviceSecure: Boolean)
        : Pair<Long, PublicKeyCredential<AuthenticatorAssertionResponse>>{

        // 5.1.4.1 1-2, 5,6: No need as a lib

        // 5.1.4.1 3
        if((options.mediation != null) && options.mediation == CredentialMediationRequirement.conditional){
            if(null != options.allowCredentials && options.allowCredentials!!.isNotEmpty()) {
                throw Fido2Error.new(Fido2Error.Companion.ErrorType.notSupported)
            }
            curTimeout = 0 //5.1.4.1 3.2 Set a timer lifetimeTimer to a value of infinity.
        }else{
            //5.1.4.1 4
            curTimeout = adjustLifetimeTimer(options.timeout, options.userVerification)
        }

        //5.1.4.1 7
        val rpId = pickRelyingPartyID(options.rpId, origin)

        // TODO Extension handling
        // 5.1.4.1 - 8,9

        // 5.1.4.1 - 10, 11, 12
        val clientDataTriple= generateClientData( CollectedClientDataType.WebAuthnGet,
            options.challenge!!, origin)

        // 5.1.4.1 - 14, 15 : dqj TODO: authenticators collection - support issuedRequests, savedCredentialIds

        // 5.1.4.1 - 16 : dqj TODO: authenticators collection - support set of authenticators
        var authenticators = arrayOf(authenticatorPlatform)

        // 5.1.4.1 - 18 Start lifetimeTimer.
        val startTime = System.currentTimeMillis()

        // 5.1.4.1 - 19
        for(authenticator in authenticators) {
            if(0< curTimeout && System.currentTimeMillis() - startTime > curTimeout) {break;}

            // TODO: support cancel

            // TODO: support ConditionalMediation preparation

            //an authenticator becomes available

            var savedCredentialId: ByteArray? = null

            var realAllowCredentials = options.allowCredentials
            if(null==realAllowCredentials)realAllowCredentials=ArrayList()

            //ConditionalMediation silentCredentialDiscovery
            if(options.mediation == CredentialMediationRequirement.conditional && authenticator.canSilentCredentialDiscovery()){
                val pubKeyCreds = authenticator.silentCredentialDiscovery(rpId)

                //TODO: Selection UI
                if(pubKeyCreds.isNotEmpty()) {
                    val pubKeyDesc = PublicKeyCredentialDescriptor (PublicKeyCredentialType.PublicKey,
                            encodeBase64URL(pubKeyCreds[0].id), mutableListOf(authenticator.transport.rawValue))
                    realAllowCredentials = mutableListOf(pubKeyDesc)
                }
            }

            //5.1.4.2. Issuing a Credential Request to an Authenticator

            if((options.userVerification == UserVerificationRequirement.Required) && !authenticator.allowUserVerification) {
                Fido2Logger.debug(Fido2Core::class.simpleName,
                    "<discoverFromExternalSource> authenticator notsupport userVerification")
                continue
            }

            val userVerification = judgeUserVerificationExecution(authenticator, options.userVerification)

            val userPresence = !userVerification

            if(realAllowCredentials.isNotEmpty()) {

                var allowCredentialDescriptorList = mutableListOf<PublicKeyCredentialDescriptor>()
                realAllowCredentials.forEach { cred ->
                    // TODO: more check for id.
                    if(null==cred.transports || cred.transports!!.contains(authenticator.transport.rawValue)){
                        allowCredentialDescriptorList.add(cred)
                    }
                }

                if (allowCredentialDescriptorList.isEmpty()) {
                    continue
                }

                // need to remember the credential Id
                // because authenticator doesn't return credentialId for single descriptor

                if(allowCredentialDescriptorList.size == 1) {
                    savedCredentialId = decodeBase64URL(allowCredentialDescriptorList[0].id)
                }

                //TODO: select distinctTransports

                realAllowCredentials = allowCredentialDescriptorList
            }

            var assertionResult: AuthenticatorAssertionResult?
            runBlocking {
                val getAssertionDeferred = async(Dispatchers.Default) {
                    authenticator.authenticatorGetAssertion(
                        messageTitle, messageSubtitle, allowDeviceSecure, rpId,
                        clientDataTriple.third, realAllowCredentials.toTypedArray(),
                        userPresence, userVerification, HashMap<String, ByteArray>() //dqj TODO: support extensions
                    )
                }
                assertionResult = getAssertionDeferred.await()
            }

            if(null == assertionResult) continue

            //End of Issuing a Credential Request to an Authenticator

            //End of an authenticator becomes available

            //authenticator indicates success
            var credentialId: ByteArray?
            if(null!=savedCredentialId) {
                Fido2Logger.debug(Fido2Core::class.simpleName,
                        "<discoverFromExternalSource> use saved credentialId")
                credentialId = savedCredentialId
            } else {
                Fido2Logger.debug(Fido2Core::class.simpleName,
                        "<discoverFromExternalSource> use credentialId from authenticator")
                if(null== assertionResult!!.credentailId) {
                    Fido2Logger.debug(Fido2Core::class.simpleName,
                            "<discoverFromExternalSource> credentialId not found")
                    throw Fido2Error.new(Fido2Error.Companion.ErrorType.unknown,
                            "<discoverFromExternalSource> credentialId not found")
                }
                credentialId = assertionResult!!.credentailId
            }

                // TODO support extensionResult
            val rawUH=assertionResult!!.userHandle ?: byteArrayOf()
            Fido2Logger.debug(Fido2Core::class.simpleName, "assertionResult!!.userHandle ${String(rawUH)}")
            val cred = PublicKeyCredential<AuthenticatorAssertionResponse>(
                PublicKeyCredentialType.PublicKey.rawValue,
                encodeBase64URL(credentialId?: byteArrayOf()),
                encodeBase64URL(credentialId?: byteArrayOf()),
                authenticator.attachment,
                AuthenticatorAssertionResponse(
                            encodeBase64URL(clientDataTriple.second.toByteArray()),
                            encodeBase64URL(assertionResult!!.authenticatorData),
                            encodeBase64URL(assertionResult!!.signature),
                            String(rawUH)
                //TODO: support [[clientExtensionsResults]]
                )
            )

            return Pair(startTime, cred)
        }

        Fido2Logger.debug(Fido2Core::class.simpleName,
            "discoverFromExternalSource cannot found usable authenticator.")

        //Wait timeout and retrun according to WebAuthn spec
        if(0< curTimeout && waitCannotFindAuthenticatorTimeout && (System.currentTimeMillis() - startTime < curTimeout)){
            val needWait = curTimeout - (System.currentTimeMillis() - startTime)
            Fido2Logger.debug(Fido2Core::class.simpleName,"needWait: $needWait")
            if(0 < needWait) {
                Thread.sleep(needWait)
            }
        }

        throw Fido2Error.new(Fido2Error.Companion.ErrorType.notAllowed)
    }

    private fun judgeUserVerificationExecution(authenticator: Authenticator,
                                               userVerificationRequest:
                                               UserVerificationRequirement? = UserVerificationRequirement.Discouraged)
            : Boolean {
        return when (userVerificationRequest) {
            UserVerificationRequirement.Required -> true
            UserVerificationRequirement.Preferred -> authenticator.canPerformUserVerification()
            UserVerificationRequirement.Discouraged -> false
            else -> {
                authenticator.canPerformUserVerification()
            }
        }
    }

    private fun encodeJSON(data: CollectedClientData): String {
        return ObjectMapper()
            .setSerializationInclusion(JsonInclude.Include.NON_NULL)
            .writeValueAsString(data)
    }

}
package dqj.dfido2lib.core

enum class UserVerificationRequirement(val type: String) {
    Required("required"),
    Preferred("preferred"),
    Discouraged("discouraged")
}

enum class ResidentKey(val type: String) {
    Required("required"),
    Preferred("preferred"),
    Discouraged("discouraged")
}

enum class CollectedClientDataType(val type: String) {
    WebAuthnCreate("webauthn.create"),
    WebAuthnGet("webauthn.get"),
}

data class CollectedClientData(
    val type: String,
    var challenge: String, // Must be String according to spec
    var origin: String,
    var tokenBinding: TokenBinding? = null
)

data class TokenBinding(
    var status: TokenBindingStatus,
    var id: String
)

enum class TokenBindingStatus(
    private val rawValue: String
) {
    Present("present"),
    Supported("supported");

    override fun toString(): String {
        return rawValue
    }
}

class PublicKeyCredentialCreationOptions(
    var rp: PublicKeyCredentialRpEntity = PublicKeyCredentialRpEntity(),
    var user: PublicKeyCredentialUserEntity = PublicKeyCredentialUserEntity(),
    var challenge: String = "",
    var pubKeyCredParams: MutableList<PublicKeyCredentialParameters> = ArrayList(),
    var timeout: Long? = null,
    var excludeCredentials: MutableList<PublicKeyCredentialDescriptor>? = ArrayList(),
    var authenticatorSelection: AuthenticatorSelectionCriteria? = null,
    var attestation: AttestationConveyancePreference = AttestationConveyancePreference.Direct,
    var extensions: Map<String, Any> = HashMap()
) {
    fun addPubKeyCredParam(alg: Long) {
        this.pubKeyCredParams.add(PublicKeyCredentialParameters(alg = alg))
    }
}

enum class CredentialMediationRequirement(
    private val rawValue: String
) {
    silent("silent"),
    optional("optional"),
    conditional("conditional"),
    required("required")
}

class PublicKeyCredentialRequestOptions (
    var challenge: String? = null,
    var rpId: String? = "",
    var allowCredentials: MutableList<PublicKeyCredentialDescriptor>? = ArrayList(),
    var userVerification: UserVerificationRequirement? = UserVerificationRequirement.Preferred,
    var timeout: Long?,
    var mediation: CredentialMediationRequirement?//dqj
    // let extensions: []
){
    fun addAllowCredential( credentialId: String,
                transports: MutableList<String>//dqj [AuthenticatorTransport]
    ) {
        if (this.allowCredentials == null) {
            this.allowCredentials = ArrayList()
        }
        this.allowCredentials!!.add(PublicKeyCredentialDescriptor(
            PublicKeyCredentialType.PublicKey,
            credentialId, //String(bytes: credentialId, encoding: .utf8)!,
            transports
        ))
    }
}

data class PublicKeyCredentialRpEntity(
    var id: String? = null,
    var name: String = "",
    var icon: String? = null
)

data class PublicKeyCredentialUserEntity(
    var id: String = "", //ByteArray = byteArrayOf(),
    var name: String = "",
    var displayName: String = "",
    var icon: String? = null
)

data class PublicKeyCredentialParameters(
    val type: PublicKeyCredentialType = PublicKeyCredentialType.PublicKey,
    var alg: Long
)

enum class PublicKeyCredentialType(
    val rawValue: String
) {
    PublicKey("public-key");

    override fun toString(): String {
        return rawValue
    }
}

data class PublicKeyCredentialDescriptor(
    val type: PublicKeyCredentialType = PublicKeyCredentialType.PublicKey,
    var id: String, // base64 credential ID. ByteArray,
    var transports: MutableList<String>? = ArrayList<String>()
) {

    fun addTransport(transport: AuthenticatorTransport) {
        if(null == this.transports)this.transports=ArrayList()
        this.transports!!.add(transport.rawValue)
    }
}

enum class AuthenticatorTransport(
    val rawValue: String
) {
    USB("usb"),
    BLE("ble"),
    NFC("nfc"),
    Internal("internal");

    override fun toString(): String {
        return rawValue
    }
}

data class AuthenticatorSelectionCriteria(
    var authenticatorAttachment: AuthenticatorAttachment? = null,
    var requireResidentKey: Boolean?,
    var userVerification: UserVerificationRequirement = UserVerificationRequirement.Required,
    var residentKey: ResidentKey? = ResidentKey.Required,
)

enum class AuthenticatorAttachment(
    private val rawValue: String
) {
    Platform("platform"),
    CrossPlatform("cross-platform");

    override fun toString(): String {
        return rawValue
    }
}

enum class AttestationConveyancePreference(
    private val rawValue: String
) {

    None("none"),
    Direct("direct"),
    Indirect("indirect");

    override fun toString(): String {
        return rawValue
    }
}

open class AuthenticatorResponse

data class AuthenticatorAttestationResponse(
    var clientDataJSON:    String,
    var attestationObject: String //ByteArray
): AuthenticatorResponse()

data class AuthenticatorAssertionResponse(
    var clientDataJSON:    String,
    var authenticatorData: String,
    var signature:         String,
    var userHandle:        String?
): AuthenticatorResponse()

data class PublicKeyCredential<T: AuthenticatorResponse>(
    val type: String = PublicKeyCredentialType.PublicKey.rawValue,
    var id: String,
    var rawId: String,
    var authenticatorAttachment: AuthenticatorAttachment?,
    var response: T,
)

enum class COSEAlgorithmIdentifier(val cose: Long){
    // See https://www.iana.org/assignments/cose/cose.xhtml#algorithms
    rs256(-257),
    rs384(-258),
    rs512(-259),
    es256(-7),
    es384(-35),
    es512(-36),
    ed256(-260),
    ed512(-261),
    ps256(-37),

    other(0);

    companion object{
        fun fromRaw(id: Long): COSEAlgorithmIdentifier? {
            val types: Array<COSEAlgorithmIdentifier> = values()
            for (type in types) {
                if (type.cose == id) {
                    return type
                }
            }
            return other
        }
    }
}

data class Account (
    val rpid: String,
    val username: String,
    val displayname: String,
    val credIdBase64: String
)

data class Accounts (
    var accounts: ArrayList<Account>
)





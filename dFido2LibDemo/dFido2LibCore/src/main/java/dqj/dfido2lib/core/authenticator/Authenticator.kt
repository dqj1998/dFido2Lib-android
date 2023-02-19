package dqj.dfido2lib.core.authenticator

import android.annotation.SuppressLint
import android.app.KeyguardManager
import android.content.Context
import android.content.Context.MODE_PRIVATE
import android.content.SharedPreferences
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import androidx.security.crypto.MasterKey.Builder
import dqj.dfido2lib.core.*
import dqj.dfido2lib.core.client.Fido2Error
import dqj.dfido2lib.core.internal.*
import dqj.dfido2lib.core.internal.ByteArrayUtil.decodeBase64URL
import dqj.dfido2lib.core.internal.ByteArrayUtil.encodeBase64URL
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import org.json.JSONArray
import org.json.JSONException
import java.io.File
import java.security.*
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.RSAPublicKeySpec
import java.util.*
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec
import kotlin.coroutines.resume
import kotlin.coroutines.suspendCoroutine


//Data
object COSEKeyFieldType {
    const val kty:    Int =  1
    const val alg:    Int =  3
    const val crv:    Int = -1
    const val xCoord: Int = -2
    const val yCoord: Int = -3
    const val n:      Int = -1
    const val e:      Int = -2
}

object COSEKeyType {
    const val ec2: Int = 2
    const val rsa: Int = 3
}

@ExperimentalUnsignedTypes
class AuthenticatorDataFlags(
    private var userPresent:               Boolean = false,
    private var userVerified:              Boolean = false,
    private var backupEligibility:         Boolean = false,
    private var backupState:               Boolean = false,
    private var hasAttestedCredentialData: Boolean = false,
    private var hasExtension:              Boolean = false,
) {

    companion object {
        val TAG = AuthenticatorDataFlags::class.simpleName
        val upMask: UByte = 0b0000_0001u
        val uvMask: UByte = 0b0000_0100u
        val beMask: UByte = 0b0000_1000u
        val bsMask: UByte = 0b0001_0000u
        val atMask: UByte = 0b0100_0000u
        val edMask: UByte = 0b1000_0100u
    }

    fun init(flags: UByte): AuthenticatorDataFlags {
        val userPresent               = ((flags and upMask) == upMask)
        val userVerified              = ((flags and uvMask) == uvMask)
        val backupEligibility         = ((flags and beMask) == beMask)
        val backupState               = ((flags and bsMask) == bsMask)
        val hasAttestedCredentialData = ((flags and atMask) == atMask)
        val hasExtension              = ((flags and edMask) == edMask)
        return AuthenticatorDataFlags(
            userPresent               = userPresent,
            userVerified              = userVerified,
            backupEligibility         = backupEligibility,
            backupState               = backupState,
            hasAttestedCredentialData = hasAttestedCredentialData,
            hasExtension              = hasExtension
        )
    }

    fun init(
        userPresent               :Boolean,
        userVerified              :Boolean,
        backupEligibility         :Boolean,
        backupState               :Boolean,
        hasAttestedCredentialData :Boolean,
        hasExtension              :Boolean,
    ){
        this.userPresent               = userPresent
        this.userVerified              = userVerified
        this.backupEligibility         = backupEligibility
        this.backupState               = backupState
        this.hasAttestedCredentialData = hasAttestedCredentialData
        this.hasExtension              = hasExtension
    }

    fun toByte(): Byte {

        var result: UByte = 0u

        if (userPresent) {
            result = (result or upMask)
        }
        if (userVerified) {
            result = (result or uvMask)
        }
        if (hasAttestedCredentialData) {
            result = (result or atMask)
        }
        if (hasExtension) {
            result = (result or edMask)
        }

        return result.toByte()
    }
}

@ExperimentalUnsignedTypes
class AttestedCredentialData(
    val aaguid:              ByteArray,
    val credentialId:        ByteArray,
    val credentialPublicKey: PublicKey
) {

    companion object {
        val TAG = AttestedCredentialData::class.simpleName
    }

    fun toBytes(): ByteArray? {
        if (aaguid.size != 16){
            Fido2Logger.err(TAG, "<AttestedCredentialData> invalid aaguid length")
            return null
        }

        if(!credentialPublicKey::class.java.simpleName.contains("RSAPublicKey")){
            Fido2Logger.err(TAG, "<AttestedCredentialData> Only support RSA now.")
            return null
        }
        var modulus = (credentialPublicKey as RSAPublicKey).modulus.toByteArray()
        val exponent = credentialPublicKey.publicExponent.toByteArray()

        var keymap=HashMap<Int, Any>()
        keymap[COSEKeyFieldType.kty] = COSEKeyType.rsa.toLong()

        val keySize= credentialPublicKey.modulus.bitLength()
        when(keySize/8){
            256 -> keymap[COSEKeyFieldType.alg] = COSEAlgorithmIdentifier.rs256.cose
            384 -> keymap[COSEKeyFieldType.alg] = COSEAlgorithmIdentifier.rs384.cose
            512 -> keymap[COSEKeyFieldType.alg] = COSEAlgorithmIdentifier.rs512.cose
            else -> {
                Fido2Logger.err(
                    PlatformAuthenticator::class.simpleName,
                    "<AttestedCredentialData.toBytes> not supported alg: $credentialPublicKey.algorithm")
                throw Fido2Error.new(Fido2Error.Companion.ErrorType.unknown,
                    "<AttestedCredentialData.toBytes> not supported alg: $credentialPublicKey.algorithm")
            }
        }

        if(modulus.size > keySize / 8){ // --> 257 bytes
            modulus = modulus.drop(1).toByteArray()
        }
        keymap[COSEKeyFieldType.n] = modulus
        keymap[COSEKeyFieldType.e] = exponent

        //val pubKeyBytes = ByteArrayUtil.merge(modulus, exponent)
        val pubKeyBytes = CBORWriter().putIntKeyMap(keymap).compute() //putStringKeyMap(keymap).compute()
        Fido2Logger.debug(TAG, "PubKey: length - ${pubKeyBytes.size}")

        val credentialIdLength: UInt = credentialId.size.toUInt()
        val size1 = (credentialIdLength and 0x0000_ff00u).shr(8).toByte()
        val size2 = (credentialIdLength and 0x0000_00ffu).toByte()
        val sizeBytes = byteArrayOf(size1, size2)

        var result = ByteArrayUtil.merge(aaguid, sizeBytes)
        result = ByteArrayUtil.merge(result, credentialId)
        result = ByteArrayUtil.merge(result, pubKeyBytes)
        return result
    }
}

@ExperimentalUnsignedTypes
class AuthenticatorData(
    private val rpIdHash:               ByteArray,
    private val userPresent:            Boolean,
    private val userVerified:           Boolean,
    private val backupEligibility:      Boolean,
    private val backupState:            Boolean,
    private val signCount:              UInt,
    val attestedCredentialData: AttestedCredentialData?,
    private val extensions:             Map<String, Any>
) {

    companion object {
        val TAG = AuthenticatorData::class.simpleName
    }

    fun toBytes(): ByteArray? {

        //assert(userPresent != userVerified)

        val flags: Byte = AuthenticatorDataFlags(
            userPresent               = userPresent,
            userVerified              = userVerified,
            backupEligibility         = backupEligibility,
            backupState               = backupState,
            hasAttestedCredentialData = (attestedCredentialData != null),
            hasExtension              = extensions.isNotEmpty()
        ).toByte()

        if (rpIdHash.size != 32) {
            throw Fido2Error.new( Fido2Error.Companion.ErrorType.unknown,
                    "<AuthenticatorData> rpIdHash should be 32 bytes")
        }

        val sc1: Byte = (signCount and 0xff00_0000u).shr(24).toByte()
        val sc2: Byte = (signCount and 0x00ff_0000u).shr(16).toByte()
        val sc3: Byte = (signCount and 0x0000_ff00u).shr(8).toByte()
        val sc4: Byte = (signCount and 0x0000_00ffu).toByte()

        var result = ByteArrayUtil.merge(rpIdHash,
            byteArrayOf(flags, sc1, sc2, sc3, sc4))

        if (attestedCredentialData != null) {
            val attestedCredentialDataBytes = attestedCredentialData.toBytes()
            if (attestedCredentialDataBytes == null) {
                Fido2Logger.debug(TAG, "failed to build attestedCredentialData")
                return null
            }
            result = ByteArrayUtil.merge(result, attestedCredentialDataBytes)
        }

        if (extensions.isNotEmpty()) {
            // TODO extensions not supported currently
            result = ByteArrayUtil.merge(result, CBORWriter().putStringKeyMap(extensions).compute())
        }

        return result
    }

}

@ExperimentalUnsignedTypes
class PublicKeyCredentialSource(
    var signCount:  UInt,
    var id:         ByteArray,
    val rpId:       String,
    val userHandle: ByteArray,
    val alg:        Long,
    val otherUI:    String,
    val algText:    String,
    val privateKey: ByteArray,
    //val publicKey:  ByteArray,
) {

    companion object {

        val TAG = PublicKeyCredentialSource::class.simpleName

        fun fromBase64(str: String): PublicKeyCredentialSource? {
            Fido2Logger.debug(TAG, "fromBase64")
            return try {
                val bytes = Base64.decode(str, Base64.URL_SAFE)
                // TODO decryption
                fromCBOR(bytes)
            } catch (e: Exception) {
                Fido2Logger.warn(TAG, "failed to decode Base64: " + e.localizedMessage)
                null
            }
        }

        fun fromCBOR(bytes: ByteArray): PublicKeyCredentialSource? {
            Fido2Logger.debug(TAG, "fromCBOR")
            return try {
                val creader = CBORReader(bytes)
                val map = creader.readStringKeyMap()!!

                if (!map.containsKey("signCount")) {
                    Fido2Logger.warn(TAG, "'signCount' key not found")
                    return null
                }
                val signCount = (map["signCount"] as Long).toUInt()

                if (!map.containsKey("alg")) {
                    Fido2Logger.warn(TAG, "'alg' key not found")
                    return null
                }
                val alg = map["alg"] as Long

                if (!map.containsKey("id")) {
                    Fido2Logger.warn(TAG, "'id' key not found")
                    return null
                }
                val credId = map["id"] as ByteArray

                if (!map.containsKey("rpId")) {
                    Fido2Logger.warn(TAG, "'rpId' key not found")
                    return null
                }
                val rpId = map["rpId"] as String

                if (!map.containsKey("userHandle")) {
                    Fido2Logger.warn(TAG, "'userHandle' key not found")
                    return null
                }
                val userHandle = map["userHandle"] as ByteArray

                if (!map.containsKey("otherUI")) {
                    Fido2Logger.warn(TAG, "'otherUI' key not found")
                    return null
                }
                val otherUI = map["otherUI"] as String

                if (!map.containsKey("algText")) {
                    Fido2Logger.warn(TAG, "'algText' key not found")
                    return null
                }
                val algText = map["algText"] as String

                /*if (!map.containsKey("publicKey")) {
                    Fido2Logger.err(TAG, "'publicKey' key not found")
                    return null
                }
                val keyPairPub = map["publicKey"] as ByteArray*/
                if (!map.containsKey("privateKey")) {
                    Fido2Logger.err(TAG, "'privateKey' key not found")
                    return null
                }
                val keyPairPri = map["privateKey"] as ByteArray

                //val cose = COSEAlgorithmIdentifier.values().first{ it.cose == alg }
                /*if (null == cose) {
                    Fido2Logger.err(TAG, "Does not support COSE: $alg")
                    return null
                }*/
                //val kpara = PlatformAuthenticator.getKeyGeneratePara(arrayOf(cose))
                /*if( null == kpara || "RSA" != kpara.first){
                    Fido2Logger.err(TAG, "Only support RSA now: $kpara.first")
                    return null
                }*/
                //val kf = KeyFactory.getInstance(kpara.first)

                /*val keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore")
                keyStore.load(null)
                val pubKey = keyStore.getCertificate(
                    PlatformAuthenticator.KEY_PREFIX + String(credId)).publicKey*/

                return PublicKeyCredentialSource(
                    signCount = signCount,
                    id = credId,
                    rpId = rpId,
                    userHandle = userHandle,
                    alg = alg,
                    otherUI = otherUI,
                    algText = algText,
                    privateKey = keyPairPri,
                    //publicKey = keyPairPub,
                )

            } catch (e: Exception) {
                Fido2Logger.warn(TAG, "failed to decode CBOR: " + e.localizedMessage)
                null
            }
        }

    }

    fun toCBOR(): ByteArray? {
        return try {

            val map = LinkedHashMap<String, Any>()
            map["id"] = this.id
            map["rpId"] = this.rpId
            map["userHandle"] = this.userHandle
            map["alg"] = this.alg.toLong()
            map["signCount"] = this.signCount.toLong()
            map["otherUI"] = this.otherUI
            map["algText"] = this.algText
            //map["publicKey"] = publicKey
            map["privateKey"] = privateKey

            return CBORWriter().putStringKeyMap(map).compute()

        } catch (e: Exception) {
            Fido2Logger.warn(TAG, "failed to encode CBOR: " + e.localizedMessage)
            null
        }

    }

}

@ExperimentalUnsignedTypes
class AttestationObject(
    val fmt:      String,
    val authData: AuthenticatorData,
    val attStmt:  Map<String, Any>
) {

    companion object {
        val TAG = AttestationObject::class.simpleName
    }

    fun toNone(): AttestationObject {
        return AttestationObject(
            fmt      = "none",
            attStmt  = HashMap(),
            authData = this.authData
        )
    }

    fun isSelfAttestation(): Boolean {
        Fido2Logger.debug(TAG, "isSelfAttestation")
        if (this.fmt != "packed") {
            return false
        }
        if (this.attStmt.containsKey("x5c")) {
            return false
        }
        if (this.attStmt.containsKey("ecdaaKeyId")) {
            return false
        }
        if (this.authData.attestedCredentialData == null) {
            return false
        }
        if (this.authData.attestedCredentialData.aaguid.any { it != 0x00.toByte() }) {
            return false
        }
        return true
    }

    fun toBytes(): ByteArray? {
        Fido2Logger.debug(TAG, "toBytes")

        return try {
            val authDataBytes = this.authData.toBytes()
            if (authDataBytes == null) {
                Fido2Logger.debug(TAG, "failed to build authenticator data")
                return null
            }
            val map = LinkedHashMap<String, Any>()
            map["authData"] = authDataBytes
            map["fmt"]      = this.fmt
            map["attStmt"]  = this.attStmt

            Fido2Logger.debug(TAG, "AUTH_DATA: " + ByteArrayUtil.toHex(authDataBytes))

            return CBORWriter().putStringKeyMap(map).compute()

        } catch (e: Exception) {
            Fido2Logger.debug(TAG, "failed to build attestation binary: " + e.localizedMessage)
            null

        }

    }

}

class AuthenticatorAssertionResult(var authenticatorData: ByteArray, var signature: ByteArray) {
    var credentailId: ByteArray? = null
    var userHandle: ByteArray? = null
}

//API

interface Authenticator {
    val attachment: AuthenticatorAttachment
    val transport: AuthenticatorTransport
    val counterStep: UInt
    val allowResidentKey: Boolean
    val allowUserVerification: Boolean

    @OptIn(ExperimentalUnsignedTypes::class)
    suspend fun authenticatorMakeCredential(
        messageTitle: String, messageSubtitle: String, allowDeviceSecure: Boolean,
        clientDataHash:                  ByteArray,
        rpEntity:                        PublicKeyCredentialRpEntity,
        userEntity:                      PublicKeyCredentialUserEntity,
        requireResidentKey: Boolean,
        requireUserPresence: Boolean,
        requireUserVerification: Boolean,
        credTypesAndPubKeyAlgs:          Array<PublicKeyCredentialParameters>,
        excludeCredentialDescriptorList: Array<PublicKeyCredentialDescriptor>,
        enterpriseAttestationPossible:   Boolean,
        extensions:                      Map<String, ByteArray>
    ) : AttestationObject?

    suspend fun authenticatorGetAssertion (
        messageTitle: String, messageSubtitle: String, allowDeviceSecure: Boolean,
        rpId:                          String,
        clientDataHash:                ByteArray,
        allowCredentialDescriptorList: Array<PublicKeyCredentialDescriptor>,
        requireUserPresence: Boolean,
        requireUserVerification: Boolean,
        extensions:                    Map<String, ByteArray>
    ) : AuthenticatorAssertionResult?

    @OptIn(ExperimentalUnsignedTypes::class)
    fun lookupCredentialSource(rpId: String, credentialId: ByteArray) : PublicKeyCredentialSource?

    @OptIn(ExperimentalUnsignedTypes::class)
    fun silentCredentialDiscovery(rpId: String) : Array<PublicKeyCredentialSource>

    fun canStoreResidentKey() : Boolean
    fun canPerformUserVerification () : Boolean
    fun canSilentCredentialDiscovery() : Boolean

    fun reset() : Boolean
}

//Platform authenticator

class PlatformAuthenticator//init non-resident keys
    (
    context: Context,
    override var counterStep: UInt = 1u,
    override var allowUserVerification: Boolean = true
) : Authenticator {
    companion object {
        //val aaguid: ByteArray = byteArrayOf(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        var servicePrefix: String = "dFido2Lib_seckey_"

        var enableResidentStorage: Boolean = true
        var enableSilentCredentialDiscovery: Boolean = true

        const val ENCRYPT_DATA_ALG: String ="RSA/ECB/PKCS1Padding" //"RSA/ECB/OAEPwithSHA-1andMGF1Padding"

        private const val NON_RESIDENTSECKEY_ALIAS = "dFido2Lib_nonresident-seckey"
        private const val NON_RESIDENTSECKEY_PRFER_FNM = "dFido2Lib_nonresident-iv"
        private const val NON_RESIDENTSECKEY_PRFERKEY_IV = "dFido2Lib_nonresident-iv"

        //Platform Authenticator Crypto support

        fun getKeyGeneratePara(requestedAlgorithms: Array<COSEAlgorithmIdentifier>): Triple<String, Int, Long> {
            var parameters: Triple<String, Int, Long>? = null
            for (alg in requestedAlgorithms) {
                when (alg) {
                    COSEAlgorithmIdentifier.rs256 -> {
                        parameters =
                            Triple("RSA", 256 * 8, COSEAlgorithmIdentifier.rs256.cose.toLong())
                    }
                    COSEAlgorithmIdentifier.rs384 -> {
                        parameters =
                            Triple("RSA", 348 * 8, COSEAlgorithmIdentifier.rs384.cose.toLong())
                    }
                    COSEAlgorithmIdentifier.rs512 -> {
                        parameters =
                            Triple("RSA", 512 * 8, COSEAlgorithmIdentifier.rs512.cose.toLong())
                    }
                    else -> {
                        Fido2Logger.debug(
                            PlatformAuthenticator::class.simpleName,
                            "<getKeyGeneratePara> not supported alg, try next: $alg"
                        )
                    }
                }
                if (parameters != null) {
                    break
                }
            }

            if (parameters != null) {
                Fido2Logger.debug(
                    PlatformAuthenticator::class.simpleName,
                    "<getKeyGeneratePara> found supported parameters: $parameters"
                )
                return parameters
            } else {
                Fido2Logger.err(
                    PlatformAuthenticator::class.simpleName,
                    "<getKeyGeneratePara> all algorithms not supported"
                )
                throw Fido2Error.new(Fido2Error.Companion.ErrorType.notSupported)
            }

        }

        fun makeKey(keyPara: Pair<String, Int>): Pair<PrivateKey, PublicKey> {
            if ("RSA" != keyPara.first) {
                Fido2Logger.err(
                    KeystoreCredentialStore::class.simpleName,
                    "Only support RSA now: $keyPara.first"
                )
                throw Fido2Error.new(
                    Fido2Error.Companion.ErrorType.notSupported,
                    "Only support RSA now: $keyPara.first"
                )
            }

            val kpg = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_RSA /*, "AndroidKeyStore"*/
            )

            val random = SecureRandom()
            kpg.initialize(keyPara.second, random)
            val keyPair = kpg.generateKeyPair()

            return Pair(
                keyPair.private,
                keyPair.public
            )
        }
    }

    override val attachment: AuthenticatorAttachment = AuthenticatorAttachment.Platform
    override val transport: AuthenticatorTransport = AuthenticatorTransport.Internal
    override var allowResidentKey: Boolean = true

    var credentialStore: KeystoreCredentialStore
    private val context: Context

    init {
        this.context = context

        credentialStore = KeystoreCredentialStore(context)
        try {
            val keyStore: KeyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)
            val entry = keyStore.getEntry(NON_RESIDENTSECKEY_ALIAS, null)
            if (null == entry) {
                val kpg = KeyGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore"
                )

                kpg.init(
                    KeyGenParameterSpec.Builder(
                        NON_RESIDENTSECKEY_ALIAS,
                        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                    )
                        .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                        //.setDigests(KeyProperties.DIGEST_SHA512)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                        //.setKeySize(512 * 8)
                        .build()
                )

                kpg.generateKey()
            }
        } catch (ex: Exception) {
            Fido2Logger.err(
                PlatformAuthenticator::class.simpleName,
                "Init PlatformAuthenticator fail ${ex.localizedMessage}"
            )
        }
    }

    private fun encryptData(data: ByteArray): ByteArray {
        Fido2Logger.debug(Authenticator::class.simpleName, "encryptData: $data")

        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        val secretKey: SecretKey = keyStore.getKey(NON_RESIDENTSECKEY_ALIAS, null) as SecretKey
        val cipher = Cipher.getInstance("AES/CBC/PKCS7Padding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)

        val ivParams = cipher.parameters.getParameterSpec(IvParameterSpec::class.java)
        val iv = encodeBase64URL(ivParams.iv)
        val prefer = context.getSharedPreferences(NON_RESIDENTSECKEY_PRFER_FNM, MODE_PRIVATE)
        prefer.edit().putString(NON_RESIDENTSECKEY_PRFERKEY_IV, iv).commit()

        //val tdata="ABCDE".toByteArray()
        return cipher.doFinal(data)
    }

    private fun decryptData(data: ByteArray): ByteArray {
        Fido2Logger.debug(Authenticator::class.simpleName, "decryptData: $data")

        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        val secretKey: SecretKey = keyStore.getKey(NON_RESIDENTSECKEY_ALIAS, null) as SecretKey
        val cipher = Cipher.getInstance("AES/CBC/PKCS7Padding")
        val prefer = context.getSharedPreferences(NON_RESIDENTSECKEY_PRFER_FNM, MODE_PRIVATE)
        val iv = prefer.getString(NON_RESIDENTSECKEY_PRFERKEY_IV, "")?.let { decodeBase64URL(it) }
        val ivParameterSpec = IvParameterSpec(iv)
        cipher.init(Cipher.DECRYPT_MODE,secretKey,ivParameterSpec)

        return cipher.doFinal(data)
    }

    fun clearKeys(rpId:String?): Boolean {
        return try {
            credentialStore.removeAll(rpId)
            true
        } catch (ex: java.lang.Exception) {
            Fido2Logger.debug(PlatformAuthenticator::class.simpleName, "reset fail")
            false
        }
    }

    @OptIn(ExperimentalUnsignedTypes::class)
    override suspend fun authenticatorMakeCredential(
        messageTitle: String, messageSubtitle: String, allowDeviceSecure: Boolean,
        clientDataHash: ByteArray,
        rpEntity: PublicKeyCredentialRpEntity,
        userEntity: PublicKeyCredentialUserEntity,
        requireResidentKey: Boolean, requireUserPresence: Boolean,
        requireUserVerification: Boolean,
        credTypesAndPubKeyAlgs: Array<PublicKeyCredentialParameters>,
        excludeCredentialDescriptorList: Array<PublicKeyCredentialDescriptor>,
        enterpriseAttestationPossible: Boolean,
        extensions: Map<String, ByteArray>
    ): AttestationObject? {
        val requestedAlgs = ArrayList<COSEAlgorithmIdentifier>()
        credTypesAndPubKeyAlgs.forEach { p ->
            COSEAlgorithmIdentifier.fromRaw(p.alg)?.let { requestedAlgs.add(it) }
        }

        try {
            val keyPara = getKeyGeneratePara(requestedAlgs.toTypedArray())

            Fido2Logger.debug(PlatformAuthenticator::class.simpleName, "<getKeyGeneratePara> keyPara: $keyPara")

            var hasSourceToBeExcluded = false
            for (ecd in excludeCredentialDescriptorList) {
                if (null != rpEntity.id && null != credentialStore.lookupCredentialSource(
                        rpEntity.id!!, decodeBase64URL(ecd.id)
                    )
                ) {
                    hasSourceToBeExcluded = true
                    break
                }
            }

            if (!hasSourceToBeExcluded && excludeCredentialDescriptorList.isNotEmpty()) {//Check non-resident
                for (cred in excludeCredentialDescriptorList) {
                    val credId = cred.id
                    Fido2Logger.debug(
                        PlatformAuthenticator::class.simpleName,
                        "excludeCredentialDescriptorList credId: $credId"
                    )
                    try {
                        val csCBOR = decryptData(decodeBasee64URLTry(credId))
                        val credSrc = PublicKeyCredentialSource.fromCBOR(csCBOR)
                        if (null != credSrc && credSrc.rpId == rpEntity.id) {
                            hasSourceToBeExcluded = true
                            break
                        }
                    } catch (ex: Exception) {
                        //do nothing try next
                        Fido2Logger.debug(
                            PlatformAuthenticator::class.simpleName,
                            "decryptData fail, try next. ${ex.localizedMessage}"
                        )
                    }
                }
            }

            if (hasSourceToBeExcluded) {
                throw Fido2Error.new(Fido2Error.Companion.ErrorType.invalidState)
            }

            if (requireResidentKey && !this.canStoreResidentKey()) {
                throw Fido2Error.new(Fido2Error.Companion.ErrorType.constraint)
            }

            if (requireUserVerification && !this.allowUserVerification) {
                Fido2Logger.debug(
                    PlatformAuthenticator::class.simpleName,
                    "<authenticatorMakeCredential> insufficient capability (user verification)"
                )
                throw Fido2Error.new(
                    Fido2Error.Companion.ErrorType.constraint,
                    "<authenticatorMakeCredential> insufficient capability (user verification)"
                )
            }

            //dqj TODO: UI interaction
            runBlocking {
                val newUserConsentDeferred = async(Dispatchers.Main) {
                    requestUserConsent(messageTitle, messageSubtitle, allowDeviceSecure, context) }
                newUserConsentDeferred.await()
            }

            var credentialIdStr = UUID.randomUUID().toString()

            val keyPair = makeKey(Pair(keyPara.first, keyPara.second))
            val algTxt = "SHA${keyPara.second / 8}with${keyPara.first}"

            val credSource = PublicKeyCredentialSource(
                0u, ByteArray(0),
                rpEntity.id!!, userEntity.id.toByteArray(), keyPara.third, "", algTxt,
                keyPair.first.encoded)

            var credentialId = credentialIdStr.encodeToByteArray()

            if (requireResidentKey) {
                if (null == rpEntity.id) {
                    throw Fido2Error.new(
                        Fido2Error.Companion.ErrorType.badData,
                        "rpEntity.id is null for ResidentKey."
                    )
                }

                credSource.id = credentialId
                Fido2Logger.debug(
                    PlatformAuthenticator::class.simpleName,
                    "authenticatorMakeCredential-credSource(resident-key): $credSource"
                )

                credentialStore.deleteAllCredentialSources(rpEntity.id!!, credSource.userHandle)
                credentialStore.saveCredentialSource(credSource)
            } else {
                val csCBOR = credSource.toCBOR()
                credentialId = encryptData(
                    csCBOR!!
                )
            }

            val theExtensions = HashMap<String, Any>()
            if(extensions.isNotEmpty()){
                theExtensions.putAll(extensions)
            }
            theExtensions[LibConfig.deviceUniqueIdKey] = LibUtil.getUniqueId(context)
            theExtensions["test_extensions_key"] = "Test_extensions_val"//for dev

            val attestedCredData = AttestedCredentialData(LibConfig.aaguid, credentialId, keyPair.second)

            val md = MessageDigest.getInstance("SHA-256")
            val authenticatorData = AuthenticatorData(
                md.digest(rpEntity.id!!.toByteArray()),
                requireUserPresence || requireUserVerification,
                requireUserVerification,
                backupEligibility = false, //dqj TODO: backupEligibility&backupState support
                backupState = false,
                signCount = 0u, //dqj TODO: support non-zero count
                attestedCredentialData = attestedCredData,
                extensions = theExtensions
            )

            val attestation =
                createAttestation(authenticatorData, clientDataHash, keyPara, keyPair.first, algTxt)
            if (null == attestation) {
                Fido2Logger.debug(
                    PlatformAuthenticator::class.simpleName,
                    "<authenticatorMakeCredential> failed to build attestation object"
                )
                throw Fido2Error.new(Fido2Error.Companion.ErrorType.unknown)
            }

            return attestation
        } catch (fex: Fido2Error) {
            throw fex
        } catch (ex: Exception) {
            ex.localizedMessage?.let {
                Fido2Logger.err(
                    PlatformAuthenticator::class.simpleName,
                    it
                )
            }
            throw Fido2Error.new(Fido2Error.Companion.ErrorType.unknown, ex)
        }
    }

    private suspend fun requestUserConsent(messageTitle: String, messageSubtitle: String,
                                           allowDeviceSecure: Boolean, context: Context) : Boolean{
        when (BiometricManager.from(context).canAuthenticate(
                BiometricManager.Authenticators.BIOMETRIC_WEAK or BiometricManager.Authenticators.BIOMETRIC_STRONG )) {
            //BiometricManager.BIOMETRIC_SUCCESS -> { }

            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> {
                checkDeviceSecure(allowDeviceSecure, Fido2Error.Companion.ErrorType.bioNoneEnrolled)
            }
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> {
                checkDeviceSecure(allowDeviceSecure, Fido2Error.Companion.ErrorType.bioHWUnavailable)
            }
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> {
                checkDeviceSecure(allowDeviceSecure, Fido2Error.Companion.ErrorType.bioNoHardware)
            }
        }

        val promptInfoBldr = BiometricPrompt.PromptInfo.Builder()
            .setTitle(messageTitle).setSubtitle(messageSubtitle)
        if(allowDeviceSecure){
            promptInfoBldr.setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG
                    or BiometricManager.Authenticators.BIOMETRIC_WEAK
                    or BiometricManager.Authenticators.DEVICE_CREDENTIAL)
        }else{
            promptInfoBldr.setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG
                    or BiometricManager.Authenticators.BIOMETRIC_WEAK)
        }
        val promptInfo = promptInfoBldr.build()

        return suspendCoroutine { continuation ->
            val callback = object: BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationError(errorCode: Int,
                                                   errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    continuation.resume(false)
                    throw Fido2Error.new(Fido2Error.Companion.ErrorType.notAllowed,
                        "Code: $errorCode Msg: $errString")
                }

                override fun onAuthenticationSucceeded(
                    result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    continuation.resume(true)
                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    continuation.resume(false)
                    throw Fido2Error.new(Fido2Error.Companion.ErrorType.notAllowed,
                        "Authentication failed")
                }
            }

            val biometricPrompt = BiometricPrompt(context as FragmentActivity,
                ContextCompat.getMainExecutor(context), callback)
            biometricPrompt.authenticate(promptInfo)
            return@suspendCoroutine
        }

    }

    private fun checkDeviceSecure(allowDeviceSecure: Boolean, errType:Fido2Error.Companion.ErrorType){
        if(!allowDeviceSecure){
            throw Fido2Error.new(errType)
        }else{
            val keyguardManager = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager?
            val deviceSeure = keyguardManager != null && keyguardManager.isDeviceSecure
            if(!deviceSeure){
                throw Fido2Error.new(Fido2Error.Companion.ErrorType.deviceNotSeure)
            }
        }
    }

    @OptIn(ExperimentalUnsignedTypes::class)
    override suspend fun authenticatorGetAssertion(
        messageTitle: String, messageSubtitle: String, allowDeviceSecure: Boolean,
        rpId: String, clientDataHash: ByteArray,
        allowCredentialDescriptorList: Array<PublicKeyCredentialDescriptor>,
        requireUserPresence: Boolean, requireUserVerification: Boolean,
        extensions: Map<String, ByteArray>
    ): AuthenticatorAssertionResult? {
        var credSources = gatherCredentialSources(rpId,allowCredentialDescriptorList)
        if(credSources.isEmpty()) {
            Fido2Logger.debug(PlatformAuthenticator::class.simpleName,
                "<authenticatorGetAssertion> not found allowable credential source")
            throw Fido2Error.new( Fido2Error.Companion.ErrorType.notAllowed,
                "not found allowable credential source")
        }

        //dqj TODO: UI interaction
        runBlocking {
            val newUserConsentDeferred = async(Dispatchers.Main) {
                requestUserConsent(messageTitle, messageSubtitle, allowDeviceSecure, context) }
            newUserConsentDeferred.await()
        }

        //dqj TODO: Support processedExtensions

        var newSignCount: UInt = 0u//dqj TODO: Support sign counter

        //dqj TODO: select cred & signCount
        val copiedCred = credSources[0]

        val theExtensions = HashMap<String, Any>()
        if(extensions.isNotEmpty()){
            theExtensions.putAll(extensions)
        }
        theExtensions[LibConfig.deviceUniqueIdKey] = LibUtil.getUniqueId(context)

        val md = MessageDigest.getInstance("SHA-256")
        val authenticatorData = AuthenticatorData(
            md.digest(rpId.toByteArray()),
            requireUserPresence || requireUserVerification,
            requireUserVerification,
            backupEligibility = false, //dqj TODO: backupEligibility&backupState support
            backupState = false,
            signCount = newSignCount,
            attestedCredentialData = null,
            extensions = theExtensions
        )
        val authenticatorDataBytes = authenticatorData.toBytes()

        var dataToBeSigned = authenticatorDataBytes
        dataToBeSigned = dataToBeSigned?.plus(clientDataHash)

        val spec = PKCS8EncodedKeySpec(copiedCred.privateKey)
        val keyFactory = KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_RSA)
        val pkey = keyFactory.generatePrivate(spec)

        val signer = Signature.getInstance(copiedCred.algText)
        signer.initSign(pkey)
        signer.update(dataToBeSigned)
        val signature = signer.sign()
        var assertion = AuthenticatorAssertionResult(authenticatorDataBytes!!,signature)
        assertion.userHandle = copiedCred.userHandle

        if(allowCredentialDescriptorList.size != 1) {
            assertion.credentailId = copiedCred.id
        }

        return assertion
    }

    @OptIn(ExperimentalUnsignedTypes::class)
    override fun silentCredentialDiscovery(rpId: String): Array<PublicKeyCredentialSource> {
        if (!enableSilentCredentialDiscovery) {
            throw Fido2Error.new(
                Fido2Error.Companion.ErrorType.unknown,
                "No SilentCredentialDiscovery feature."
            )
        }
        return credentialStore.loadAllCredentialSources(rpId)
    }

    override fun canStoreResidentKey(): Boolean {
        return enableResidentStorage
    }

    override fun canPerformUserVerification(): Boolean {
        return true
    }

    override fun canSilentCredentialDiscovery(): Boolean {
        return enableSilentCredentialDiscovery
    }

    override fun reset(): Boolean {
        return try {
            credentialStore.removeAll(null)

            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)
            keyStore.deleteEntry(NON_RESIDENTSECKEY_ALIAS)

            true
        } catch (ex: Exception) {
            Fido2Logger.debug(PlatformAuthenticator::class.simpleName, "reset fail")
            false
        }
    }

    @OptIn(ExperimentalUnsignedTypes::class)
    private fun gatherCredentialSources(
        rpId: String,
        allowCredentialDescriptorList: Array<PublicKeyCredentialDescriptor>
    ) : Array<PublicKeyCredentialSource> {

        if (allowCredentialDescriptorList.isEmpty()) {
            return credentialStore.loadAllCredentialSources(rpId)
        } else {
            //Lookup non-resident Credential Source by decrypting Credential ID
            for (allowCred in allowCredentialDescriptorList) {
                try {
                    val csCBOR = decryptData(
                        decodeBasee64URLTry(allowCred.id))
                    val credSrc = PublicKeyCredentialSource.fromCBOR(csCBOR)
                    if (null != credSrc && credSrc.rpId == rpId) {
                        return arrayOf(credSrc)
                    }
                } catch (ex: Exception) {
                    Fido2Logger.debug(PlatformAuthenticator::class.simpleName,
                            "Fail to decryptData, try next:" + ex.javaClass.simpleName + ":"
                                    + ex.message + "|" + ex.localizedMessage)
                    //Do nothing, try next
                }
            }
            if (!LibConfig.enabledInsideAuthenticatorResidentStorage()) {
                Fido2Logger.info(
                    PlatformAuthenticator::class.simpleName,
                    "No non-resident Credential found, we start to try resident Credential. " +
                            "So we may use a Credential that created before you disabling InsideAuthenticatorResidentStorage " +
                            "if auth succ. Calling Fido2Core.clearKeys() can clear all resident Credentials. rpId: $rpId"
                )
            }

            //Look for resident Credential Source with this Credential ID
            val rtn = ArrayList<PublicKeyCredentialSource>()
            allowCredentialDescriptorList.forEach { desc ->
                val cred = credentialStore.lookupCredentialSource(
                    rpId,
                    decodeBasee64URLTry(desc.id)
                )
                if (null != cred) rtn.add(cred)
            }
            return rtn.toTypedArray()
        }
    }

    // 6.3.1 Lookup Credential Source By Credential ID Algoreithm
    @OptIn(ExperimentalUnsignedTypes::class)
    override fun lookupCredentialSource(
        rpId: String,
        credentialId: ByteArray
    ): PublicKeyCredentialSource? {
        Fido2Logger.debug(PlatformAuthenticator::class.simpleName, "lookupCredentialSource")
        return credentialStore.lookupCredentialSource(rpId, credentialId)
    }

    @OptIn(ExperimentalUnsignedTypes::class)
    private fun createAttestation(
        authData: AuthenticatorData, clientDataHash: ByteArray,
        keyPara: Triple<String, Int, Long>, privateKey: PrivateKey, algText:String
    ): AttestationObject? {
        var dataToBeSigned = authData.toBytes()
        dataToBeSigned = dataToBeSigned?.plus(clientDataHash)
        //Fido2Logger.debug("dataToBeSigned: \(dataToBeSigned)")

        if (keyPara.first != "RSA") {
            Fido2Logger.err(
                PlatformAuthenticator::class.simpleName,
                "<sign> Only support RSA now: $keyPara"
            )
            return null
        }
        //Fido2Logger.debug("<createAttestation> SecKeyAlgorithm: \(alg)")

        val signer = Signature.getInstance(algText)
        signer.initSign(privateKey)
        signer.update(dataToBeSigned)
        val sign = signer.sign()

        val stmt = HashMap<String, Any>()
        stmt["alg"] = keyPara.third
        stmt["sig"] = sign

        return AttestationObject(
            "packed", //dqj TODO: support other format?
            authData, stmt
        )
    }
}

//Secure util

fun retrievePublicKey(privetKey: RSAPrivateKey): RSAPublicKey{
    val specP = RSAPublicKeySpec(privetKey.modulus, privetKey.privateExponent)
    val factory = KeyFactory.getInstance("RSA")
    return factory.generatePublic(specP) as RSAPublicKey
}

//Base64 util

fun decodeBasee64URLTry(intext: String):ByteArray{
    var rtn:ByteArray = try {
        Base64.decode(intext, Base64.URL_SAFE)
    }catch (ex:Exception){
        intext.toByteArray()
    }
    return rtn
}

//Platform Authenticator Store

interface CredentialStore {
    @OptIn(ExperimentalUnsignedTypes::class)
    fun lookupCredentialSource(rpId: String, credentialId: ByteArray) :PublicKeyCredentialSource?

    @OptIn(ExperimentalUnsignedTypes::class)
    fun saveCredentialSource(cred: PublicKeyCredentialSource)

    @OptIn(ExperimentalUnsignedTypes::class)
    fun loadAllCredentialSources(rpId: String) : Array<PublicKeyCredentialSource>

    @OptIn(ExperimentalUnsignedTypes::class)
    fun deleteCredentialSource(cred: PublicKeyCredentialSource)

    fun deleteAllCredentialSources(rpId: String, userHandle: ByteArray)

    fun removeAll(rpId:String?)
}

class KeystoreCredentialStore(var context: Context) : CredentialStore {

    companion object{
        private const val PREFERENCE_FILENAME_ALL_PREFERENCES = "all_dfido2lib_preferences"
        private const val PREFERENCE_KEYNAME_ALL_PREFERENCES  = "all_preferences"
        private const val PREFERENCE_FILENAME_PREFIX = "dfido2lib_"
        private const val PREFERENCE_MASTER_KEY_ALIAS = "mkey_dfido2lib_preferences"
    }

    init {
        //context.getSharedPreferences(PREFERENCE_FILENAME_ALL_PREFERENCES, MODE_PRIVATE)
        EncryptedSharedPreferences.create(
            context, PREFERENCE_FILENAME_ALL_PREFERENCES,
            getMasterKey(PREFERENCE_MASTER_KEY_ALIAS),
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM)
    }

    private fun getMasterKey(alias: String):MasterKey{
        val spec = KeyGenParameterSpec.Builder(
            alias, //MasterKey.DEFAULT_MASTER_KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .build()

        return Builder(this.context, alias)
            .setKeyGenParameterSpec(spec)
            .build()
    }

    private fun getEncryptedSharedPreferences(preferFile: String):SharedPreferences{
        var encPref = context.getSharedPreferences(preferFile, MODE_PRIVATE)

        if(null == encPref){
            encPref = EncryptedSharedPreferences.create(
                context, preferFile,
                getMasterKey(PREFERENCE_MASTER_KEY_ALIAS),
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM)
        }

        val preferList =context.getSharedPreferences(PREFERENCE_FILENAME_ALL_PREFERENCES, MODE_PRIVATE)
        val all=getStringArrayPref(preferList, PREFERENCE_KEYNAME_ALL_PREFERENCES)
        if(!all.contains(preferFile)){
            all.add(preferFile)
            setStringArrayPref(preferList, PREFERENCE_KEYNAME_ALL_PREFERENCES, all)
        }

        return encPref
    }

    private fun setStringArrayPref(preference: SharedPreferences, key: String, values: ArrayList<String>) {
        val editor = preference.edit()
        val a = JSONArray()
        for (i in 0 until values.size) {
            a.put(values[i])
        }
        if (values.isNotEmpty()) {
            editor.putString(key, a.toString())
        } else {
            editor.putString(key, null)
        }
        editor.commit()
    }

    private fun getStringArrayPref(preference: SharedPreferences,  key: String): ArrayList<String> {
        val json = preference.getString(key, null)
        val rtn = ArrayList<String>()
        if (json != null) {
            try {
                val a = JSONArray(json)
                for (i in 0 until a.length()) {
                    val v = a.optString(i)
                    rtn.add(v)
                }
            } catch (e: JSONException) {
                e.localizedMessage?.let {
                    Fido2Logger.err(KeystoreCredentialStore::class.simpleName,
                        it
                    )
                }
                rtn.clear()
            }
        }
        return rtn
    }

    override fun removeAll(rpId: String?) {
        val preferList = context.getSharedPreferences(PREFERENCE_FILENAME_ALL_PREFERENCES, MODE_PRIVATE)

        val all=getStringArrayPref(preferList, PREFERENCE_KEYNAME_ALL_PREFERENCES)
        var keepNames=ArrayList<String>()
        //val keyStore = KeyStore.getInstance("AndroidKeyStore")
        //keyStore.load(null)
        all.forEach { name ->
            if (null == rpId || name == PREFERENCE_FILENAME_PREFIX + rpId) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                    context.deleteSharedPreferences(name)
                } else {
                    context.getSharedPreferences(name, MODE_PRIVATE).edit().clear().commit()
                    val dir = File(context.applicationInfo.dataDir, "shared_prefs")
                    File(dir, "$name.xml").delete()
                }
            }else{
                keepNames.add(name)
            }
        }
        setStringArrayPref(preferList, PREFERENCE_KEYNAME_ALL_PREFERENCES,keepNames)
    }

    @SuppressLint("CommitPrefEdits")
    @OptIn(ExperimentalUnsignedTypes::class)
    override fun deleteAllCredentialSources(rpId: String, userHandle: ByteArray) {
        val prefer = getEncryptedSharedPreferences(PREFERENCE_FILENAME_PREFIX + rpId)
        val lst:List<String> = prefer.all.map {it.key}
        lst.forEach { key ->
            val v = prefer.getString(key, null)
            if(null != v){
                val b = decodeBase64URL(v)
                val cred = PublicKeyCredentialSource.fromCBOR(b)
                if(null != cred && cred.userHandle.contentEquals(userHandle)) {
                    prefer.edit().remove(key).commit()

                    //We do not use keystore
                    /*val keyStore = KeyStore.getInstance("AndroidKeyStore")
                    keyStore.load(null)
                    keyStore.deleteEntry(PlatformAuthenticator.KEY_PREFIX+String(cred.id))*/
                }
            }
        }
    }

    @OptIn(ExperimentalUnsignedTypes::class)
    override fun loadAllCredentialSources(rpId: String) : Array<PublicKeyCredentialSource> {
        val rtn = ArrayList<PublicKeyCredentialSource>()
        val lst = getEncryptedSharedPreferences(PREFERENCE_FILENAME_PREFIX + rpId)
                    .all.map {it.value}
        lst.forEach { value ->
            val b = (decodeBase64URL(value as String))
            val cred = PublicKeyCredentialSource.fromCBOR(b)
            if(null != cred)rtn.add(cred)
        }
        return rtn.toTypedArray()
    }

    @OptIn(ExperimentalUnsignedTypes::class)
    override fun lookupCredentialSource(rpId: String, credentialId: ByteArray)
            : PublicKeyCredentialSource? {
        var cid = String(credentialId)
        val pref = getEncryptedSharedPreferences(PREFERENCE_FILENAME_PREFIX + rpId)
        val cobr= pref.getString(cid, null)
        return if (cobr != null) {
            PublicKeyCredentialSource.fromCBOR(decodeBase64URL(cobr))
        } else null
    }

    @OptIn(ExperimentalUnsignedTypes::class)
    @SuppressLint("CommitPrefEdits")
    override fun deleteCredentialSource(cred: PublicKeyCredentialSource){
        getEncryptedSharedPreferences(PREFERENCE_FILENAME_PREFIX + cred.rpId)
            .edit().remove(String(cred.id)).commit()

        //Delete key from store
        /*val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        keyStore.deleteEntry(PlatformAuthenticator.KEY_PREFIX+String(cred.id))*/
    }

    @OptIn(ExperimentalUnsignedTypes::class)
    override fun saveCredentialSource(cred: PublicKeyCredentialSource){
        val pref = getEncryptedSharedPreferences(PREFERENCE_FILENAME_PREFIX + cred.rpId)
        var cid = String(cred.id)
        val value = cred.toCBOR()
        if(null != value){
            val s = encodeBase64URL(value)
            pref.edit().putString(cid, s).commit()
        }

    }

}


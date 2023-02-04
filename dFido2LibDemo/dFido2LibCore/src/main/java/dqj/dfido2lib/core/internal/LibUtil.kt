package dqj.dfido2lib.core.internal

import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.scottyab.rootbeer.RootBeer
import dqj.dfido2lib.core.LibConfig
import dqj.dfido2lib.core.authenticator.KeystoreCredentialStore
import dqj.dfido2lib.core.client.Fido2Error
import org.json.JSONArray
import org.json.JSONException
import java.io.*
import java.net.HttpURLConnection
import java.net.URL


class Fido2Logger {

    companion object {
        private val libraryPart = "dFido2Lib"

        enum class Level(val level: Int) {
            err(1),
            warn(2),
            info(3),
            debug(4)
        }

        private var logLevel: Level = Level.info

        fun confLogLevel(level: Level){
            logLevel = level
        }

        fun debug(tag: String?, msg: String) {
            if (logLevel == Level.debug) {
                Log.d(libraryPart, wrapMessage(tag!!, msg))
            }
        }

        fun err(tag: String?, msg: String) {
            if (logLevel >= Level.err) {
                Log.e(libraryPart, wrapMessage(tag!!, msg))
            }
        }

        fun info(tag: String?, msg: String) {
            if (logLevel >= Level.info) {
                Log.i(libraryPart, wrapMessage(tag!!, msg))
            }
        }

        fun warn(tag: String?, msg: String) {
            if (logLevel >= Level.warn) {
                Log.w(libraryPart, wrapMessage(tag!!, msg))
            }
        }

        private fun wrapMessage(klass: String, msg: String): String {
            return "[$klass] $msg"
        }
    }
}

class LibUtil{
    companion object {

        suspend fun httpRequest(url: String, method: String,
                body: ByteArray?, headers: Map<String, String>,
                usecaches: Boolean, timeout: Int = 60000): Pair<String, List<String>> {
            val url = URL(url)
            val urlConnection = url.openConnection() as HttpURLConnection
            urlConnection.requestMethod = method

            urlConnection.doOutput = true
            urlConnection.doInput = true

            headers.forEach { entry ->
                urlConnection.setRequestProperty(entry.key, entry.value)
            }

            urlConnection.useCaches = usecaches
            urlConnection.connectTimeout = timeout
            urlConnection.readTimeout = timeout
            urlConnection.setChunkedStreamingMode(0)

            val sbRtn = StringBuilder()
            val sbCookies = ArrayList<String>()

            try{
                val outputStream = urlConnection.outputStream
                outputStream.write(body)
                outputStream.flush()
                outputStream.close()

                val statusCode = urlConnection.responseCode
                if (statusCode == HttpURLConnection.HTTP_OK) {
                    var inStream: InputStream? = urlConnection.inputStream
                    val br = BufferedReader(InputStreamReader(inStream))

                    for (line in br.readLines()) {
                        line.let { sbRtn.append(line) }
                    }

                    br.close()
                    inStream?.close()

                    urlConnection.headerFields.forEach{ (key, value) ->
                        if(null != key && key.uppercase() == "SET-COOKIE") sbCookies.addAll(value)
                    }
                }else{
                    var errtxt = urlConnection.responseCode.toString() + urlConnection.responseMessage
                    Fido2Logger.err(LibUtil::class.simpleName, "$errtxt:$sbRtn")
                    throw Fido2Error.new( Fido2Error.Companion.ErrorType.unknown, sbRtn.toString())
                }
            }catch (ef:FileNotFoundException) {
                var errStream: InputStream? = null
                try {
                    errStream = urlConnection.errorStream
                    val br = BufferedReader(InputStreamReader(errStream))
                    val sb = StringBuilder()
                    for (line in br.readLines()) {
                        line.let { sb.append(line) }
                    }
                    br.close()
                    var errtxt = urlConnection.responseCode.toString() + urlConnection.responseMessage
                    Fido2Logger.err(LibUtil::class.simpleName, "$errtxt:$sb")
                    throw Fido2Error.new( Fido2Error.Companion.ErrorType.unknown, sb.toString())
                } catch (e1: Exception) {
                    e1.localizedMessage?.let { Fido2Logger.err(LibUtil::class.simpleName, it) }
                    throw Fido2Error.new( Fido2Error.Companion.ErrorType.unknown, e1)
                } finally {
                    if (errStream != null) {
                        try {
                            errStream.close()
                        } catch (e2: IOException) {
                            e2.localizedMessage?.let {
                                Fido2Logger.err(LibUtil::class.simpleName,
                                    it
                                )
                            }
                            throw Fido2Error.new( Fido2Error.Companion.ErrorType.unknown, e2)
                        }
                    }
                }
            }catch (fido2ex:Fido2Error){
                throw fido2ex
            }catch (ex:Exception){
                ex.localizedMessage?.let { Fido2Logger.err(LibUtil::class.simpleName, it) }
                throw Fido2Error.new(Fido2Error.Companion.ErrorType.notSupported, ex)
            }finally {
                urlConnection.disconnect()
            }

            return Pair(sbRtn.toString(), sbCookies)
        }

        fun buildCookesHeaderValue(cookies: List<String>): String{
            val sbRtn = StringBuilder()
            //TODO check details, like expire time
            cookies.forEach { c ->
                var v = if(0 < c.indexOf(";")) c.substring(0, c.indexOf(";")+1)+" "
                else "$c; "
                sbRtn.append(v)
            }
            return sbRtn.toString()
        }

        fun checkDevice(context: Context){
            if(!LibConfig.enableRooted){
                val rootBeer = RootBeer(context)
                if (rootBeer.isRooted) {
                    Fido2Logger.err(LibUtil::class.simpleName,
                        "A rooted device or emulator!"
                    )
                    throw Fido2Error.new(Fido2Error.Companion.ErrorType.unknown,
                        "LibErr101: A rooted device or emulator!")
                }
            }
        }


    }
}

class KeyTools (private var context: Context) {
    companion object{
        private const val PREFERENCE_FILENAME_ALL_KEYPREFERENCES= "all_dfido2lib_preferences_keys"
        private const val PREFERENCE_KEYNAME_ALL_KEYPREFERENCES  = "all_preferences_keys"
        //private const val PREFERENCE_FILENAME_PREFIX_KEYS = "dfido2lib_keys_"
        private const val PREFERENCE_MASTER_KEY_ALIAS = "mkey_dfido2lib_pre_keys"
    }

    init {
        //context.getSharedPreferences(PREFERENCE_FILENAME_ALL_PREFERENCES, MODE_PRIVATE)
        EncryptedSharedPreferences.create(
            context, PREFERENCE_FILENAME_ALL_KEYPREFERENCES,
            getMasterKey(PREFERENCE_MASTER_KEY_ALIAS),
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM)
    }

    private fun getMasterKey(alias: String): MasterKey {
        val spec = KeyGenParameterSpec.Builder(
            alias, //MasterKey.DEFAULT_MASTER_KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .build()

        return MasterKey.Builder(this.context, alias)
            .setKeyGenParameterSpec(spec)
            .build()
    }

    fun saveKey(preferFile: String, handle: String, key: String){
        val pref = getEncryptedSharedPreferences(preferFile)
        //val s = ByteArrayUtil.encodeBase64URL(key)
        pref.edit().putString(handle, key).commit()
    }

    fun retrieveKey(preferFile: String, handle: String) : String? {
        val pref = getEncryptedSharedPreferences(preferFile)
        val key = pref.getString(handle, null)
        //return key?.let { ByteArrayUtil.decodeBase64URL(it) }
        return key
    }

    fun deleteKey(preferFile: String, handle: String) {
        getEncryptedSharedPreferences(preferFile)
            .edit().remove(handle).commit()
    }

    fun clearKey(handle: String?) {
        val preferList = context.getSharedPreferences(
            PREFERENCE_FILENAME_ALL_KEYPREFERENCES,
            Context.MODE_PRIVATE
        )

        val all=getStringArrayPref(preferList,
            PREFERENCE_KEYNAME_ALL_KEYPREFERENCES
        )
        var keepNames= java.util.ArrayList<String>()
        all.forEach { name ->
            if (null == handle) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                    context.deleteSharedPreferences(name)
                } else {
                    context.getSharedPreferences(name, Context.MODE_PRIVATE).edit().clear().commit()
                    val dir = File(context.applicationInfo.dataDir, "shared_prefs")
                    File(dir, "$name.xml").delete()
                }
            }else{
                deleteKey(name, handle)
                keepNames.add(name)
            }
        }
        setStringArrayPref(preferList, PREFERENCE_KEYNAME_ALL_KEYPREFERENCES,keepNames)
    }

    private fun getEncryptedSharedPreferences(preferFile: String): SharedPreferences {
        var encPref = context.getSharedPreferences(preferFile, Context.MODE_PRIVATE)

        if(null == encPref){
            encPref = EncryptedSharedPreferences.create(
                context, preferFile,
                getMasterKey(PREFERENCE_MASTER_KEY_ALIAS),
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM)
        }

        val preferList =context.getSharedPreferences(
            PREFERENCE_FILENAME_ALL_KEYPREFERENCES,
            Context.MODE_PRIVATE
        )
        val all=getStringArrayPref(preferList,
            PREFERENCE_KEYNAME_ALL_KEYPREFERENCES
        )
        if(!all.contains(preferFile)){
            all.add(preferFile)
            setStringArrayPref(preferList,
                PREFERENCE_KEYNAME_ALL_KEYPREFERENCES, all)
        }

        return encPref
    }

    private fun setStringArrayPref(preference: SharedPreferences, key: String, values: java.util.ArrayList<String>) {
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

    private fun getStringArrayPref(preference: SharedPreferences,  key: String): java.util.ArrayList<String> {
        val json = preference.getString(key, null)
        val rtn = java.util.ArrayList<String>()
        if (json != null) {
            try {
                val a = JSONArray(json)
                for (i in 0 until a.length()) {
                    val v = a.optString(i)
                    rtn.add(v)
                }
            } catch (e: JSONException) {
                e.localizedMessage?.let {
                    Fido2Logger.err(KeyTools::class.simpleName,
                        it
                    )
                }
                rtn.clear()
            }
        }
        return rtn
    }
}
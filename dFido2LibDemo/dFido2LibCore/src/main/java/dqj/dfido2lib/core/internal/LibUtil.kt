package dqj.dfido2lib.core.internal

import android.util.Log
import dqj.dfido2lib.core.client.Fido2Error
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
    }
}

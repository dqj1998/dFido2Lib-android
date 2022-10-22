package dqj.dfido2lib.core.client

class Fido2Error: java.lang.Exception() {
    var error = ErrorType.unknown
    var details = Exception()

    companion object {
        enum class ErrorType(val type: String) {
            badData("fido2.badData"),
            badOperation("fido2.badOperation"),
            invalidState("fido2.invalidState"),
            constraint("fido2.constraint"),
            cancelled("fido2.cancelled"),
            timeout("fido2.timeout"),
            notAllowed("fido2.notAllowed"),
            notSupported("fido2.notSupported"),
            typeError("fido2.typeError"),
            unknown("fido2.unknown"),

            bioNoHardware("android.BIOMETRIC_ERROR_NO_HARDWARE"),
            bioHWUnavailable("android.BIOMETRIC_ERROR_HW_UNAVAILABLE"),
            bioNoneEnrolled("android.BIOMETRIC_ERROR_NONE_ENROLLED"),

            deviceNotSeure("android.DEVICE_NOT_SECURE"),
        }

        fun new(error: ErrorType = ErrorType.unknown, message: String? = null): Fido2Error {
            var err = Fido2Error()
            err.error = error
            if (null != message) err.details = Exception(message)
            return err
        }

        fun new(error: ErrorType = ErrorType.unknown, details: Exception): Fido2Error {
            var err = Fido2Error()
            err.error = error
            if (null != details) err.details = details
            return err
        }
    }

    fun fullMessage():String{
        var msg = error.type + " : ("
        msg += details.javaClass.simpleName + ")" + details.localizedMessage + " | " + details.message
        msg += " | $localizedMessage | $message"
        return msg
    }
}
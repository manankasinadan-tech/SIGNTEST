package com.example.api

object SignerApiContract {
    const val API_VERSION = "1.0"
    const val PACKAGE_ID = "com.aistudio.signerlab.kxfmqt"

    // Activity Intent Action & Deep Link
    const val ACTION_VERIFY_APK = "com.aistudio.signerlab.action.VERIFY_APK"
    const val DEEP_LINK_SCHEME = "signerlab"
    const val DEEP_LINK_HOST = "verify"

    // ContentProvider Authority & Methods
    const val PROVIDER_AUTHORITY = "com.aistudio.signerlab.kxfmqt.api"
    const val PROVIDER_URI = "content://$PROVIDER_AUTHORITY"
    const val METHOD_VERIFY_APK = "verify_apk"
    const val METHOD_PING = "ping"

    // Input Extras
    const val EXTRA_APK_PATH = "apk_path"
    const val EXTRA_APK_PATHS = "apk_paths"
    const val EXTRA_URI = "uri"
    const val EXTRA_AUTO_VERIFY = "auto_verify"
    const val EXTRA_RETURN_RESULT = "return_result"
    const val EXTRA_SILENT_RETURN = "silent_return"
    const val EXTRA_LANG = "lang"

    // Output Result Extras / Bundle Keys
    const val RESULT_IS_VERIFIED = "is_verified"
    const val RESULT_DETECTED_SCHEMES = "detected_schemes"
    const val RESULT_VERIFIED_SCHEMES = "verified_schemes"
    const val RESULT_CERT_SHA256_LIST = "cert_sha256_list"
    const val RESULT_PACKAGE_NAME = "package_name"
    const val RESULT_JSON = "result_json"
    const val RESULT_TEXT = "result_text"
    const val RESULT_ERROR = "error_message"
}

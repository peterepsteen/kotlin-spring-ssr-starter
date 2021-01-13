package com.example.saasstarter.auth

object AuthenticationConstants {
    const val EXPIRATION_TIME: Long = 864000000 // 10 days
    const val TOKEN_PREFIX = "Bearer "
    const val HEADER_STRING = "Authorization"
    const val AUTHORITIES_KEY = "authorities"
    const val ACCESS_TOKEN_PARAM = "access_token"
}
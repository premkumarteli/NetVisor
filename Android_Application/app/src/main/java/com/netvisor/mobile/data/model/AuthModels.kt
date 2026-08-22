package com.netvisor.mobile.data.model

import kotlinx.serialization.Serializable

@Serializable
data class LoginRequest(
    val username: String,
    val password: String
)

@Serializable
data class TokenResponse(
    val access_token: String,
    val token_type: String
)

@Serializable
data class UserProfile(
    val id: String,
    val username: String,
    val email: String? = null,
    val role: String,
    val organization_id: String? = null
)

package com.netvisor.mobile.data.model

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement

@Serializable
data class Alert(
    val id: Int,
    val timestamp: String,
    val device_ip: String,
    val severity: String,
    val risk_score: Float,
    val message: String? = null,
    val resolved: Boolean = false,
    val breakdown: Map<String, JsonElement>? = null
)

package com.netvisor.mobile.data.model

import kotlinx.serialization.Serializable

@Serializable
data class Device(
    val id: String,
    val ip: String,
    val mac: String? = null,
    val hostname: String? = null,
    val vendor: String? = null,
    val os: String? = null,
    val status: String? = "offline",
    val risk_score: Int? = 0,
    val last_seen: String? = null
)

@Serializable
data class DeviceRisk(
    val device_id: String,
    val current_score: Int,
    val risk_level: String,
    val reasons: List<String>,
    val confidence: Double? = null
)

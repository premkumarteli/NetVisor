package com.netvisor.mobile.data.model

import kotlinx.serialization.Serializable

@Serializable
data class AgentSummary(
    val agent_id: String,
    val hostname: String = "Unknown",
    val ip_address: String = "-",
    val status: String = "Offline",
    val last_seen: String? = null,
    val device_count: Int = 0,
    val os_family: String? = "Unknown",
    val version: String? = "Unknown",
    val upload_queue_depth: Int = 0
)

@Serializable
data class AppSummaryItem(
    val application: String,
    val category: String? = "Web",
    val bandwidth_bytes: Long = 0,
    val event_count: Int = 0,
    val last_seen: String? = null
)

@Serializable
data class DpiStatus(
    val status: String = "active",
    val packet_engine_running: Boolean = true,
    val total_inspected_flows: Long = 0,
    val detected_protocols_count: Int = 0
)

@Serializable
data class WebActivityItem(
    val domain: String = "Unknown",
    val category: String? = "General",
    val risk_level: String = "safe",
    val confidence_score: Double = 0.0,
    val request_bytes: Long = 0,
    val response_bytes: Long = 0,
    val event_count: Int = 1,
    val timestamp: String? = null
)

@Serializable
data class FlowLogItem(
    val id: Long? = null,
    val src_ip: String,
    val dst_ip: String,
    val src_port: Int,
    val dst_port: Int,
    val protocol: String,
    val domain: String? = null,
    val byte_count: Long = 0,
    val packet_count: Long = 0,
    val last_seen: String? = null
)

@Serializable
data class SystemHealth(
    val status: String = "healthy",
    val database: String = "connected",
    val version: String = "2.0.0"
)

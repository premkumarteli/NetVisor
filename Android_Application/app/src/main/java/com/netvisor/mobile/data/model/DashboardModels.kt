package com.netvisor.mobile.data.model

import kotlinx.serialization.Serializable

@Serializable
data class DashboardOverview(
    val agents_summary: SummaryStats? = null,
    val gateways_summary: SummaryStats? = null,
    val fleet_summary: FleetSummary? = null
)

@Serializable
data class SummaryStats(
    val online: Int,
    val offline: Int,
    val total: Int,
    val degraded: Int,
    val queue_depth: Int
)

@Serializable
data class FleetSummary(
    val total_queue_depth: Int,
    val total_degraded: Int
)

@Serializable
data class ActivityEvent(
    val timestamp: String,
    val event_type: String,
    val message: String,
    val severity: String,
    val device_id: String? = null,
    val organization_id: String? = null
)

@Serializable
data class TrafficHistory(
    val timestamps: List<String>,
    val inbound: List<Long>,
    val outbound: List<Long>
)

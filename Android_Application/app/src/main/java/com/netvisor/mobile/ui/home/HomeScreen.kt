package com.netvisor.mobile.ui.home

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Devices
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Traffic
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.netvisor.mobile.data.model.ActivityEvent
import com.netvisor.mobile.data.model.DashboardOverview
import com.netvisor.mobile.ui.components.GlassCard
import com.netvisor.mobile.ui.components.MetricCard
import com.netvisor.mobile.ui.components.StatusBadge
import com.netvisor.mobile.ui.theme.*
import com.netvisor.mobile.viewmodel.HomeViewModel

@Composable
fun HomeScreen(viewModel: HomeViewModel) {
    val overviewState by viewModel.overview.collectAsState()
    val activityState by viewModel.recentActivity.collectAsState()
    val trafficTotal by viewModel.trafficTotal.collectAsState()
    val threatCount by viewModel.threatCount.collectAsState()
    val criticalThreatCount by viewModel.criticalThreatCount.collectAsState()

    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 24.dp),
        verticalArrangement = Arrangement.spacedBy(24.dp)
    ) {
        item {
            Header()
        }

        item {
            SystemStatusCard()
        }

        item {
            MetricsGrid(
                state = overviewState,
                trafficTotal = trafficTotal,
                threatCount = threatCount,
                criticalThreatCount = criticalThreatCount
            )
        }

        item {
            SectionHeader("Recent Security Activity")
        }

        when (val state = activityState) {
            is HomeViewModel.DashboardUiState.Loading -> {
                item {
                    Box(modifier = Modifier.fillMaxWidth().padding(32.dp), contentAlignment = Alignment.Center) {
                        CircularProgressIndicator(color = Primary)
                    }
                }
            }
            is HomeViewModel.DashboardUiState.Success -> {
                if (state.data.isEmpty()) {
                    item {
                        GlassCard {
                            Text(
                                text = "No recent security activity detected.",
                                color = SecondaryText,
                                style = MaterialTheme.typography.bodyMedium
                            )
                        }
                    }
                } else {
                    items(state.data) { event ->
                        ActivityItem(event)
                    }
                }
            }
            is HomeViewModel.DashboardUiState.Error -> {
                item {
                    GlassCard {
                        Text(text = state.message, color = Critical, style = MaterialTheme.typography.bodyMedium)
                    }
                }
            }
        }
        
        item {
            Spacer(modifier = Modifier.height(100.dp)) // Padding for bottom bar
        }
    }
}

@Composable
private fun Header() {
    Column(modifier = Modifier.padding(vertical = 16.dp)) {
        Text(
            text = "NetVisor",
            color = PrimaryText,
            style = MaterialTheme.typography.headlineLarge,
            fontWeight = FontWeight.Bold,
            letterSpacing = 2.sp
        )
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(
                modifier = Modifier
                    .size(8.dp)
                    .background(Success, shape = MaterialTheme.shapes.small)
            )
            Spacer(modifier = Modifier.width(8.dp))
            Text(
                text = "Network Operational",
                color = Success,
                style = MaterialTheme.typography.labelMedium
            )
        }
    }
}

@Composable
private fun SystemStatusCard() {
    GlassCard {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column {
                Text(
                    text = "SYSTEM STATUS",
                    color = SecondaryText,
                    style = MaterialTheme.typography.labelSmall
                )
                Text(
                    text = "ALL SYSTEMS OPERATIONAL",
                    color = PrimaryText,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
            }
            StatusBadge(status = "Healthy", color = Success)
        }
    }
}

@Composable
private fun MetricsGrid(
    state: HomeViewModel.DashboardUiState<DashboardOverview>,
    trafficTotal: String,
    threatCount: Int,
    criticalThreatCount: Int
) {
    Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
        val data = (state as? HomeViewModel.DashboardUiState.Success)?.data
        
        Row(horizontalArrangement = Arrangement.spacedBy(16.dp)) {
            MetricCard(
                label = "Devices",
                value = data?.agents_summary?.total?.toString() ?: "--",
                subValue = "${data?.agents_summary?.online ?: 0} Online",
                icon = Icons.Default.Devices,
                modifier = Modifier.weight(1f)
            )
            MetricCard(
                label = "Traffic (24h)",
                value = trafficTotal,
                subValue = "Inbound / Outbound",
                icon = Icons.Default.Traffic,
                modifier = Modifier.weight(1f)
            )
        }
        
        Row(horizontalArrangement = Arrangement.spacedBy(16.dp)) {
            MetricCard(
                label = "Threats",
                value = threatCount.toString(),
                subValue = "$criticalThreatCount Critical/High",
                icon = Icons.Default.Security,
                modifier = Modifier.weight(1f)
            )
            MetricCard(
                label = "Gateways",
                value = data?.gateways_summary?.total?.toString() ?: "0",
                subValue = "${data?.gateways_summary?.online ?: 0} Active",
                icon = Icons.Default.Security,
                modifier = Modifier.weight(1f)
            )
        }
    }
}

@Composable
private fun SectionHeader(title: String) {
    Text(
        text = title,
        color = PrimaryText,
        style = MaterialTheme.typography.titleMedium,
        fontWeight = FontWeight.Bold,
        modifier = Modifier.padding(vertical = 8.dp)
    )
}

@Composable
private fun ActivityItem(event: ActivityEvent) {
    GlassCard(modifier = Modifier.padding(vertical = 4.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(
                modifier = Modifier
                    .size(4.dp)
                    .background(
                        when (event.severity.uppercase()) {
                            "CRITICAL" -> Critical
                            "HIGH" -> Warning
                            else -> Primary
                        },
                        shape = MaterialTheme.shapes.small
                    )
            )
            Spacer(modifier = Modifier.width(16.dp))
            Column {
                Text(
                    text = event.message,
                    color = PrimaryText,
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.Medium
                )
                Text(
                    text = "${event.event_type} • ${event.timestamp}",
                    color = SecondaryText,
                    style = MaterialTheme.typography.labelSmall
                )
            }
        }
    }
}

package com.netvisor.mobile.ui.threats

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.netvisor.mobile.data.model.Alert
import com.netvisor.mobile.ui.components.*
import com.netvisor.mobile.ui.theme.*
import com.netvisor.mobile.viewmodel.ThreatsViewModel

@Composable
fun ThreatsScreen(viewModel: ThreatsViewModel) {
    val uiState by viewModel.alerts.collectAsState()
    val selectedSeverity by viewModel.selectedSeverity.collectAsState()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 24.dp)
    ) {
        Header(uiState)
        
        Spacer(modifier = Modifier.height(16.dp))
        
        SeverityFilter(selectedSeverity) { viewModel.onSeverityChange(it) }
        
        Spacer(modifier = Modifier.height(16.dp))

        when (val state = uiState) {
            is ThreatsViewModel.ThreatsUiState.Loading -> {
                Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    CircularProgressIndicator(color = Primary)
                }
            }
            is ThreatsViewModel.ThreatsUiState.Success -> {
                LazyColumn(
                    modifier = Modifier.fillMaxSize(),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    items(state.alerts) { alert ->
                        ThreatItem(alert)
                    }
                    item {
                        Spacer(modifier = Modifier.height(100.dp))
                    }
                }
            }
            is ThreatsViewModel.ThreatsUiState.Error -> {
                Text(text = state.message, color = Critical)
            }
        }
    }
}

@Composable
private fun Header(state: ThreatsViewModel.ThreatsUiState) {
    val alerts = (state as? ThreatsViewModel.ThreatsUiState.Success)?.alerts ?: emptyList()
    val criticalCount = alerts.count { it.severity.uppercase() == "CRITICAL" }
    
    Column(modifier = Modifier.padding(vertical = 16.dp)) {
        Text(
            text = "Threats",
            color = PrimaryText,
            style = MaterialTheme.typography.headlineLarge,
            fontWeight = FontWeight.Bold,
            letterSpacing = 2.sp
        )
        Text(
            text = "${alerts.size} Active Threats • $criticalCount Critical",
            color = if (criticalCount > 0) Critical else SecondaryText,
            style = MaterialTheme.typography.labelMedium
        )
    }
}

@Composable
private fun SeverityFilter(
    selectedSeverity: String?,
    onSeveritySelected: (String?) -> Unit
) {
    val severities = listOf("All", "Critical", "High", "Medium", "Low")
    
    LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        items(severities) { severity ->
            val value = if (severity == "All") null else severity.uppercase()
            GlassChip(
                text = severity,
                selected = (value == selectedSeverity),
                onClick = { onSeveritySelected(value) }
            )
        }
    }
}

@Composable
private fun ThreatItem(alert: Alert) {
    val severityColor = when (alert.severity.uppercase()) {
        "CRITICAL" -> Critical
        "HIGH" -> Warning
        "MEDIUM" -> Primary
        else -> SecondaryText
    }
    
    GlassCard {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.Top
        ) {
            Column(modifier = Modifier.weight(1f)) {
                StatusBadge(status = alert.severity, color = severityColor)
                Spacer(modifier = Modifier.height(12.dp))
                Text(
                    text = alert.message ?: "Unknown Threat",
                    color = PrimaryText,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    text = "Device: ${alert.device_ip}",
                    color = SecondaryText,
                    style = MaterialTheme.typography.bodySmall
                )
            }
            Text(
                text = alert.timestamp.split(" ").lastOrNull() ?: "",
                color = SecondaryText,
                style = MaterialTheme.typography.labelSmall
            )
        }
    }
}

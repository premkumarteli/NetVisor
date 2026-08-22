package com.netvisor.mobile.ui.network

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.Icons
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.netvisor.mobile.data.model.Device
import com.netvisor.mobile.data.model.DeviceRisk
import com.netvisor.mobile.ui.components.GlassCard
import com.netvisor.mobile.ui.components.StatusBadge
import com.netvisor.mobile.ui.theme.*
import com.netvisor.mobile.viewmodel.DeviceDetailsViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DeviceDetailsScreen(
    device: Device,
    viewModel: DeviceDetailsViewModel,
    onBack: () -> Unit
) {
    val riskState by viewModel.risk.collectAsState()
    
    LaunchedEffect(device.id) {
        viewModel.loadRisk(device.id)
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(device.ip, color = PrimaryText) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back", tint = PrimaryText)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = Background)
            )
        },
        containerColor = Background
    ) { innerPadding ->
        LazyColumn(
            modifier = Modifier
                .padding(innerPadding)
                .padding(horizontal = 24.dp)
                .fillMaxSize(),
            verticalArrangement = Arrangement.spacedBy(24.dp)
        ) {
            item {
                StatusHeader(device)
            }
            
            item {
                RiskScoreSection(riskState)
            }
            
            item {
                InfoSection("IDENTITY", listOf(
                    "IP" to device.ip,
                    "MAC" to (device.mac ?: "Unknown"),
                    "Hostname" to (device.hostname ?: "Unknown"),
                    "Vendor" to (device.vendor ?: "Unknown"),
                    "OS" to (device.os ?: "Unknown")
                ))
            }
            
            item {
                Spacer(modifier = Modifier.height(32.dp))
            }
        }
    }
}

@Composable
private fun StatusHeader(device: Device) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column {
            Text(
                text = device.hostname ?: "Unknown Device",
                color = PrimaryText,
                style = MaterialTheme.typography.headlineMedium,
                fontWeight = FontWeight.Bold
            )
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    modifier = Modifier
                        .size(8.dp)
                        .background(if (device.status == "online") Success else SecondaryText, shape = MaterialTheme.shapes.small)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = device.status?.uppercase() ?: "OFFLINE",
                    color = if (device.status == "online") Success else SecondaryText,
                    style = MaterialTheme.typography.labelSmall,
                    fontWeight = FontWeight.Bold
                )
            }
        }
        StatusBadge(status = "Agent Connected", color = Success)
    }
}

@Composable
private fun RiskScoreSection(state: DeviceDetailsViewModel.RiskUiState) {
    GlassCard {
        Text(
            text = "Risk Score",
            color = SecondaryText,
            style = MaterialTheme.typography.labelSmall
        )
        
        when (val risk = state) {
            is DeviceDetailsViewModel.RiskUiState.Loading -> {
                CircularProgressIndicator(color = Primary, modifier = Modifier.size(24.dp))
            }
            is DeviceDetailsViewModel.RiskUiState.Success -> {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.Bottom,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(
                        text = risk.risk.current_score.toString(),
                        color = when (risk.risk.risk_level.uppercase()) {
                            "CRITICAL" -> Critical
                            "HIGH" -> Warning
                            else -> Success
                        },
                        style = MaterialTheme.typography.displayMedium,
                        fontWeight = FontWeight.Bold
                    )
                    Text(
                        text = risk.risk.risk_level,
                        color = when (risk.risk.risk_level.uppercase()) {
                            "CRITICAL" -> Critical
                            "HIGH" -> Warning
                            else -> Success
                        },
                        style = MaterialTheme.typography.titleLarge,
                        fontWeight = FontWeight.Bold,
                        modifier = Modifier.padding(bottom = 8.dp)
                    )
                }
                
                Spacer(modifier = Modifier.height(16.dp))
                
                // Risk Factors
                Text("Risk Factors", color = PrimaryText, fontWeight = FontWeight.Bold)
                risk.risk.reasons.forEach { reason ->
                    Text("+ $reason", color = SecondaryText, style = MaterialTheme.typography.bodySmall)
                }
                
                if (risk.risk.confidence != null) {
                    Text(
                        text = "Confidence: ${(risk.risk.confidence * 100).toInt()}%",
                        color = SecondaryText,
                        style = MaterialTheme.typography.labelSmall,
                        modifier = Modifier.padding(top = 8.dp)
                    )
                }
            }
            is DeviceDetailsViewModel.RiskUiState.Error -> {
                Text(text = risk.message, color = Critical)
            }
        }
    }
}

@Composable
private fun InfoSection(title: String, items: List<Pair<String, String>>) {
    Column {
        Text(
            text = title,
            color = Primary,
            style = MaterialTheme.typography.labelMedium,
            fontWeight = FontWeight.Bold,
            letterSpacing = 1.sp
        )
        Spacer(modifier = Modifier.height(12.dp))
        GlassCard {
            items.forEachIndexed { index, item ->
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 4.dp),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(text = item.first, color = SecondaryText, style = MaterialTheme.typography.bodyMedium)
                    Text(text = item.second, color = PrimaryText, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Medium)
                }
                if (index < items.size - 1) {
                    HorizontalDivider(color = GlassBorder, thickness = 0.5.dp)
                }
            }
        }
    }
}

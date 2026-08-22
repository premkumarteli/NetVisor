package com.netvisor.mobile.ui.vpn

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.VpnKey
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.netvisor.mobile.data.model.Alert
import com.netvisor.mobile.ui.components.*
import com.netvisor.mobile.ui.theme.*
import com.netvisor.mobile.viewmodel.VpnViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun VpnScreen(
    viewModel: VpnViewModel,
    onBack: () -> Unit
) {
    val uiState by viewModel.vpnAlerts.collectAsState()

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("VPN & Tunnel Detection", color = PrimaryText) },
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
        Column(
            modifier = Modifier
                .padding(innerPadding)
                .padding(horizontal = 24.dp)
                .fillMaxSize()
        ) {
            when (val state = uiState) {
                is VpnViewModel.VpnUiState.Loading -> {
                    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                        CircularProgressIndicator(color = Primary)
                    }
                }
                is VpnViewModel.VpnUiState.Success -> {
                    if (state.alerts.isEmpty()) {
                        GlassCard {
                            Text(
                                text = "No active VPN tunnels or proxy connections detected on monitored devices.",
                                color = SecondaryText
                            )
                        }
                    } else {
                        LazyColumn(
                            verticalArrangement = Arrangement.spacedBy(12.dp),
                            modifier = Modifier.fillMaxSize()
                        ) {
                            items(state.alerts) { alert ->
                                VpnItemCard(alert)
                            }
                            item {
                                Spacer(modifier = Modifier.height(80.dp))
                            }
                        }
                    }
                }
                is VpnViewModel.VpnUiState.Error -> {
                    GlassCard {
                        Text(text = state.message, color = Critical)
                    }
                }
            }
        }
    }
}

@Composable
private fun VpnItemCard(alert: Alert) {
    GlassCard {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.Top
        ) {
            Column(modifier = Modifier.weight(1f)) {
                StatusBadge(status = "TUNNEL DETECTED", color = Warning)
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = alert.message ?: "VPN / Proxy Traffic",
                    color = PrimaryText,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    text = "Endpoint IP: ",
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

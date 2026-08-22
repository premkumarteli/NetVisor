package com.netvisor.mobile.ui.dpi

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Radar
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.netvisor.mobile.data.model.WebActivityItem
import com.netvisor.mobile.ui.components.*
import com.netvisor.mobile.ui.theme.*
import com.netvisor.mobile.viewmodel.DpiViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DpiScreen(
    viewModel: DpiViewModel,
    onBack: () -> Unit
) {
    val statusState by viewModel.dpiStatus.collectAsState()
    val activityState by viewModel.webActivity.collectAsState()

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Deep Packet Inspection", color = PrimaryText) },
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
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            item {
                when (val st = statusState) {
                    is DpiViewModel.DpiUiState.Success -> {
                        GlassCard {
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column {
                                    Text("DPI ENGINE STATUS", color = SecondaryText, style = MaterialTheme.typography.labelSmall)
                                    Text("Real-Time Protocol Decoder", color = PrimaryText, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                                }
                                StatusBadge(status = "ACTIVE", color = Success)
                            }
                        }
                    }
                    else -> Unit
                }
            }

            item {
                Text(
                    text = "Live Inspectable Web Flows",
                    color = PrimaryText,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
            }

            when (val act = activityState) {
                is DpiViewModel.DpiUiState.Loading -> {
                    item {
                        Box(modifier = Modifier.fillMaxWidth().padding(32.dp), contentAlignment = Alignment.Center) {
                            CircularProgressIndicator(color = Primary)
                        }
                    }
                }
                is DpiViewModel.DpiUiState.Success -> {
                    if (act.data.isEmpty()) {
                        item {
                            GlassCard {
                                Text("No recent HTTP/TLS web flows intercepted.", color = SecondaryText)
                            }
                        }
                    } else {
                        items(act.data) { item ->
                            WebActivityCard(item)
                        }
                    }
                }
                is DpiViewModel.DpiUiState.Error -> {
                    item {
                        GlassCard {
                            Text(text = act.message, color = Critical)
                        }
                    }
                }
            }

            item {
                Spacer(modifier = Modifier.height(80.dp))
            }
        }
    }
}

@Composable
private fun WebActivityCard(item: WebActivityItem) {
    GlassCard {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = item.domain,
                    color = PrimaryText,
                    style = MaterialTheme.typography.bodyLarge,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    text = " • Risk: ",
                    color = SecondaryText,
                    style = MaterialTheme.typography.labelSmall
                )
            }
            StatusBadge(
                status = item.risk_level.uppercase(),
                color = when (item.risk_level.lowercase()) {
                    "high", "critical" -> Critical
                    "medium" -> Warning
                    else -> Success
                }
            )
        }
    }
}

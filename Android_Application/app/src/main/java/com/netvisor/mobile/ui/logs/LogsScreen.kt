package com.netvisor.mobile.ui.logs

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.netvisor.mobile.data.model.FlowLogItem
import com.netvisor.mobile.ui.components.*
import com.netvisor.mobile.ui.theme.*
import com.netvisor.mobile.viewmodel.LogsViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun LogsScreen(
    viewModel: LogsViewModel,
    onBack: () -> Unit
) {
    val uiState by viewModel.logs.collectAsState()
    val filterQuery by viewModel.filterQuery.collectAsState()

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("System & Flow Logs", color = PrimaryText) },
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
            GlassSearchBar(
                value = filterQuery,
                onValueChange = { viewModel.onFilterChange(it) },
                placeholder = "Filter by IP or protocol..."
            )

            Spacer(modifier = Modifier.height(16.dp))

            when (val state = uiState) {
                is LogsViewModel.LogsUiState.Loading -> {
                    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                        CircularProgressIndicator(color = Primary)
                    }
                }
                is LogsViewModel.LogsUiState.Success -> {
                    val filtered = state.logs.filter {
                        it.src_ip.contains(filterQuery, ignoreCase = true) ||
                        it.dst_ip.contains(filterQuery, ignoreCase = true) ||
                        it.protocol.contains(filterQuery, ignoreCase = true) ||
                        it.domain?.contains(filterQuery, ignoreCase = true) == true
                    }

                    if (filtered.isEmpty()) {
                        GlassCard {
                            Text("No flow log records matching query.", color = SecondaryText)
                        }
                    } else {
                        LazyColumn(
                            verticalArrangement = Arrangement.spacedBy(12.dp),
                            modifier = Modifier.fillMaxSize()
                        ) {
                            items(filtered) { log ->
                                FlowLogCard(log)
                            }
                            item {
                                Spacer(modifier = Modifier.height(80.dp))
                            }
                        }
                    }
                }
                is LogsViewModel.LogsUiState.Error -> {
                    GlassCard {
                        Text(text = state.message, color = Critical)
                    }
                }
            }
        }
    }
}

@Composable
private fun FlowLogCard(log: FlowLogItem) {
    GlassCard {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.Top
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = ": -> :",
                    color = PrimaryText,
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    text = " •  •  B",
                    color = SecondaryText,
                    style = MaterialTheme.typography.labelSmall
                )
            }
            StatusBadge(
                status = log.protocol,
                color = Primary
            )
        }
    }
}

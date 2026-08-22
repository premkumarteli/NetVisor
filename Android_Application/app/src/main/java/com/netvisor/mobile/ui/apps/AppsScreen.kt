package com.netvisor.mobile.ui.apps

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.netvisor.mobile.data.model.AppSummaryItem
import com.netvisor.mobile.ui.components.*
import com.netvisor.mobile.ui.theme.*
import com.netvisor.mobile.viewmodel.AppsViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AppsScreen(
    viewModel: AppsViewModel,
    onBack: () -> Unit
) {
    val uiState by viewModel.apps.collectAsState()
    val searchQuery by viewModel.searchQuery.collectAsState()

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Applications & Bandwidth", color = PrimaryText) },
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
                value = searchQuery,
                onValueChange = { viewModel.onSearchQueryChange(it) },
                placeholder = "Search applications..."
            )

            Spacer(modifier = Modifier.height(16.dp))

            when (val state = uiState) {
                is AppsViewModel.AppsUiState.Loading -> {
                    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                        CircularProgressIndicator(color = Primary)
                    }
                }
                is AppsViewModel.AppsUiState.Success -> {
                    val filtered = state.apps.filter {
                        it.application.contains(searchQuery, ignoreCase = true) ||
                        it.category?.contains(searchQuery, ignoreCase = true) == true
                    }

                    if (filtered.isEmpty()) {
                        GlassCard {
                            Text("No application telemetry captured yet.", color = SecondaryText)
                        }
                    } else {
                        LazyColumn(
                            verticalArrangement = Arrangement.spacedBy(12.dp),
                            modifier = Modifier.fillMaxSize()
                        ) {
                            items(filtered) { app ->
                                AppItemCard(app)
                            }
                            item {
                                Spacer(modifier = Modifier.height(80.dp))
                            }
                        }
                    }
                }
                is AppsViewModel.AppsUiState.Error -> {
                    GlassCard {
                        Text(text = state.message, color = Critical)
                    }
                }
            }
        }
    }
}

@Composable
private fun AppItemCard(app: AppSummaryItem) {
    GlassCard {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = app.application,
                    color = PrimaryText,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    text = " •  flows",
                    color = SecondaryText,
                    style = MaterialTheme.typography.bodySmall
                )
            }
            StatusBadge(
                status = formatBytes(app.bandwidth_bytes),
                color = Primary
            )
        }
    }
}

private fun formatBytes(bytes: Long): String {
    if (bytes <= 0) return "0 B"
    val kb = bytes / 1024.0
    val mb = kb / 1024.0
    val gb = mb / 1024.0
    return when {
        gb >= 1.0 -> String.format(java.util.Locale.US, "%.2f GB", gb)
        mb >= 1.0 -> String.format(java.util.Locale.US, "%.2f MB", mb)
        kb >= 1.0 -> String.format(java.util.Locale.US, "%.1f KB", kb)
        else -> " B"
    }
}

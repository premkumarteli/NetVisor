package com.netvisor.mobile.ui.agents

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Router
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.netvisor.mobile.data.model.AgentSummary
import com.netvisor.mobile.ui.components.*
import com.netvisor.mobile.ui.theme.*
import com.netvisor.mobile.viewmodel.AgentsViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AgentsScreen(
    viewModel: AgentsViewModel,
    onBack: () -> Unit
) {
    val uiState by viewModel.agents.collectAsState()

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Agents & Collectors", color = PrimaryText) },
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
                is AgentsViewModel.AgentsUiState.Loading -> {
                    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                        CircularProgressIndicator(color = Primary)
                    }
                }
                is AgentsViewModel.AgentsUiState.Success -> {
                    if (state.agents.isEmpty()) {
                        GlassCard {
                            Text("No telemetry collector agents currently enrolled.", color = SecondaryText)
                        }
                    } else {
                        LazyColumn(
                            verticalArrangement = Arrangement.spacedBy(12.dp),
                            modifier = Modifier.fillMaxSize()
                        ) {
                            items(state.agents) { agent ->
                                AgentItemCard(agent)
                            }
                            item {
                                Spacer(modifier = Modifier.height(80.dp))
                            }
                        }
                    }
                }
                is AgentsViewModel.AgentsUiState.Error -> {
                    GlassCard {
                        Text(text = state.message, color = Critical)
                    }
                }
            }
        }
    }
}

@Composable
private fun AgentItemCard(agent: AgentSummary) {
    GlassCard {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = agent.hostname,
                    color = PrimaryText,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    text = " • v • ",
                    color = SecondaryText,
                    style = MaterialTheme.typography.bodySmall
                )
            }
            StatusBadge(
                status = agent.status.uppercase(),
                color = if (agent.status.equals("online", ignoreCase = true)) Success else SecondaryText
            )
        }
    }
}

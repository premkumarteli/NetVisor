package com.netvisor.mobile.ui.settings

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.netvisor.mobile.ui.components.*
import com.netvisor.mobile.ui.theme.*
import com.netvisor.mobile.viewmodel.SettingsViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    viewModel: SettingsViewModel,
    onBack: () -> Unit
) {
    val user by viewModel.currentUser.collectAsState()
    val backendUrl by viewModel.backendUrl.collectAsState()
    val health by viewModel.health.collectAsState()
    val scanMsg by viewModel.scanMessage.collectAsState()

    var editingUrl by remember(backendUrl) { mutableStateOf(backendUrl) }
    var urlSavedMessage by remember { mutableStateOf<String?>(null) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Settings & Control", color = PrimaryText) },
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
            verticalArrangement = Arrangement.spacedBy(20.dp)
        ) {
            item {
                Text(
                    text = "OPERATOR PROFILE",
                    color = Primary,
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.Bold,
                    letterSpacing = 1.sp
                )
                Spacer(modifier = Modifier.height(8.dp))
                GlassCard {
                    Text("Username: ", color = PrimaryText, fontWeight = FontWeight.Bold)
                    Text("Role: ", color = SecondaryText, style = MaterialTheme.typography.bodySmall)
                    Text("Org: ", color = SecondaryText, style = MaterialTheme.typography.bodySmall)
                }
            }

            item {
                Text(
                    text = "CONTROL PLANE BACKEND",
                    color = Primary,
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.Bold,
                    letterSpacing = 1.sp
                )
                Spacer(modifier = Modifier.height(8.dp))
                GlassCard {
                    OutlinedTextField(
                        value = editingUrl,
                        onValueChange = { editingUrl = it },
                        label = { Text("API Base URL") },
                        modifier = Modifier.fillMaxWidth(),
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedTextColor = PrimaryText,
                            unfocusedTextColor = PrimaryText,
                            focusedBorderColor = Primary,
                            unfocusedBorderColor = Color.White.copy(alpha = 0.2f)
                        ),
                        singleLine = true
                    )
                    Spacer(modifier = Modifier.height(12.dp))
                    GlassButton(
                        text = "Save URL",
                        onClick = {
                            viewModel.onBackendUrlChange(editingUrl)
                            viewModel.saveBackendUrl()
                            urlSavedMessage = "Backend URL updated!"
                        },
                        modifier = Modifier.fillMaxWidth()
                    )
                    if (urlSavedMessage != null) {
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(text = urlSavedMessage!!, color = Success, style = MaterialTheme.typography.labelSmall)
                    }
                }
            }

            item {
                Text(
                    text = "SYSTEM HEALTH & ACTIONS",
                    color = Primary,
                    style = MaterialTheme.typography.labelMedium,
                    fontWeight = FontWeight.Bold,
                    letterSpacing = 1.sp
                )
                Spacer(modifier = Modifier.height(8.dp))
                GlassCard {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text("Core Services Status", color = PrimaryText)
                        StatusBadge(status = health?.status?.uppercase() ?: "OPERATIONAL", color = Success)
                    }
                    Spacer(modifier = Modifier.height(16.dp))
                    GlassButton(
                        text = "Trigger Security Scan",
                        onClick = { viewModel.triggerScan() },
                        modifier = Modifier.fillMaxWidth(),
                        containerColor = Primary.copy(alpha = 0.2f),
                        contentColor = Primary
                    )
                    if (scanMsg != null) {
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(text = scanMsg!!, color = Primary, style = MaterialTheme.typography.bodySmall)
                    }
                }
            }

            item {
                Spacer(modifier = Modifier.height(80.dp))
            }
        }
    }
}

package com.netvisor.mobile.ui.more

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.automirrored.filled.Logout
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.netvisor.mobile.ui.components.GlassCard
import com.netvisor.mobile.ui.theme.*

@Composable
fun MoreScreen(
    onNavigate: (String) -> Unit,
    onLogout: () -> Unit
) {
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
            Section(
                title = "SECURITY & ANALYSIS",
                items = listOf(
                    MenuItem("Threats & Alerts", Icons.Default.Security, "threats"),
                    MenuItem("Deep Packet Inspection", Icons.Default.Radar, "dpi"),
                    MenuItem("Activity & Flow Logs", Icons.Default.History, "logs")
                ),
                onItemClick = onNavigate
            )
        }

        item {
            Section(
                title = "NETWORK & TRAFFIC",
                items = listOf(
                    MenuItem("Devices Inventory", Icons.Default.Devices, "network"),
                    MenuItem("Applications & Bandwidth", Icons.Default.Apps, "apps"),
                    MenuItem("VPN & Tunnel Detection", Icons.Default.VpnLock, "vpn")
                ),
                onItemClick = onNavigate
            )
        }

        item {
            Section(
                title = "SYSTEM & CONTROL",
                items = listOf(
                    MenuItem("Agents & Collectors", Icons.Default.Router, "agents"),
                    MenuItem("Settings & Server", Icons.Default.Settings, "settings")
                ),
                onItemClick = onNavigate
            )
        }

        item {
            GlassCard(modifier = Modifier.clickable { onLogout() }) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.AutoMirrored.Filled.Logout, contentDescription = null, tint = Critical)
                    Spacer(modifier = Modifier.width(16.dp))
                    Text("Logout Session", color = Critical, fontWeight = FontWeight.Bold)
                }
            }
        }
        
        item {
            Spacer(modifier = Modifier.height(100.dp))
        }
    }
}

@Composable
private fun Header() {
    Text(
        text = "More",
        color = PrimaryText,
        style = MaterialTheme.typography.headlineLarge,
        fontWeight = FontWeight.Bold,
        letterSpacing = 2.sp,
        modifier = Modifier.padding(vertical = 16.dp)
    )
}

@Composable
private fun Section(
    title: String,
    items: List<MenuItem>,
    onItemClick: (String) -> Unit
) {
    Column {
        Text(
            text = title,
            color = Primary,
            style = MaterialTheme.typography.labelMedium,
            fontWeight = FontWeight.Bold,
            letterSpacing = 1.sp,
            modifier = Modifier.padding(bottom = 8.dp)
        )
        GlassCard {
            items.forEachIndexed { index, item ->
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 12.dp)
                        .clickable { onItemClick(item.route) },
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(item.icon, contentDescription = null, tint = Primary, modifier = Modifier.size(20.dp))
                    Spacer(modifier = Modifier.width(16.dp))
                    Text(text = item.label, color = PrimaryText, style = MaterialTheme.typography.bodyLarge)
                    Spacer(modifier = Modifier.weight(1f))
                    Icon(Icons.Default.ChevronRight, contentDescription = null, tint = SecondaryText)
                }
                if (index < items.size - 1) {
                    HorizontalDivider(color = GlassBorder, thickness = 0.5.dp)
                }
            }
        }
    }
}

data class MenuItem(val label: String, val icon: ImageVector, val route: String)

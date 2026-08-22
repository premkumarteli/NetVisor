package com.netvisor.mobile.ui.network

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.netvisor.mobile.data.model.Device
import com.netvisor.mobile.ui.components.*
import com.netvisor.mobile.ui.theme.*
import com.netvisor.mobile.viewmodel.NetworkViewModel

@Composable
fun NetworkScreen(
    viewModel: NetworkViewModel,
    onDeviceClick: (Device) -> Unit
) {
    val uiState by viewModel.devices.collectAsState()
    val searchQuery by viewModel.searchQuery.collectAsState()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 24.dp)
    ) {
        Header(uiState)
        
        Spacer(modifier = Modifier.height(16.dp))
        
        GlassSearchBar(
            value = searchQuery,
            onValueChange = { viewModel.onSearchQueryChange(it) },
            placeholder = "Search devices..."
        )
        
        Spacer(modifier = Modifier.height(16.dp))
        
        FilterChips()
        
        Spacer(modifier = Modifier.height(16.dp))

        when (val state = uiState) {
            is NetworkViewModel.NetworkUiState.Loading -> {
                Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    CircularProgressIndicator(color = Primary)
                }
            }
            is NetworkViewModel.NetworkUiState.Success -> {
                val filteredDevices = state.devices.filter {
                    it.ip.contains(searchQuery, ignoreCase = true) ||
                    it.hostname?.contains(searchQuery, ignoreCase = true) == true
                }
                
                LazyColumn(
                    modifier = Modifier.fillMaxSize(),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    items(filteredDevices) { device ->
                        DeviceItem(device, onClick = { onDeviceClick(device) })
                    }
                    item {
                        Spacer(modifier = Modifier.height(100.dp))
                    }
                }
            }
            is NetworkViewModel.NetworkUiState.Error -> {
                Text(text = state.message, color = Critical)
            }
        }
    }
}

@Composable
private fun Header(state: NetworkViewModel.NetworkUiState) {
    val count = (state as? NetworkViewModel.NetworkUiState.Success)?.devices?.size ?: 0
    Column(modifier = Modifier.padding(vertical = 16.dp)) {
        Text(
            text = "Network",
            color = PrimaryText,
            style = MaterialTheme.typography.headlineLarge,
            fontWeight = FontWeight.Bold,
            letterSpacing = 2.sp
        )
        Text(
            text = "$count Devices",
            color = SecondaryText,
            style = MaterialTheme.typography.labelMedium
        )
    }
}

@Composable
private fun FilterChips() {
    val filters = listOf("All", "Online", "Risk: High", "Servers")
    var selectedFilter by remember { mutableStateOf("All") }
    
    LazyRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        items(filters) { filter ->
            GlassChip(
                text = filter,
                selected = filter == selectedFilter,
                onClick = { selectedFilter = filter }
            )
        }
    }
}

@Composable
private fun DeviceItem(device: Device, onClick: () -> Unit) {
    GlassSurface(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick),
        cornerRadius = 20.dp
    ) {
        Row(
            modifier = Modifier
                .padding(16.dp)
                .fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    modifier = Modifier
                        .size(8.dp)
                        .background(
                            if (device.status == "online") Success else SecondaryText,
                            shape = MaterialTheme.shapes.small
                        )
                )
                Spacer(modifier = Modifier.width(16.dp))
                Column {
                    Text(
                        text = device.ip,
                        color = PrimaryText,
                        style = MaterialTheme.typography.bodyLarge,
                        fontWeight = FontWeight.Bold
                    )
                    Text(
                        text = "${device.hostname ?: "Unknown Host"} • ${device.os ?: "Unknown OS"}",
                        color = SecondaryText,
                        style = MaterialTheme.typography.labelSmall
                    )
                }
            }
            
            Row(verticalAlignment = Alignment.CenterVertically) {
                StatusBadge(
                    status = "Risk: ${device.risk_score ?: 0}",
                    color = when {
                        (device.risk_score ?: 0) > 70 -> Critical
                        (device.risk_score ?: 0) > 30 -> Warning
                        else -> Success
                    }
                )
                Spacer(modifier = Modifier.width(8.dp))
                Icon(
                    imageVector = Icons.Default.ChevronRight,
                    contentDescription = null,
                    tint = SecondaryText
                )
            }
        }
    }
}

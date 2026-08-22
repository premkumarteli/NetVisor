package com.netvisor.mobile.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.netvisor.mobile.data.model.ActivityEvent
import com.netvisor.mobile.data.model.DashboardOverview
import com.netvisor.mobile.data.repository.AlertRepository
import com.netvisor.mobile.data.repository.DashboardRepository
import com.netvisor.mobile.data.websocket.NetVisorWebSocket
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

class HomeViewModel(
    private val dashboardRepository: DashboardRepository,
    private val alertRepository: AlertRepository,
    private val webSocket: NetVisorWebSocket? = null
) : ViewModel() {

    private val _overview = MutableStateFlow<DashboardUiState<DashboardOverview>>(DashboardUiState.Loading)
    val overview: StateFlow<DashboardUiState<DashboardOverview>> = _overview.asStateFlow()

    private val _recentActivity = MutableStateFlow<DashboardUiState<List<ActivityEvent>>>(DashboardUiState.Loading)
    val recentActivity: StateFlow<DashboardUiState<List<ActivityEvent>>> = _recentActivity.asStateFlow()

    private val _trafficTotal = MutableStateFlow("--")
    val trafficTotal: StateFlow<String> = _trafficTotal.asStateFlow()

    private val _threatCount = MutableStateFlow(0)
    val threatCount: StateFlow<Int> = _threatCount.asStateFlow()

    private val _criticalThreatCount = MutableStateFlow(0)
    val criticalThreatCount: StateFlow<Int> = _criticalThreatCount.asStateFlow()

    init {
        refresh()
        observeWebSocketEvents()
    }

    private fun observeWebSocketEvents() {
        if (webSocket == null) return
        viewModelScope.launch {
            webSocket.events.collect { _ ->
                refresh()
            }
        }
    }

    fun refresh() {
        viewModelScope.launch {
            _overview.value = DashboardUiState.Loading
            dashboardRepository.getOverview().collect { result ->
                _overview.value = if (result.isSuccess) {
                    DashboardUiState.Success(result.getOrThrow())
                } else {
                    DashboardUiState.Error(result.exceptionOrNull()?.message ?: "Failed to connect to server")
                }
            }
        }
        viewModelScope.launch {
            _recentActivity.value = DashboardUiState.Loading
            dashboardRepository.getRecentActivity(limit = 20).collect { result ->
                _recentActivity.value = if (result.isSuccess) {
                    DashboardUiState.Success(result.getOrThrow())
                } else {
                    DashboardUiState.Error(result.exceptionOrNull()?.message ?: "Failed to load activity")
                }
            }
        }
        viewModelScope.launch {
            dashboardRepository.getTrafficHistory(hours = 24).collect { result ->
                result.onSuccess { history ->
                    val totalBytes = (history.inbound.sum() + history.outbound.sum())
                    _trafficTotal.value = formatBytes(totalBytes)
                }
            }
        }
        viewModelScope.launch {
            alertRepository.getAlerts(limit = 50, resolved = false).collect { result ->
                result.onSuccess { alerts ->
                    _threatCount.value = alerts.size
                    _criticalThreatCount.value = alerts.count { it.severity.equals("CRITICAL", ignoreCase = true) || it.severity.equals("HIGH", ignoreCase = true) }
                }
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
            else -> "$bytes B"
        }
    }

    sealed interface DashboardUiState<out T> {
        object Loading : DashboardUiState<Nothing>
        data class Success<T>(val data: T) : DashboardUiState<T>
        data class Error(val message: String) : DashboardUiState<Nothing>
    }
}

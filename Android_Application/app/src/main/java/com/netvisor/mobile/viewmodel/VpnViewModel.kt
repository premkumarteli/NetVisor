package com.netvisor.mobile.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.netvisor.mobile.data.model.Alert
import com.netvisor.mobile.data.repository.SystemRepository
import com.netvisor.mobile.data.websocket.NetVisorWebSocket
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

class VpnViewModel(
    private val repository: SystemRepository,
    private val webSocket: NetVisorWebSocket? = null
) : ViewModel() {

    private val _vpnAlerts = MutableStateFlow<VpnUiState>(VpnUiState.Loading)
    val vpnAlerts: StateFlow<VpnUiState> = _vpnAlerts.asStateFlow()

    init {
        refresh()
        observeWebSocket()
    }

    private fun observeWebSocket() {
        if (webSocket == null) return
        viewModelScope.launch {
            webSocket.events.collect { _ -> refresh() }
        }
    }

    fun refresh() {
        viewModelScope.launch {
            _vpnAlerts.value = VpnUiState.Loading
            repository.getVpnAlerts().collect { result ->
                _vpnAlerts.value = if (result.isSuccess) {
                    VpnUiState.Success(result.getOrThrow())
                } else {
                    VpnUiState.Error(result.exceptionOrNull()?.message ?: "Failed to load VPN events")
                }
            }
        }
    }

    sealed interface VpnUiState {
        object Loading : VpnUiState
        data class Success(val alerts: List<Alert>) : VpnUiState
        data class Error(val message: String) : VpnUiState
    }
}

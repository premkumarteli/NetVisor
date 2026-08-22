package com.netvisor.mobile.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.netvisor.mobile.data.model.Alert
import com.netvisor.mobile.data.repository.AlertRepository
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

import com.netvisor.mobile.data.websocket.NetVisorWebSocket

class ThreatsViewModel(
    private val repository: AlertRepository,
    private val webSocket: NetVisorWebSocket? = null
) : ViewModel() {

    private val _alerts = MutableStateFlow<ThreatsUiState>(ThreatsUiState.Loading)
    val alerts: StateFlow<ThreatsUiState> = _alerts.asStateFlow()

    private val _selectedSeverity = MutableStateFlow<String?>(null)
    val selectedSeverity: StateFlow<String?> = _selectedSeverity.asStateFlow()

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
            _alerts.value = ThreatsUiState.Loading
            repository.getAlerts(severity = _selectedSeverity.value).collect { result ->
                _alerts.value = result.fold(
                    onSuccess = { ThreatsUiState.Success(it) },
                    onFailure = { ThreatsUiState.Error(it.message ?: "Unknown error") }
                )
            }
        }
    }

    fun onSeverityChange(severity: String?) {
        _selectedSeverity.value = severity
        refresh()
    }

    sealed interface ThreatsUiState {
        object Loading : ThreatsUiState
        data class Success(val alerts: List<Alert>) : ThreatsUiState
        data class Error(val message: String) : ThreatsUiState
    }
}

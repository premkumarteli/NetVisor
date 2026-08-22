package com.netvisor.mobile.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.netvisor.mobile.data.model.FlowLogItem
import com.netvisor.mobile.data.repository.SystemRepository
import com.netvisor.mobile.data.websocket.NetVisorWebSocket
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

class LogsViewModel(
    private val repository: SystemRepository,
    private val webSocket: NetVisorWebSocket? = null
) : ViewModel() {

    private val _logs = MutableStateFlow<LogsUiState>(LogsUiState.Loading)
    val logs: StateFlow<LogsUiState> = _logs.asStateFlow()

    private val _filterQuery = MutableStateFlow("")
    val filterQuery: StateFlow<String> = _filterQuery.asStateFlow()

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
            _logs.value = LogsUiState.Loading
            repository.getFlowLogs(limit = 60).collect { res ->
                _logs.value = if (res.isSuccess) LogsUiState.Success(res.getOrThrow())
                else LogsUiState.Error(res.exceptionOrNull()?.message ?: "Failed to load flow logs")
            }
        }
    }

    fun onFilterChange(q: String) {
        _filterQuery.value = q
    }

    sealed interface LogsUiState {
        object Loading : LogsUiState
        data class Success(val logs: List<FlowLogItem>) : LogsUiState
        data class Error(val message: String) : LogsUiState
    }
}

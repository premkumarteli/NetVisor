package com.netvisor.mobile.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.netvisor.mobile.data.model.AgentSummary
import com.netvisor.mobile.data.repository.SystemRepository
import com.netvisor.mobile.data.websocket.NetVisorWebSocket
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

class AgentsViewModel(
    private val repository: SystemRepository,
    private val webSocket: NetVisorWebSocket? = null
) : ViewModel() {

    private val _agents = MutableStateFlow<AgentsUiState>(AgentsUiState.Loading)
    val agents: StateFlow<AgentsUiState> = _agents.asStateFlow()

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
            _agents.value = AgentsUiState.Loading
            repository.getAgents().collect { res ->
                _agents.value = if (res.isSuccess) AgentsUiState.Success(res.getOrThrow())
                else AgentsUiState.Error(res.exceptionOrNull()?.message ?: "Failed to load agents")
            }
        }
    }

    sealed interface AgentsUiState {
        object Loading : AgentsUiState
        data class Success(val agents: List<AgentSummary>) : AgentsUiState
        data class Error(val message: String) : AgentsUiState
    }
}

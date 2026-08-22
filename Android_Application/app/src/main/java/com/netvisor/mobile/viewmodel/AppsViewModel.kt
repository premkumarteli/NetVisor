package com.netvisor.mobile.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.netvisor.mobile.data.model.AppSummaryItem
import com.netvisor.mobile.data.repository.SystemRepository
import com.netvisor.mobile.data.websocket.NetVisorWebSocket
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

class AppsViewModel(
    private val repository: SystemRepository,
    private val webSocket: NetVisorWebSocket? = null
) : ViewModel() {

    private val _apps = MutableStateFlow<AppsUiState>(AppsUiState.Loading)
    val apps: StateFlow<AppsUiState> = _apps.asStateFlow()

    private val _searchQuery = MutableStateFlow("")
    val searchQuery: StateFlow<String> = _searchQuery.asStateFlow()

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
            _apps.value = AppsUiState.Loading
            repository.getAppsSummary().collect { result ->
                _apps.value = if (result.isSuccess) {
                    AppsUiState.Success(result.getOrThrow())
                } else {
                    AppsUiState.Error(result.exceptionOrNull()?.message ?: "Failed to load apps")
                }
            }
        }
    }

    fun onSearchQueryChange(q: String) {
        _searchQuery.value = q
    }

    sealed interface AppsUiState {
        object Loading : AppsUiState
        data class Success(val apps: List<AppSummaryItem>) : AppsUiState
        data class Error(val message: String) : AppsUiState
    }
}

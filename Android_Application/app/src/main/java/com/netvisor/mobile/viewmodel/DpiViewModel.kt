package com.netvisor.mobile.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.netvisor.mobile.data.model.DpiStatus
import com.netvisor.mobile.data.model.WebActivityItem
import com.netvisor.mobile.data.repository.SystemRepository
import com.netvisor.mobile.data.websocket.NetVisorWebSocket
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

class DpiViewModel(
    private val repository: SystemRepository,
    private val webSocket: NetVisorWebSocket? = null
) : ViewModel() {

    private val _dpiStatus = MutableStateFlow<DpiUiState<DpiStatus>>(DpiUiState.Loading)
    val dpiStatus: StateFlow<DpiUiState<DpiStatus>> = _dpiStatus.asStateFlow()

    private val _webActivity = MutableStateFlow<DpiUiState<List<WebActivityItem>>>(DpiUiState.Loading)
    val webActivity: StateFlow<DpiUiState<List<WebActivityItem>>> = _webActivity.asStateFlow()

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
            _dpiStatus.value = DpiUiState.Loading
            repository.getDpiStatus().collect { res ->
                _dpiStatus.value = if (res.isSuccess) DpiUiState.Success(res.getOrThrow())
                else DpiUiState.Error(res.exceptionOrNull()?.message ?: "Failed to load DPI status")
            }
        }
        viewModelScope.launch {
            _webActivity.value = DpiUiState.Loading
            repository.getWebActivity(limit = 40).collect { res ->
                _webActivity.value = if (res.isSuccess) DpiUiState.Success(res.getOrThrow())
                else DpiUiState.Error(res.exceptionOrNull()?.message ?: "Failed to load web activity")
            }
        }
    }

    sealed interface DpiUiState<out T> {
        object Loading : DpiUiState<Nothing>
        data class Success<T>(val data: T) : DpiUiState<T>
        data class Error(val message: String) : DpiUiState<Nothing>
    }
}

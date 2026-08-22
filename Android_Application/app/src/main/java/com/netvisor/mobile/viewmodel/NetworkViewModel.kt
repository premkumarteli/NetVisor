package com.netvisor.mobile.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.netvisor.mobile.data.model.Device
import com.netvisor.mobile.data.repository.DeviceRepository
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

import com.netvisor.mobile.data.websocket.NetVisorWebSocket

class NetworkViewModel(
    private val repository: DeviceRepository,
    private val webSocket: NetVisorWebSocket? = null
) : ViewModel() {

    private val _devices = MutableStateFlow<NetworkUiState>(NetworkUiState.Loading)
    val devices: StateFlow<NetworkUiState> = _devices.asStateFlow()

    private val _searchQuery = MutableStateFlow("")
    val searchQuery: StateFlow<String> = _searchQuery.asStateFlow()

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
            _devices.value = NetworkUiState.Loading
            repository.getDevices().collect { result ->
                _devices.value = result.fold(
                    onSuccess = { NetworkUiState.Success(it) },
                    onFailure = { NetworkUiState.Error(it.message ?: "Unknown error") }
                )
            }
        }
    }

    fun onSearchQueryChange(query: String) {
        _searchQuery.value = query
    }

    sealed interface NetworkUiState {
        object Loading : NetworkUiState
        data class Success(val devices: List<Device>) : NetworkUiState
        data class Error(val message: String) : NetworkUiState
    }
}

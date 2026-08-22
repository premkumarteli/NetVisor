package com.netvisor.mobile.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.netvisor.mobile.data.model.DeviceRisk
import com.netvisor.mobile.data.repository.DeviceRepository
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

class DeviceDetailsViewModel(private val repository: DeviceRepository) : ViewModel() {

    private val _risk = MutableStateFlow<RiskUiState>(RiskUiState.Loading)
    val risk: StateFlow<RiskUiState> = _risk.asStateFlow()

    fun loadRisk(deviceId: String) {
        viewModelScope.launch {
            _risk.value = RiskUiState.Loading
            repository.getDeviceRisk(deviceId).collect { result ->
                _risk.value = result.fold(
                    onSuccess = { RiskUiState.Success(it) },
                    onFailure = { RiskUiState.Error(it.message ?: "Unknown error") }
                )
            }
        }
    }

    sealed interface RiskUiState {
        object Loading : RiskUiState
        data class Success(val risk: DeviceRisk) : RiskUiState
        data class Error(val message: String) : RiskUiState
    }
}

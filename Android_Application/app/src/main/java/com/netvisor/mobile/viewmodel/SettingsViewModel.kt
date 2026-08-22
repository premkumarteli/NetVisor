package com.netvisor.mobile.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.netvisor.mobile.data.model.SystemHealth
import com.netvisor.mobile.data.model.UserProfile
import com.netvisor.mobile.data.repository.AuthRepository
import com.netvisor.mobile.data.repository.SettingsRepository
import com.netvisor.mobile.data.repository.SystemRepository
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

class SettingsViewModel(
    private val settingsRepository: SettingsRepository,
    private val authRepository: AuthRepository,
    private val systemRepository: SystemRepository
) : ViewModel() {

    val currentUser: StateFlow<UserProfile?> = authRepository.currentUser

    private val _backendUrl = MutableStateFlow("")
    val backendUrl: StateFlow<String> = _backendUrl.asStateFlow()

    private val _health = MutableStateFlow<SystemHealth?>(null)
    val health: StateFlow<SystemHealth?> = _health.asStateFlow()

    private val _scanMessage = MutableStateFlow<String?>(null)
    val scanMessage: StateFlow<String?> = _scanMessage.asStateFlow()

    init {
        viewModelScope.launch {
            settingsRepository.backendUrl.collect {
                _backendUrl.value = it
            }
        }
        loadHealth()
    }

    fun onBackendUrlChange(url: String) {
        _backendUrl.value = url
    }

    fun saveBackendUrl() {
        viewModelScope.launch {
            settingsRepository.setBackendUrl(_backendUrl.value)
        }
    }

    fun loadHealth() {
        viewModelScope.launch {
            systemRepository.getHealth().collect { res ->
                if (res.isSuccess) _health.value = res.getOrThrow()
            }
        }
    }

    fun triggerScan() {
        viewModelScope.launch {
            _scanMessage.value = "Initiating scan..."
            val res = systemRepository.triggerScan()
            if (res.isSuccess) {
                _scanMessage.value = "Security scan successfully triggered!"
            } else {
                _scanMessage.value = "Scan trigger error: "
            }
        }
    }

    fun clearScanMessage() {
        _scanMessage.value = null
    }
}

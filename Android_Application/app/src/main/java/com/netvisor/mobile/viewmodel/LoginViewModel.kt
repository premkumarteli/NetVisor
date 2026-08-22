package com.netvisor.mobile.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.netvisor.mobile.data.repository.AuthRepository
import com.netvisor.mobile.data.repository.SettingsRepository
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

class LoginViewModel(
    private val authRepository: AuthRepository,
    private val settingsRepository: SettingsRepository
) : ViewModel() {

    private val _uiState = MutableStateFlow<LoginUiState>(LoginUiState.Idle)
    val uiState: StateFlow<LoginUiState> = _uiState.asStateFlow()

    private val _backendUrl = MutableStateFlow("")
    val backendUrl: StateFlow<String> = _backendUrl.asStateFlow()

    init {
        viewModelScope.launch {
            settingsRepository.backendUrl.collect {
                _backendUrl.value = it
            }
        }
    }

    fun onBackendUrlChange(url: String) {
        _backendUrl.value = url
    }

    fun login(username: String, password: String) {
        viewModelScope.launch {
            _uiState.value = LoginUiState.Loading
            
            // Update backend URL first
            settingsRepository.setBackendUrl(_backendUrl.value)
            
            val result = authRepository.login(username, password)
            if (result.isSuccess) {
                _uiState.value = LoginUiState.Success
            } else {
                _uiState.value = LoginUiState.Error(result.exceptionOrNull()?.message ?: "Unknown error")
            }
        }
    }

    sealed interface LoginUiState {
        object Idle : LoginUiState
        object Loading : LoginUiState
        object Success : LoginUiState
        data class Error(val message: String) : LoginUiState
    }
}

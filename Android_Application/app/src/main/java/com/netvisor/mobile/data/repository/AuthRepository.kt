package com.netvisor.mobile.data.repository

import com.netvisor.mobile.data.api.NetVisorApi
import com.netvisor.mobile.data.model.UserProfile
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

class AuthRepository(
    private val api: NetVisorApi,
    private val settingsRepository: SettingsRepository
) {
    private val _currentUser = MutableStateFlow<UserProfile?>(null)
    val currentUser: StateFlow<UserProfile?> = _currentUser.asStateFlow()

    suspend fun login(username: String, password: String): Result<UserProfile> {
        return try {
            val response = api.login(username, password)
            if (response.isSuccessful) {
                val profile = response.body()
                if (profile != null) {
                    _currentUser.value = profile
                    Result.success(profile)
                } else {
                    Result.failure(Exception("Login successful but response body is empty"))
                }
            } else {
                Result.failure(Exception("Login failed: ${response.code()} ${response.message()}"))
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    suspend fun logout() {
        try {
            api.logout()
        } catch (e: Exception) {
            // Log or handle error, but still clear local state
        } finally {
            _currentUser.value = null
            settingsRepository.setSessionCookie(null)
        }
    }

    suspend fun checkAuth(): Boolean {
        return try {
            val response = api.getMe()
            if (response.isSuccessful && response.body() != null) {
                _currentUser.value = response.body()
                true
            } else {
                _currentUser.value = null
                false
            }
        } catch (e: Exception) {
            _currentUser.value = null
            false
        }
    }
}

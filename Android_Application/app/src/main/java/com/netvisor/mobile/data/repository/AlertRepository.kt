package com.netvisor.mobile.data.repository

import com.netvisor.mobile.data.api.NetVisorApi
import com.netvisor.mobile.data.model.Alert
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow

class AlertRepository(private val api: NetVisorApi) {

    fun getAlerts(
        severity: String? = null,
        resolved: Boolean? = null,
        limit: Int = 50
    ): Flow<Result<List<Alert>>> = flow {
        try {
            val response = api.getAlerts(limit, severity, resolved)
            if (response.isSuccessful) {
                emit(Result.success(response.body() ?: emptyList()))
            } else {
                emit(Result.failure(Exception("Failed to load alerts: ${response.code()}")))
            }
        } catch (e: Exception) {
            emit(Result.failure(e))
        }
    }
}

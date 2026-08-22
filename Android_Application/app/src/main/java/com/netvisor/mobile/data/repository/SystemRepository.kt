package com.netvisor.mobile.data.repository

import com.netvisor.mobile.data.api.NetVisorApi
import com.netvisor.mobile.data.model.*
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow

class SystemRepository(private val api: NetVisorApi) {

    fun getAgents(): Flow<Result<List<AgentSummary>>> = flow {
        try {
            val res = api.getAgents()
            if (res.isSuccessful) emit(Result.success(res.body() ?: emptyList()))
            else emit(Result.failure(Exception("Failed to load agents: ")))
        } catch (e: Exception) {
            emit(Result.failure(e))
        }
    }

    fun getHealth(): Flow<Result<SystemHealth>> = flow {
        try {
            val res = api.getHealth()
            if (res.isSuccessful) emit(Result.success(res.body() ?: SystemHealth()))
            else emit(Result.failure(Exception("Health check error: ")))
        } catch (e: Exception) {
            emit(Result.failure(e))
        }
    }

    fun getDpiStatus(): Flow<Result<DpiStatus>> = flow {
        try {
            val res = api.getDpiStatus()
            if (res.isSuccessful) emit(Result.success(res.body() ?: DpiStatus()))
            else emit(Result.failure(Exception("DPI status error: ")))
        } catch (e: Exception) {
            emit(Result.failure(e))
        }
    }

    fun getWebActivity(limit: Int = 30): Flow<Result<List<WebActivityItem>>> = flow {
        try {
            val res = api.getWebActivity(limit)
            if (res.isSuccessful) emit(Result.success(res.body() ?: emptyList()))
            else emit(Result.failure(Exception("Web activity error: ")))
        } catch (e: Exception) {
            emit(Result.failure(e))
        }
    }

    fun getAppsSummary(): Flow<Result<List<AppSummaryItem>>> = flow {
        try {
            val res = api.getAppsSummary()
            if (res.isSuccessful) emit(Result.success(res.body() ?: emptyList()))
            else emit(Result.failure(Exception("Apps summary error: ")))
        } catch (e: Exception) {
            emit(Result.failure(e))
        }
    }

    fun getFlowLogs(limit: Int = 50): Flow<Result<List<FlowLogItem>>> = flow {
        try {
            val res = api.getFlowLogs(limit)
            if (res.isSuccessful) emit(Result.success(res.body() ?: emptyList()))
            else emit(Result.failure(Exception("Flow logs error: ")))
        } catch (e: Exception) {
            emit(Result.failure(e))
        }
    }

    fun getVpnAlerts(): Flow<Result<List<Alert>>> = flow {
        try {
            val res = api.getAlerts(limit = 100)
            if (res.isSuccessful) {
                val allAlerts = res.body() ?: emptyList()
                val vpnAlerts = allAlerts.filter { alert ->
                    alert.message?.contains("VPN", ignoreCase = true) == true ||
                    alert.message?.contains("WireGuard", ignoreCase = true) == true ||
                    alert.message?.contains("Tunnel", ignoreCase = true) == true ||
                    alert.message?.contains("Proxy", ignoreCase = true) == true
                }
                emit(Result.success(vpnAlerts))
            } else {
                emit(Result.failure(Exception("VPN alerts error: ")))
            }
        } catch (e: Exception) {
            emit(Result.failure(e))
        }
    }

    suspend fun triggerScan(): Result<Unit> {
        return try {
            val res = api.triggerScan()
            if (res.isSuccessful) Result.success(Unit)
            else Result.failure(Exception("Scan failed: "))
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}

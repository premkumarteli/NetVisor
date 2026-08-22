package com.netvisor.mobile.data.repository

import com.netvisor.mobile.data.api.NetVisorApi
import com.netvisor.mobile.data.model.*
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow

class DashboardRepository(private val api: NetVisorApi) {

    fun getOverview(): Flow<Result<DashboardOverview>> = flow {
        try {
            val response = api.getOverview()
            if (response.isSuccessful) {
                emit(Result.success(response.body()!!))
            } else {
                emit(Result.failure(Exception("Failed to load overview: ${response.code()}")))
            }
        } catch (e: Exception) {
            emit(Result.failure(e))
        }
    }

    fun getRecentActivity(limit: Int = 10): Flow<Result<List<ActivityEvent>>> = flow {
        try {
            val response = api.getActivity(limit)
            if (response.isSuccessful) {
                emit(Result.success(response.body() ?: emptyList()))
            } else {
                emit(Result.failure(Exception("Failed to load activity: ${response.code()}")))
            }
        } catch (e: Exception) {
            emit(Result.failure(e))
        }
    }

    fun getTrafficHistory(hours: Int = 24): Flow<Result<TrafficHistory>> = flow {
        try {
            val response = api.getTrafficHistory(hours)
            if (response.isSuccessful) {
                emit(Result.success(response.body()!!))
            } else {
                emit(Result.failure(Exception("Failed to load traffic history: ${response.code()}")))
            }
        } catch (e: Exception) {
            emit(Result.failure(e))
        }
    }
}

package com.netvisor.mobile.data.repository

import com.netvisor.mobile.data.api.NetVisorApi
import com.netvisor.mobile.data.model.Device
import com.netvisor.mobile.data.model.DeviceRisk
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow

class DeviceRepository(private val api: NetVisorApi) {

    fun getDevices(includeObserved: Boolean = false): Flow<Result<List<Device>>> = flow {
        try {
            val response = api.getDevices(includeObserved)
            if (response.isSuccessful) {
                emit(Result.success(response.body() ?: emptyList()))
            } else {
                emit(Result.failure(Exception("Failed to load devices: ${response.code()}")))
            }
        } catch (e: Exception) {
            emit(Result.failure(e))
        }
    }

    fun getDeviceRisk(deviceId: String): Flow<Result<DeviceRisk>> = flow {
        try {
            val response = api.getDeviceRisk(deviceId)
            if (response.isSuccessful) {
                emit(Result.success(response.body()!!))
            } else {
                emit(Result.failure(Exception("Failed to load device risk: ${response.code()}")))
            }
        } catch (e: Exception) {
            emit(Result.failure(e))
        }
    }
}

package com.netvisor.mobile

import android.content.Context
import com.netvisor.mobile.data.api.NetVisorApiFactory
import com.netvisor.mobile.data.repository.*
import com.netvisor.mobile.data.websocket.NetVisorWebSocket
import com.netvisor.mobile.viewmodel.*
import okhttp3.OkHttpClient
import okhttp3.logging.HttpLoggingInterceptor

class DependencyContainer(context: Context) {
    
    val settingsRepository = SettingsRepository(context)
    
    private val apiFactory = NetVisorApiFactory(settingsRepository)
    val api = apiFactory.create()
    
    val authRepository = AuthRepository(api, settingsRepository)
    val dashboardRepository = DashboardRepository(api)
    val deviceRepository = DeviceRepository(api)
    val alertRepository = AlertRepository(api)
    val systemRepository = SystemRepository(api)
    
    private val logging = HttpLoggingInterceptor().apply {
        level = HttpLoggingInterceptor.Level.BODY
    }
    private val okHttpClient = OkHttpClient.Builder()
        .addInterceptor(logging)
        .build()
        
    val webSocket = NetVisorWebSocket(settingsRepository, okHttpClient)
    
    // ViewModels
    fun createLoginViewModel() = LoginViewModel(authRepository, settingsRepository)
    fun createHomeViewModel() = HomeViewModel(dashboardRepository, alertRepository, webSocket)
    fun createNetworkViewModel() = NetworkViewModel(deviceRepository, webSocket)
    fun createDeviceDetailsViewModel() = DeviceDetailsViewModel(deviceRepository)
    fun createThreatsViewModel() = ThreatsViewModel(alertRepository, webSocket)
    fun createAppsViewModel() = AppsViewModel(systemRepository, webSocket)
    fun createVpnViewModel() = VpnViewModel(systemRepository, webSocket)
    fun createDpiViewModel() = DpiViewModel(systemRepository, webSocket)
    fun createAgentsViewModel() = AgentsViewModel(systemRepository, webSocket)
    fun createLogsViewModel() = LogsViewModel(systemRepository, webSocket)
    fun createSettingsViewModel() = SettingsViewModel(settingsRepository, authRepository, systemRepository)
}

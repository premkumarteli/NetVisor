package com.netvisor.mobile.data.api

import com.netvisor.mobile.data.model.*
import retrofit2.Response
import retrofit2.http.*

interface NetVisorApi {

    @FormUrlEncoded
    @POST("auth/login")
    suspend fun login(
        @Field("username") username: String,
        @Field("password") password: String,
        @Field("grant_type") grantType: String = "password"
    ): Response<UserProfile>

    @POST("auth/logout")
    suspend fun logout(): Response<Unit>

    @GET("auth/me")
    suspend fun getMe(): Response<UserProfile>

    @GET("dashboard/overview")
    suspend fun getOverview(): Response<DashboardOverview>

    @GET("dashboard/activity")
    suspend fun getActivity(
        @Query("limit") limit: Int = 50
    ): Response<List<ActivityEvent>>

    @GET("dashboard/traffic-history")
    suspend fun getTrafficHistory(
        @Query("hours") hours: Int = 24
    ): Response<TrafficHistory>

    @GET("devices/")
    suspend fun getDevices(
        @Query("include_observed") includeObserved: Boolean = false
    ): Response<List<Device>>

    @GET("devices/{device_id}/risk")
    suspend fun getDeviceRisk(
        @Path("device_id") deviceId: String
    ): Response<DeviceRisk>

    @GET("alerts/")
    suspend fun getAlerts(
        @Query("limit") limit: Int = 50,
        @Query("severity") severity: String? = null,
        @Query("resolved") resolved: Boolean? = null
    ): Response<List<Alert>>

    @GET("agents/")
    suspend fun getAgents(): Response<List<AgentSummary>>

    @GET("health/status")
    suspend fun getHealth(): Response<SystemHealth>

    @GET("dpi/status")
    suspend fun getDpiStatus(): Response<DpiStatus>

    @GET("web/activity")
    suspend fun getWebActivity(
        @Query("limit") limit: Int = 20
    ): Response<List<WebActivityItem>>

    @GET("apps/summary")
    suspend fun getAppsSummary(): Response<List<AppSummaryItem>>

    @GET("logs/flows")
    suspend fun getFlowLogs(
        @Query("limit") limit: Int = 50
    ): Response<List<FlowLogItem>>

    @POST("system/actions/scan")
    suspend fun triggerScan(): Response<Unit>
}

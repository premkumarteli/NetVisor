package com.netvisor.mobile.data.websocket

import android.util.Log
import com.netvisor.mobile.data.repository.SettingsRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import okhttp3.*

@Serializable
data class WebSocketEvent(
    val event: String,
    val data: JsonElement
)

class NetVisorWebSocket(
    private val settingsRepository: SettingsRepository,
    private val okHttpClient: OkHttpClient
) {
    private val _events = MutableSharedFlow<WebSocketEvent>(extraBufferCapacity = 64)
    val events: SharedFlow<WebSocketEvent> = _events.asSharedFlow()

    private var webSocket: WebSocket? = null
    private val json = Json { ignoreUnknownKeys = true }
    private val scope = CoroutineScope(Dispatchers.IO)
    @Volatile
    private var isExplicitlyDisconnected = false
    private var reconnectAttempts = 0

    fun connect() {
        isExplicitlyDisconnected = false
        reconnectAttempts = 0
        establishConnection()
    }

    private fun establishConnection() {
        if (isExplicitlyDisconnected) return

        scope.launch {
            try {
                val backendUrl = settingsRepository.backendUrl.first()
                val wsUrl = if (backendUrl.startsWith("https")) {
                    backendUrl.replaceFirst("https", "wss").replace("/api/v1/", "/socket.io/?EIO=4&transport=websocket")
                } else {
                    backendUrl.replaceFirst("http", "ws").replace("/api/v1/", "/socket.io/?EIO=4&transport=websocket")
                }
                val cookie = settingsRepository.sessionCookie.first()

                val request = Request.Builder()
                    .url(wsUrl)
                    .apply {
                        if (!cookie.isNullOrBlank()) {
                            addHeader("Cookie", "netvisor_session=$cookie")
                        }
                    }
                    .build()

                webSocket = okHttpClient.newWebSocket(request, object : WebSocketListener() {
                    override fun onOpen(webSocket: WebSocket, response: Response) {
                        Log.i("NetVisorWS", "WebSocket connected successfully to $wsUrl")
                        reconnectAttempts = 0
                    }

                    override fun onMessage(webSocket: WebSocket, text: String) {
                        try {
                            val event = json.decodeFromString<WebSocketEvent>(text)
                            scope.launch { _events.emit(event) }
                        } catch (e: Exception) {
                            Log.e("NetVisorWS", "Failed to parse message: $text", e)
                        }
                    }

                    override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
                        Log.d("NetVisorWS", "Closing: $code / $reason")
                    }

                    override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                        Log.d("NetVisorWS", "Closed: $code / $reason")
                        if (!isExplicitlyDisconnected) {
                            scheduleReconnect()
                        }
                    }

                    override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                        Log.w("NetVisorWS", "WebSocket Failure: ${t.message}")
                        if (!isExplicitlyDisconnected) {
                            scheduleReconnect()
                        }
                    }
                })
            } catch (e: Exception) {
                Log.e("NetVisorWS", "Error establishing WebSocket connection", e)
                scheduleReconnect()
            }
        }
    }

    private fun scheduleReconnect() {
        if (isExplicitlyDisconnected) return
        scope.launch {
            reconnectAttempts++
            val delayMs = (minOf(reconnectAttempts * 2000L, 10000L))
            Log.d("NetVisorWS", "Scheduling reconnect in ${delayMs}ms (attempt $reconnectAttempts)")
            kotlinx.coroutines.delay(delayMs)
            if (!isExplicitlyDisconnected) {
                establishConnection()
            }
        }
    }

    fun disconnect() {
        isExplicitlyDisconnected = true
        webSocket?.close(1000, "User logout")
        webSocket = null
    }
}

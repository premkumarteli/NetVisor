package com.netvisor.mobile.data.api

import retrofit2.converter.kotlinx.serialization.asConverterFactory
import com.netvisor.mobile.data.repository.SettingsRepository
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import okhttp3.Cookie
import okhttp3.CookieJar
import okhttp3.HttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.logging.HttpLoggingInterceptor
import retrofit2.Retrofit

import java.util.concurrent.TimeUnit
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.Interceptor

class NetVisorApiFactory(private val settingsRepository: SettingsRepository) {

    private val json = Json {
        ignoreUnknownKeys = true
        coerceInputValues = true
    }

    fun create(): NetVisorApi {
        val baseUrl = runBlocking { settingsRepository.backendUrl.first() }
        
        val logging = HttpLoggingInterceptor().apply {
            level = HttpLoggingInterceptor.Level.BODY
        }

        val cookieStore = java.util.concurrent.ConcurrentHashMap<String, String>()

        val dynamicHostInterceptor = Interceptor { chain ->
            var request = chain.request()
            val currentBaseUrlStr = runBlocking { settingsRepository.backendUrl.first() }
            val currentBaseUrl = currentBaseUrlStr.toHttpUrlOrNull()
            if (currentBaseUrl != null) {
                val originalUrl = request.url
                val newUrl = originalUrl.newBuilder()
                    .scheme(currentBaseUrl.scheme)
                    .host(currentBaseUrl.host)
                    .port(currentBaseUrl.port)
                    .build()
                
                val reqBuilder = request.newBuilder().url(newUrl)
                
                // Attach CSRF header if available
                val csrfToken = cookieStore["csrftoken"] ?: cookieStore["XSRF-TOKEN"]
                if (!csrfToken.isNullOrBlank()) {
                    reqBuilder.header("X-XSRF-TOKEN", csrfToken)
                    reqBuilder.header("X-CSRF-Token", csrfToken)
                }

                request = reqBuilder.build()
            }
            chain.proceed(request)
        }

        val client = OkHttpClient.Builder()
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(20, TimeUnit.SECONDS)
            .writeTimeout(20, TimeUnit.SECONDS)
            .addInterceptor(dynamicHostInterceptor)
            .addInterceptor(logging)
            .cookieJar(object : CookieJar {
                override fun saveFromResponse(url: HttpUrl, cookies: List<Cookie>) {
                    for (cookie in cookies) {
                        cookieStore[cookie.name] = cookie.value
                        if (cookie.name == "netvisor_session") {
                            runBlocking { settingsRepository.setSessionCookie(cookie.value) }
                        }
                    }
                }

                override fun loadForRequest(url: HttpUrl): List<Cookie> {
                    val result = mutableListOf<Cookie>()
                    val savedSession = runBlocking { settingsRepository.sessionCookie.first() }
                    if (!savedSession.isNullOrBlank() && !cookieStore.containsKey("netvisor_session")) {
                        cookieStore["netvisor_session"] = savedSession
                    }

                    for ((name, value) in cookieStore) {
                        try {
                            val c = Cookie.Builder()
                                .name(name)
                                .value(value)
                                .domain(url.host)
                                .path("/")
                                .build()
                            result.add(c)
                        } catch (_: Exception) {}
                    }
                    return result
                }
            })
            .build()

        return Retrofit.Builder()
            .baseUrl(baseUrl)
            .client(client)
            .addConverterFactory(json.asConverterFactory("application/json".toMediaType()))
            .build()
            .create(NetVisorApi::class.java)
    }
}

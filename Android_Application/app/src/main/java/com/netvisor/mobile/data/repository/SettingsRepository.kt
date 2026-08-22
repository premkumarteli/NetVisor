package com.netvisor.mobile.data.repository

import android.content.Context
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

private val Context.dataStore by preferencesDataStore(name = "settings")

class SettingsRepository(private val context: Context) {

    private val BACKEND_URL_KEY = stringPreferencesKey("backend_url")
    private val SESSION_COOKIE_KEY = stringPreferencesKey("session_cookie")

    val backendUrl: Flow<String> = context.dataStore.data.map { preferences ->
        preferences[BACKEND_URL_KEY] ?: "http://10.0.2.2:8000/api/v1/" // Default to emulator localhost
    }

    val sessionCookie: Flow<String?> = context.dataStore.data.map { preferences ->
        preferences[SESSION_COOKIE_KEY]
    }

    suspend fun setBackendUrl(url: String) {
        val trimmed = url.trim()
        val withScheme = if (trimmed.startsWith("http://") || trimmed.startsWith("https://")) {
            trimmed
        } else {
            "http://$trimmed"
        }
        val sanitizedUrl = if (withScheme.endsWith("/")) withScheme else "$withScheme/"
        val finalUrl = if (sanitizedUrl.contains("/api/v1/")) sanitizedUrl else "${sanitizedUrl}api/v1/"
        context.dataStore.edit { preferences ->
            preferences[BACKEND_URL_KEY] = finalUrl
        }
    }

    suspend fun setSessionCookie(cookie: String?) {
        context.dataStore.edit { preferences ->
            if (cookie == null) {
                preferences.remove(SESSION_COOKIE_KEY)
            } else {
                preferences[SESSION_COOKIE_KEY] = cookie
            }
        }
    }
}

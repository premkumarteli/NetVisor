package com.netvisor.mobile

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.netvisor.mobile.ui.auth.LoginScreen
import com.netvisor.mobile.ui.home.HomeScreen
import com.netvisor.mobile.ui.network.DeviceDetailsScreen
import com.netvisor.mobile.ui.network.NetworkScreen
import com.netvisor.mobile.ui.threats.ThreatsScreen
import com.netvisor.mobile.ui.theme.NetVisorTheme
import com.netvisor.mobile.ui.components.FloatingBottomNavBar
import kotlinx.coroutines.launch
import com.netvisor.mobile.ui.more.MoreScreen
import com.netvisor.mobile.viewmodel.NetworkViewModel

import com.netvisor.mobile.ui.apps.AppsScreen
import com.netvisor.mobile.ui.vpn.VpnScreen
import com.netvisor.mobile.ui.dpi.DpiScreen
import com.netvisor.mobile.ui.agents.AgentsScreen
import com.netvisor.mobile.ui.logs.LogsScreen
import com.netvisor.mobile.ui.settings.SettingsScreen

class MainActivity : ComponentActivity() {
    
    private lateinit var container: DependencyContainer

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        container = DependencyContainer(applicationContext)
        
        enableEdgeToEdge()
        setContent {
            NetVisorTheme {
                val navController = rememberNavController()
                
                LaunchedEffect(Unit) {
                    if (container.authRepository.checkAuth()) {
                        navController.navigate("home") {
                            popUpTo("login") { inclusive = true }
                        }
                        container.webSocket.connect()
                    }
                }
                val loginViewModel = remember { container.createLoginViewModel() }
                val homeViewModel = remember { container.createHomeViewModel() }
                val networkViewModel = remember { container.createNetworkViewModel() }
                val threatsViewModel = remember { container.createThreatsViewModel() }
                val deviceDetailsViewModel = remember { container.createDeviceDetailsViewModel() }
                val appsViewModel = remember { container.createAppsViewModel() }
                val vpnViewModel = remember { container.createVpnViewModel() }
                val dpiViewModel = remember { container.createDpiViewModel() }
                val agentsViewModel = remember { container.createAgentsViewModel() }
                val logsViewModel = remember { container.createLogsViewModel() }
                val settingsViewModel = remember { container.createSettingsViewModel() }

                val navBackStackEntry by navController.currentBackStackEntryAsState()
                val currentRoute = navBackStackEntry?.destination?.route ?: "login"
                val showBottomBar = currentRoute in listOf("home", "network", "threats", "more")

                Scaffold(
                    modifier = Modifier.fillMaxSize(),
                    bottomBar = {
                        if (showBottomBar) {
                            FloatingBottomNavBar(
                                selectedRoute = currentRoute,
                                onRouteSelected = { route ->
                                    navController.navigate(route) {
                                        popUpTo(navController.graph.startDestinationId) {
                                            saveState = true
                                        }
                                        launchSingleTop = true
                                        restoreState = true
                                    }
                                }
                            )
                        }
                    }
                ) { innerPadding ->
                    NavHost(
                        navController = navController,
                        startDestination = "login",
                        modifier = Modifier.padding(innerPadding)
                    ) {
                        composable("login") {
                            LoginScreen(
                                viewModel = loginViewModel,
                                onLoginSuccess = {
                                    container.webSocket.connect()
                                    navController.navigate("home") {
                                        popUpTo("login") { inclusive = true }
                                    }
                                }
                            )
                        }
                        composable("home") {
                            HomeScreen(viewModel = homeViewModel)
                        }
                        composable("network") {
                            NetworkScreen(
                                viewModel = networkViewModel,
                                onDeviceClick = { device ->
                                    navController.navigate("device_details/${device.id}")
                                }
                            )
                        }
                        composable("device_details/{deviceId}") { backStackEntry ->
                            val deviceId = backStackEntry.arguments?.getString("deviceId")
                            val uiState by networkViewModel.devices.collectAsState()
                            val device = (uiState as? NetworkViewModel.NetworkUiState.Success)
                                ?.devices?.find { it.id == deviceId }
                            
                            if (device != null) {
                                DeviceDetailsScreen(
                                    device = device,
                                    viewModel = deviceDetailsViewModel,
                                    onBack = { navController.popBackStack() }
                                )
                            }
                        }
                        composable("threats") {
                            ThreatsScreen(viewModel = threatsViewModel)
                        }
                        composable("more") {
                            val scope = rememberCoroutineScope()
                            MoreScreen(
                                onNavigate = { route ->
                                    navController.navigate(route)
                                },
                                onLogout = {
                                    scope.launch {
                                        container.webSocket.disconnect()
                                        container.authRepository.logout()
                                        navController.navigate("login") {
                                            popUpTo(0) { inclusive = true }
                                        }
                                    }
                                }
                            )
                        }
                        composable("apps") {
                            AppsScreen(
                                viewModel = appsViewModel,
                                onBack = { navController.popBackStack() }
                            )
                        }
                        composable("vpn") {
                            VpnScreen(
                                viewModel = vpnViewModel,
                                onBack = { navController.popBackStack() }
                            )
                        }
                        composable("dpi") {
                            DpiScreen(
                                viewModel = dpiViewModel,
                                onBack = { navController.popBackStack() }
                            )
                        }
                        composable("agents") {
                            AgentsScreen(
                                viewModel = agentsViewModel,
                                onBack = { navController.popBackStack() }
                            )
                        }
                        composable("logs") {
                            LogsScreen(
                                viewModel = logsViewModel,
                                onBack = { navController.popBackStack() }
                            )
                        }
                        composable("settings") {
                            SettingsScreen(
                                viewModel = settingsViewModel,
                                onBack = { navController.popBackStack() }
                            )
                        }
                    }
                }
            }
        }
    }
}

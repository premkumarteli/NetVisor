package com.netvisor.mobile.navigation

import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Scaffold
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.navigation.NavHostController
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.netvisor.mobile.ui.auth.LoginScreen
import com.netvisor.mobile.ui.components.FloatingBottomNavBar
import com.netvisor.mobile.viewmodel.LoginViewModel

@Composable
fun NetVisorNavGraph(
    loginViewModel: LoginViewModel,
    navController: NavHostController = rememberNavController()
) {
    val navBackStackEntry by navController.currentBackStackEntryAsState()
    val currentRoute = navBackStackEntry?.destination?.route ?: "login"
    
    val showBottomBar = currentRoute in listOf("home", "network", "threats", "more")

    Scaffold(
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
                        navController.navigate("home") {
                            popUpTo("login") { inclusive = true }
                        }
                    }
                )
            }
            composable("home") {
                // TODO: HomeScreen
            }
            composable("network") {
                // TODO: NetworkScreen
            }
            composable("threats") {
                // TODO: ThreatsScreen
            }
            composable("more") {
                // TODO: MoreScreen
            }
        }
    }
}

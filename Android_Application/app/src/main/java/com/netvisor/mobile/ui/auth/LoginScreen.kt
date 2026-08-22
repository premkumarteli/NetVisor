package com.netvisor.mobile.ui.auth

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.foundation.Image
import androidx.compose.ui.res.painterResource
import com.netvisor.mobile.R
import com.netvisor.mobile.ui.components.GlassButton
import com.netvisor.mobile.ui.components.GlassCard
import com.netvisor.mobile.ui.theme.Primary
import com.netvisor.mobile.ui.theme.PrimaryText
import com.netvisor.mobile.ui.theme.SecondaryText
import com.netvisor.mobile.viewmodel.LoginViewModel

@Composable
fun LoginScreen(
    viewModel: LoginViewModel,
    onLoginSuccess: () -> Unit
) {
    val uiState by viewModel.uiState.collectAsState()
    val backendUrl by viewModel.backendUrl.collectAsState()
    
    var username by remember { mutableStateOf("admin") }
    var password by remember { mutableStateOf("NetVisor!DemoAccess99") }
    
    LaunchedEffect(uiState) {
        if (uiState is LoginViewModel.LoginUiState.Success) {
            onLoginSuccess()
        }
    }

    Box(
        modifier = Modifier.fillMaxSize(),
        contentAlignment = Alignment.Center
    ) {
        Column(
            modifier = Modifier
                .padding(24.dp)
                .fillMaxWidth(),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Image(
                painter = painterResource(id = R.drawable.ic_netvisor_logo),
                contentDescription = "NetVisor Logo",
                modifier = Modifier.size(72.dp)
            )
            
            Spacer(modifier = Modifier.height(12.dp))

            Text(
                text = "NETVISOR",
                color = Primary,
                style = MaterialTheme.typography.displayMedium,
                fontWeight = FontWeight.Bold,
                letterSpacing = 4.sp
            )
            Text(
                text = "MOBILE SECURITY CONSOLE",
                color = SecondaryText,
                style = MaterialTheme.typography.labelMedium,
                letterSpacing = 2.sp
            )
            
            Spacer(modifier = Modifier.height(24.dp))
            
            GlassCard {
                Text(
                    text = "Sign In",
                    color = PrimaryText,
                    style = MaterialTheme.typography.titleLarge,
                    fontWeight = FontWeight.Bold
                )
                
                Spacer(modifier = Modifier.height(16.dp))
                
                OutlinedTextField(
                    value = backendUrl,
                    onValueChange = { viewModel.onBackendUrlChange(it) },
                    label = { Text("Server URL") },
                    modifier = Modifier.fillMaxWidth(),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedTextColor = PrimaryText,
                        unfocusedTextColor = PrimaryText,
                        focusedBorderColor = Primary,
                        unfocusedBorderColor = Color.White.copy(alpha = 0.2f)
                    ),
                    singleLine = true
                )
                
                Spacer(modifier = Modifier.height(12.dp))
                
                OutlinedTextField(
                    value = username,
                    onValueChange = { username = it },
                    label = { Text("Username") },
                    modifier = Modifier.fillMaxWidth(),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedTextColor = PrimaryText,
                        unfocusedTextColor = PrimaryText,
                        focusedBorderColor = Primary,
                        unfocusedBorderColor = Color.White.copy(alpha = 0.2f)
                    ),
                    singleLine = true
                )
                
                Spacer(modifier = Modifier.height(12.dp))
                
                OutlinedTextField(
                    value = password,
                    onValueChange = { password = it },
                    label = { Text("Password") },
                    modifier = Modifier.fillMaxWidth(),
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedTextColor = PrimaryText,
                        unfocusedTextColor = PrimaryText,
                        focusedBorderColor = Primary,
                        unfocusedBorderColor = Color.White.copy(alpha = 0.2f)
                    ),
                    singleLine = true
                )
                
                Spacer(modifier = Modifier.height(12.dp))

                // Quick Demo Account Selector
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    AssistChip(
                        onClick = {
                            username = "admin"
                            password = "NetVisor!DemoAccess99"
                        },
                        label = { Text("Admin (Default)", fontSize = 11.sp) },
                        colors = AssistChipDefaults.assistChipColors(
                            containerColor = Primary.copy(alpha = 0.15f),
                            labelColor = Primary
                        ),
                        modifier = Modifier.weight(1f)
                    )
                    AssistChip(
                        onClick = {
                            username = "operator"
                            password = "NetVisor!OperatorAccess99"
                        },
                        label = { Text("Operator", fontSize = 11.sp) },
                        colors = AssistChipDefaults.assistChipColors(
                            containerColor = Color(0xFF8B5CF6).copy(alpha = 0.15f),
                            labelColor = Color(0xFF8B5CF6)
                        ),
                        modifier = Modifier.weight(1f)
                    )
                }
                
                Spacer(modifier = Modifier.height(16.dp))
                
                if (uiState is LoginViewModel.LoginUiState.Error) {
                    Text(
                        text = (uiState as LoginViewModel.LoginUiState.Error).message,
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier.padding(bottom = 12.dp)
                    )
                }
                
                GlassButton(
                    text = if (uiState is LoginViewModel.LoginUiState.Loading) "Connecting..." else "Sign In",
                    onClick = { viewModel.login(username, password) },
                    modifier = Modifier.fillMaxWidth(),
                    containerColor = Primary.copy(alpha = 0.25f),
                    contentColor = Primary
                )
            }
        }
    }
}

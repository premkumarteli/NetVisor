package com.netvisor.mobile.ui.components

import androidx.compose.animation.animateColorAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Menu
import androidx.compose.material.icons.filled.Notifications
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.Security
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.netvisor.mobile.ui.theme.Primary
import com.netvisor.mobile.ui.theme.SecondaryText

@Composable
fun FloatingBottomNavBar(
    selectedRoute: String,
    onRouteSelected: (String) -> Unit,
    modifier: Modifier = Modifier
) {
    GlassSurface(
        modifier = modifier
            .padding(horizontal = 24.dp, vertical = 24.dp)
            .height(80.dp),
        cornerRadius = 40.dp
    ) {
        Row(
            modifier = Modifier.fillMaxSize(),
            horizontalArrangement = Arrangement.SpaceEvenly,
            verticalAlignment = Alignment.CenterVertically
        ) {
            NavItem(
                icon = Icons.Default.Home,
                label = "Home",
                selected = selectedRoute == "home",
                onClick = { onRouteSelected("home") }
            )
            NavItem(
                icon = Icons.Default.Public,
                label = "Network",
                selected = selectedRoute == "network",
                onClick = { onRouteSelected("network") }
            )
            NavItem(
                icon = Icons.Default.Security,
                label = "Threats",
                selected = selectedRoute == "threats",
                onClick = { onRouteSelected("threats") }
            )
            NavItem(
                icon = Icons.Default.Menu,
                label = "More",
                selected = selectedRoute == "more",
                onClick = { onRouteSelected("more") }
            )
        }
    }
}

@Composable
private fun NavItem(
    icon: ImageVector,
    label: String,
    selected: Boolean,
    onClick: () -> Unit
) {
    val color by animateColorAsState(targetValue = if (selected) Primary else SecondaryText)
    
    Column(
        modifier = Modifier
            .clip(RoundedCornerShape(12.dp))
            .clickable(onClick = onClick)
            .padding(horizontal = 12.dp, vertical = 8.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Icon(
            imageVector = icon,
            contentDescription = label,
            tint = color,
            modifier = Modifier.size(24.dp)
        )
        Spacer(modifier = Modifier.height(4.dp))
        Text(
            text = label,
            color = color,
            style = MaterialTheme.typography.labelSmall,
            fontSize = 10.sp
        )
    }
}

# Implementation Plan - NetVisor Mobile

Build a production-quality Android application for NetVisor Platform monitoring and control.

## User Review Required

> [!IMPORTANT]
> The application will use a **dark Liquid Glass / Glassmorphism** design. This requires custom Compose components for translucent surfaces and borders.

> [!WARNING]
> Real-time updates will be implemented using WebSockets. Ensure the backend URL is correctly configured in the app settings.

## Proposed Changes

### Project Structure & Dependencies

- Setup `com.netvisor.mobile` package (refactor from `com.example.myapplication` if necessary).
- Add dependencies for:
    - Jetpack Compose (Material 3, Navigation, ViewModel)
    - Retrofit & OkHttp
    - Kotlin Serialization
    - DataStore (for secure storage)
    - Kotlin Coroutines & Flow

### [Component] UI / Design System
#### [MODIFY] [Theme.kt](file:///C:/Users/prem/Network/Android_Application/app/src/main/java/com/example/myapplication/ui/theme/Theme.kt)
#### [MODIFY] [Color.kt](file:///C:/Users/prem/Network/Android_Application/app/src/main/java/com/example/myapplication/ui/theme/Color.kt)
#### [NEW] [GlassComponents.kt](file:///C:/Users/prem/Network/Android_Application/app/src/main/java/com/netvisor/mobile/ui/components/GlassComponents.kt)
- Implement `GlassCard`, `GlassSurface`, `GlassButton`, etc.

### [Component] Data & Network
#### [NEW] [NetVisorApi.kt](file:///C:/Users/prem/Network/Android_Application/app/src/main/java/com/netvisor/mobile/data/api/NetVisorApi.kt)
- Define Retrofit interface based on backend inspection.
#### [NEW] [NetVisorWebSocket.kt](file:///C:/Users/prem/Network/Android_Application/app/src/main/java/com/netvisor/mobile/data/websocket/NetVisorWebSocket.py)
- Implement WebSocket client using OkHttp.
#### [NEW] [AuthRepository.kt](file:///C:/Users/prem/Network/Android_Application/app/src/main/java/com/netvisor/mobile/data/repository/AuthRepository.kt)
- Handle login and token storage.

### [Component] Navigation
#### [NEW] [NavGraph.kt](file:///C:/Users/prem/Network/Android_Application/app/src/main/java/com/netvisor/mobile/navigation/NavGraph.kt)
- Setup Compose Navigation for Splash, Login, Home, Network, Threats, and More.
#### [NEW] [BottomNavBar.kt](file:///C:/Users/prem/Network/Android_Application/app/src/main/java/com/netvisor/mobile/ui/components/BottomNavBar.kt)
- Floating glass bottom navigation bar.

### [Component] Screens
#### [NEW] [HomeScreen.kt](file:///C:/Users/prem/Network/Android_Application/app/src/main/java/com/netvisor/mobile/ui/home/HomeScreen.kt)
- Dashboard with metrics and traffic visualization.
#### [NEW] [NetworkScreen.kt](file:///C:/Users/prem/Network/Android_Application/app/src/main/java/com/netvisor/mobile/ui/network/NetworkScreen.kt)
- Device list with search and filters.
#### [NEW] [ThreatsScreen.kt](file:///C:/Users/prem/Network/Android_Application/app/src/main/java/com/netvisor/mobile/ui/threats/ThreatsScreen.kt)
- Security threat monitoring.
#### [NEW] [MoreScreen.kt](file:///C:/Users/prem/Network/Android_Application/app/src/main/java/com/netvisor/mobile/ui/more/MoreScreen.kt)
- Settings, Alerts, Activity, Agents, and Server Status.

## Verification Plan

### Automated Tests
- Run `./gradlew assembleDebug` to verify build.
- Unit tests for Repositories and ViewModels.

### Manual Verification
- Deploy to emulator/device.
- Verify authentication flow.
- Verify real-time updates via WebSocket (simulated or against local backend).
- Verify navigation and glass UI consistency.

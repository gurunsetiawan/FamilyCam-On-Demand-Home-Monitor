package com.familycam.viewer

import android.app.Activity
import android.content.Context
import android.content.ContextWrapper
import android.content.pm.ActivityInfo
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.viewinterop.AndroidView
import androidx.compose.ui.unit.dp
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowInsetsControllerCompat
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.familycam.viewer.ui.theme.FamilyCamViewerTheme
import java.io.IOException
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import org.webrtc.AudioSource
import org.webrtc.CandidatePairChangeEvent
import org.webrtc.DataChannel
import org.webrtc.DefaultVideoDecoderFactory
import org.webrtc.DefaultVideoEncoderFactory
import org.webrtc.EglBase
import org.webrtc.IceCandidate
import org.webrtc.MediaConstraints
import org.webrtc.MediaStream
import org.webrtc.MediaStreamTrack
import org.webrtc.PeerConnection
import org.webrtc.PeerConnectionFactory
import org.webrtc.RtpReceiver
import org.webrtc.RtpTransceiver
import org.webrtc.SdpObserver
import org.webrtc.SessionDescription
import org.webrtc.SurfaceViewRenderer
import org.webrtc.VideoTrack
import org.webrtc.audio.JavaAudioDeviceModule

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            FamilyCamViewerTheme {
                Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                    AppScreen()
                }
            }
        }
    }
}

private val Context.dataStore by preferencesDataStore(name = "familycam_viewer_prefs")

private object PrefKeys {
    val serverUrl = stringPreferencesKey("server_url")
    val ownerToken = stringPreferencesKey("owner_token")
}

@Composable
private fun AppScreen() {
    val localContext = androidx.compose.ui.platform.LocalContext.current
    val appContext = localContext.applicationContext
    val activity = remember(localContext) { localContext.findActivity() }
    val controller = remember { AppController(appContext) }
    val state = controller.state
    val selectedCamera = state.cameras.firstOrNull { it.path == state.devicePath }
    var isFullscreen by remember { mutableStateOf(false) }
    var isTokenVisible by remember { mutableStateOf(false) }

    val deviceOptions = mergeOptions(
        defaults = listOf("/dev/video0", "/dev/video1"),
        probed = state.cameras.map { it.path },
        current = state.devicePath,
    )
    val formatOptions = mergeOptions(
        defaults = listOf("mjpeg", "h264", "yuyv422"),
        probed = selectedCamera?.formats?.map { it.ffmpegInput } ?: emptyList(),
        current = state.inputFormat,
    )
    val resolutionOptions = mergeOptions(
        defaults = listOf("320x240", "480x270", "640x360", "640x480", "854x480", "960x540", "1280x720"),
        probed = selectedCamera?.resolutions ?: emptyList(),
        current = state.resolution,
    )
    val fpsOptions = mergeOptions(
        defaults = listOf("5", "10", "15", "24", "30"),
        probed = selectedCamera?.fpsOptions?.map { it.toString() } ?: emptyList(),
        current = state.fps,
    )

    val bgTop = Color(0xFF0A0C10)
    val bgBottom = Color(0xFF121722)
    val cardColor = Color(0xFF111418)
    val borderColor = Color(0xFF1E2530)
    val accent = Color(0xFF00E5A0)
    val accent2 = Color(0xFF00B8D4)
    val danger = Color(0xFFFF3B5C)
    val textPrimary = Color(0xFFE8EDF5)
    val textMuted = Color(0xFF778299)

    val connectColor = ButtonDefaults.buttonColors(containerColor = accent, contentColor = Color(0xFF0A0C10))
    val dangerColor = ButtonDefaults.buttonColors(containerColor = Color(0xFF3A1720), contentColor = Color(0xFFFF9DB0))
    val actionColor = ButtonDefaults.buttonColors(containerColor = Color(0xFF18202B), contentColor = accent2)
    val warnColor = ButtonDefaults.buttonColors(containerColor = Color(0xFF2B2318), contentColor = Color(0xFFFFB36B))

    DisposableEffect(isFullscreen, activity) {
        val targetActivity = activity
        if (isFullscreen && targetActivity != null) {
            runCatching {
                targetActivity.requestedOrientation = ActivityInfo.SCREEN_ORIENTATION_SENSOR_LANDSCAPE
                WindowCompat.setDecorFitsSystemWindows(targetActivity.window, false)
                WindowInsetsControllerCompat(targetActivity.window, targetActivity.window.decorView).apply {
                    hide(WindowInsetsCompat.Type.systemBars())
                    systemBarsBehavior = WindowInsetsControllerCompat.BEHAVIOR_SHOW_TRANSIENT_BARS_BY_SWIPE
                }
            }
        }
        onDispose {
            if (targetActivity != null) {
                runCatching {
                    targetActivity.requestedOrientation = ActivityInfo.SCREEN_ORIENTATION_UNSPECIFIED
                    WindowCompat.setDecorFitsSystemWindows(targetActivity.window, true)
                    WindowInsetsControllerCompat(targetActivity.window, targetActivity.window.decorView).show(WindowInsetsCompat.Type.systemBars())
                }
            }
        }
    }

    BackHandler(enabled = isFullscreen) {
        isFullscreen = false
    }

    DisposableEffect(Unit) {
        onDispose {
            controller.dispose()
        }
    }

    if (isFullscreen) {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(Color.Black),
        ) {
            AndroidView(
                modifier = Modifier.fillMaxSize(),
                factory = { ctx -> controller.createRendererView(ctx) },
                onRelease = { view -> controller.releaseRendererView(view) },
            )
            OutlinedButton(
                onClick = { isFullscreen = false },
                modifier = Modifier
                    .align(Alignment.TopEnd)
                    .padding(14.dp),
                colors = ButtonDefaults.outlinedButtonColors(contentColor = Color.White),
                border = BorderStroke(1.dp, Color(0x66FFFFFF)),
            ) { Text("✕") }
        }
        return
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .background(brush = Brush.verticalGradient(listOf(bgTop, bgBottom)))
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.cardColors(containerColor = cardColor),
        ) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                    Text(
                        "FamilyCam",
                        style = MaterialTheme.typography.headlineSmall,
                        fontWeight = FontWeight.Bold,
                        color = textPrimary,
                        modifier = Modifier.weight(1f),
                    )
                    Text(
                        state.connectionState.uppercase(),
                        style = MaterialTheme.typography.labelSmall,
                        color = if (state.connectionState == "connected") accent else textMuted,
                    )
                }
                Text(
                    "Publisher: ${state.publisherState}",
                    style = MaterialTheme.typography.bodySmall,
                    color = textMuted,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                OutlinedTextField(
                    value = state.serverUrl,
                    onValueChange = controller::setServerUrl,
                    label = { Text("Server URL") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                )
                OutlinedTextField(
                    value = state.ownerToken,
                    onValueChange = controller::setOwnerToken,
                    label = { Text("Owner Token") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    visualTransformation = if (isTokenVisible) VisualTransformation.None else PasswordVisualTransformation(),
                    trailingIcon = {
                        IconButton(onClick = { isTokenVisible = !isTokenVisible }) {
                            Text(if (isTokenVisible) "🙈" else "👁")
                        }
                    },
                )
            }
        }

        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.cardColors(containerColor = cardColor),
        ) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                    Text("Viewer", color = textMuted, style = MaterialTheme.typography.labelLarge, modifier = Modifier.weight(1f))
                    Text(
                        state.sessionId.ifBlank { "session: -" },
                        color = accent,
                        style = MaterialTheme.typography.labelSmall,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }

                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(220.dp)
                        .background(Color.Black, RoundedCornerShape(12.dp)),
                ) {
                    AndroidView(
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(220.dp),
                        factory = { ctx -> controller.createRendererView(ctx) },
                        onRelease = { view -> controller.releaseRendererView(view) },
                    )
                    Text(
                        "REC",
                        color = danger,
                        style = MaterialTheme.typography.labelSmall,
                        modifier = Modifier.padding(10.dp),
                    )
                    Button(
                        onClick = { isFullscreen = true },
                        modifier = Modifier
                            .align(Alignment.BottomEnd)
                            .padding(10.dp),
                        colors = actionColor,
                    ) { Text("⛶") }
                }

                Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                    Button(
                        onClick = { controller.connect() },
                        modifier = Modifier.weight(1f),
                        colors = connectColor,
                    ) { Text("Connect") }
                    Button(
                        onClick = { controller.disconnect() },
                        modifier = Modifier.weight(1f),
                        colors = dangerColor,
                    ) { Text("Disconnect") }
                }
            }
        }

        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.cardColors(containerColor = cardColor),
        ) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Owner Controls", color = textMuted, style = MaterialTheme.typography.labelLarge)

                Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                    Button(onClick = { controller.probeCameras() }, modifier = Modifier.weight(1f), colors = actionColor) { Text("Probe") }
                    Button(onClick = { controller.publisherStatus() }, modifier = Modifier.weight(1f), colors = actionColor) { Text("Status") }
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                    Button(onClick = { controller.startTestPattern() }, modifier = Modifier.weight(1f), colors = warnColor) { Text("Test") }
                    Button(onClick = { controller.stopPublisher() }, modifier = Modifier.weight(1f), colors = dangerColor) { Text("Stop") }
                }

                HorizontalDivider(color = borderColor)

                SelectionField(
                    label = "Device",
                    selected = state.devicePath,
                    options = deviceOptions,
                    onSelect = controller::selectDevicePath,
                    textColor = textPrimary,
                    accentColor = accent2,
                )
                SelectionField(
                    label = "Input Format",
                    selected = state.inputFormat,
                    options = formatOptions,
                    onSelect = controller::selectInputFormat,
                    textColor = textPrimary,
                    accentColor = accent2,
                )
                SelectionField(
                    label = "FPS",
                    selected = state.fps,
                    options = fpsOptions,
                    onSelect = controller::selectFps,
                    textColor = textPrimary,
                    accentColor = accent2,
                )
                SelectionField(
                    label = "Resolution",
                    selected = state.resolution,
                    options = resolutionOptions,
                    onSelect = controller::selectResolution,
                    textColor = textPrimary,
                    accentColor = accent2,
                )

                Text("Manual Override", style = MaterialTheme.typography.labelLarge, color = textMuted)
                OutlinedTextField(
                    value = state.devicePath,
                    onValueChange = controller::setDevicePath,
                    label = { Text("Device") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                )
                OutlinedTextField(
                    value = state.inputFormat,
                    onValueChange = controller::setInputFormat,
                    label = { Text("Input Format") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                    OutlinedTextField(
                        value = state.fps,
                        onValueChange = controller::setFps,
                        label = { Text("FPS") },
                        modifier = Modifier.weight(1f),
                        singleLine = true,
                    )
                    OutlinedTextField(
                        value = state.resolution,
                        onValueChange = controller::setResolution,
                        label = { Text("Resolution") },
                        modifier = Modifier.weight(1f),
                        singleLine = true,
                    )
                }
                Button(
                    onClick = { controller.startWebcam() },
                    modifier = Modifier.fillMaxWidth(),
                    colors = connectColor,
                ) { Text("Start Webcam") }

                Text("Camera ditemukan: ${state.cameras.size}", color = textMuted, style = MaterialTheme.typography.bodySmall)
                if (state.cameras.isNotEmpty()) {
                    val text = state.cameras.joinToString("\n") { "- ${it.name} (${it.path})" }
                    Text(text, style = MaterialTheme.typography.bodySmall, color = textPrimary)
                }
            }
        }

        Card(
            modifier = Modifier.fillMaxWidth(),
            shape = RoundedCornerShape(16.dp),
            colors = CardDefaults.cardColors(containerColor = cardColor),
        ) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text("Log", style = MaterialTheme.typography.titleMedium, color = textMuted)
                Text(state.logs.joinToString("\n"), style = MaterialTheme.typography.bodySmall, color = textPrimary)
            }
        }
    }
}

@Composable
private fun SelectionField(
    label: String,
    selected: String,
    options: List<String>,
    onSelect: (String) -> Unit,
    textColor: Color,
    accentColor: Color,
) {
    var expanded by remember(label, options, selected) { mutableStateOf(false) }
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(label, style = MaterialTheme.typography.labelLarge, color = textColor)
        Box(modifier = Modifier.fillMaxWidth()) {
            OutlinedButton(
                onClick = { expanded = true },
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.outlinedButtonColors(contentColor = accentColor),
            ) {
                Text(
                    selected.ifBlank { "Pilih..." },
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            DropdownMenu(
                expanded = expanded,
                onDismissRequest = { expanded = false },
            ) {
                options.forEach { option ->
                    DropdownMenuItem(
                        text = { Text(option) },
                        onClick = {
                            onSelect(option)
                            expanded = false
                        },
                    )
                }
            }
        }
    }
}

private fun mergeOptions(defaults: List<String>, probed: List<String>, current: String): List<String> {
    return (defaults + probed + listOf(current))
        .map { it.trim() }
        .filter { it.isNotEmpty() }
        .distinct()
}

private tailrec fun Context.findActivity(): Activity? = when (this) {
    is Activity -> this
    is ContextWrapper -> baseContext.findActivity()
    else -> null
}

private data class AppState(
    val serverUrl: String = "http://192.168.240.1:9180",
    val ownerToken: String = "",
    val connectionState: String = "idle",
    val sessionId: String = "",
    val publisherState: String = "unknown",
    val rtpListen: String = "127.0.0.1:6004",
    val devicePath: String = "/dev/video0",
    val inputFormat: String = "mjpeg",
    val fps: String = "15",
    val resolution: String = "640x360",
    val cameras: List<CameraDevice> = emptyList(),
    val logs: List<String> = listOf("ready"),
)

private class AppController(context: Context) {
    private val appContext = context.applicationContext
    private val dataStore = appContext.dataStore
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private val json = Json {
        ignoreUnknownKeys = true
        explicitNulls = false
    }
    private val api = FamilyCamApi(json)

    private val webrtc = WebRtcEngine(
        appContext = appContext,
        api = api,
        onState = { s ->
            state = state.copy(connectionState = s)
            log("webrtc state: $s")
        },
        onSession = { sid ->
            state = state.copy(sessionId = sid)
            log("session: $sid")
        },
        onError = { msg ->
            log("webrtc error: $msg")
        },
    )

    var state by mutableStateOf(AppState())
        private set

    init {
        scope.launch {
            restoreSavedCredentials()
        }
    }

    fun setServerUrl(v: String) {
        state = state.copy(serverUrl = v)
        persistCredentials()
    }

    fun setOwnerToken(v: String) {
        state = state.copy(ownerToken = v)
        persistCredentials()
    }

    fun setDevicePath(v: String) {
        state = state.copy(devicePath = v)
    }

    fun setInputFormat(v: String) {
        state = state.copy(inputFormat = v)
    }

    fun setFps(v: String) {
        state = state.copy(fps = v)
    }

    fun setResolution(v: String) {
        state = state.copy(resolution = v)
    }

    fun selectDevicePath(v: String) {
        var newState = state.copy(devicePath = v)
        val camera = newState.cameras.firstOrNull { it.path == v }
        if (camera != null) {
            val preferredFormat = pickPreferredFormat(camera.formats.map { it.ffmpegInput })
            val preferredFps = pickPreferredFps(camera.fpsOptions.map { it.toString() })
            val preferredResolution = pickPreferredResolution(camera.resolutions)

            if (preferredFormat.isNotBlank()) {
                newState = newState.copy(inputFormat = preferredFormat)
            }
            if (preferredFps.isNotBlank()) {
                newState = newState.copy(fps = preferredFps)
            }
            if (preferredResolution.isNotBlank()) {
                newState = newState.copy(resolution = preferredResolution)
            }
        }
        state = newState
    }

    fun selectInputFormat(v: String) {
        state = state.copy(inputFormat = v)
    }

    fun selectFps(v: String) {
        state = state.copy(fps = v)
    }

    fun selectResolution(v: String) {
        state = state.copy(resolution = v)
    }

    fun createRendererView(ctx: Context): SurfaceViewRenderer {
        return webrtc.createRendererView(ctx)
    }

    fun releaseRendererView(view: SurfaceViewRenderer) {
        webrtc.releaseRendererView(view)
    }

    fun connect() {
        scope.launch {
            val base = state.serverUrl.trim()
            if (base.isEmpty()) {
                log("server URL kosong")
                return@launch
            }
            try {
                val health = api.healthz(base)
                state = state.copy(rtpListen = health.rtpListen)
                log("health ok. rtp=${health.rtpListen}")
                webrtc.connect(baseUrl = base, iceServers = health.iceServers)
            } catch (e: Exception) {
                log("connect gagal: ${e.message}")
                state = state.copy(connectionState = "failed")
            }
        }
    }

    fun disconnect() {
        scope.launch {
            webrtc.disconnect()
            state = state.copy(connectionState = "closed", sessionId = "")
            log("viewer disconnected")
        }
    }

    fun publisherStatus() {
        scope.launch {
            val token = state.ownerToken.trim()
            if (token.isEmpty()) {
                log("owner token belum diisi")
                return@launch
            }
            try {
                val resp = api.publisherStatus(state.serverUrl, token)
                val summary = if (resp.running) "running pid=${resp.pid ?: "-"}" else "stopped"
                state = state.copy(publisherState = summary)
                log("publisher: $summary")
            } catch (e: Exception) {
                log("publisher status gagal: ${e.message}")
            }
        }
    }

    fun startTestPattern() {
        scope.launch {
            val token = state.ownerToken.trim()
            if (token.isEmpty()) {
                log("owner token belum diisi")
                return@launch
            }
            try {
                val resp = api.publisherStart(state.serverUrl, token, PublisherStartRequest())
                val summary = if (resp.running) "running pid=${resp.pid ?: "-"}" else "stopped"
                state = state.copy(publisherState = summary)
                log("publisher test pattern started")
            } catch (e: Exception) {
                log("start test pattern gagal: ${e.message}")
            }
        }
    }

    fun stopPublisher() {
        scope.launch {
            val token = state.ownerToken.trim()
            if (token.isEmpty()) {
                log("owner token belum diisi")
                return@launch
            }
            try {
                val resp = api.publisherStop(state.serverUrl, token)
                val summary = if (resp.running) "running pid=${resp.pid ?: "-"}" else "stopped"
                state = state.copy(publisherState = summary)
                log("publisher stopped")
            } catch (e: Exception) {
                log("stop publisher gagal: ${e.message}")
            }
        }
    }

    fun probeCameras() {
        scope.launch {
            val token = state.ownerToken.trim()
            if (token.isEmpty()) {
                log("owner token belum diisi")
                return@launch
            }
            try {
                val resp = api.cameraProbe(state.serverUrl, token)
                var device = state.devicePath
                var format = state.inputFormat
                var fps = state.fps
                var resolution = state.resolution

                val first = resp.cameras.firstOrNull()
                if (first != null) {
                    device = first.path
                    val pickedFormat = pickPreferredFormat(first.formats.map { it.ffmpegInput })
                    if (pickedFormat.isNotBlank()) {
                        format = pickedFormat
                    }
                    val pickedFps = pickPreferredFps(first.fpsOptions.map { it.toString() })
                    if (pickedFps.isNotBlank()) {
                        fps = pickedFps
                    }
                    val pickedResolution = pickPreferredResolution(first.resolutions)
                    if (pickedResolution.isNotBlank()) {
                        resolution = pickedResolution
                    }
                }

                state = state.copy(
                    cameras = resp.cameras,
                    devicePath = device,
                    inputFormat = format,
                    fps = fps,
                    resolution = resolution,
                )
                log("camera probe: ${resp.cameras.size} device")
            } catch (e: Exception) {
                log("camera probe gagal: ${e.message}")
            }
        }
    }

    fun startWebcam() {
        scope.launch {
            val token = state.ownerToken.trim()
            if (token.isEmpty()) {
                log("owner token belum diisi")
                return@launch
            }
            if (state.devicePath.trim().isEmpty()) {
                log("device path kosong")
                return@launch
            }

            try {
                val health = api.healthz(state.serverUrl)
                state = state.copy(rtpListen = health.rtpListen)

                val args = buildList {
                    add("-f")
                    add("v4l2")
                    if (state.inputFormat.trim().isNotEmpty()) {
                        add("-input_format")
                        add(state.inputFormat.trim())
                    }
                    if (state.fps.trim().isNotEmpty()) {
                        add("-framerate")
                        add(state.fps.trim())
                    }
                    if (state.resolution.trim().isNotEmpty()) {
                        add("-video_size")
                        add(state.resolution.trim())
                    }
                    add("-i")
                    add(state.devicePath.trim())
                    add("-an")
                    add("-c:v")
                    add("libx264")
                    add("-preset")
                    add("ultrafast")
                    add("-tune")
                    add("zerolatency")
                    add("-pix_fmt")
                    add("yuv420p")
                    add("-profile:v")
                    add("baseline")
                    add("-level")
                    add("3.1")
                    add("-g")
                    add("30")
                    add("-keyint_min")
                    add("30")
                    add("-sc_threshold")
                    add("0")
                    add("-f")
                    add("rtp")
                    add("rtp://${health.rtpListen}")
                }

                val resp = api.publisherStart(
                    state.serverUrl,
                    token,
                    PublisherStartRequest(args = args),
                )
                val summary = if (resp.running) "running pid=${resp.pid ?: "-"}" else "stopped"
                state = state.copy(publisherState = summary)
                log("webcam publisher started: ${state.devicePath} -> rtp://${health.rtpListen}")
            } catch (e: Exception) {
                log("start webcam gagal: ${e.message}")
            }
        }
    }

    fun dispose() {
        scope.cancel()
        webrtc.release()
    }

    private fun log(message: String) {
        val time = System.currentTimeMillis()
        val line = "[$time] $message"
        val updated = (listOf(line) + state.logs).take(40)
        state = state.copy(logs = updated)
    }

    private fun pickPreferredFormat(options: List<String>): String {
        val normalized = options.map { it.trim() }.filter { it.isNotEmpty() }
        if (normalized.isEmpty()) return state.inputFormat
        return normalized.firstOrNull { it.equals("mjpeg", ignoreCase = true) }
            ?: normalized.firstOrNull { it.equals("h264", ignoreCase = true) }
            ?: normalized.first()
    }

    private fun pickPreferredFps(options: List<String>): String {
        val normalized = options.map { it.trim() }.filter { it.isNotEmpty() }
        if (normalized.isEmpty()) return state.fps
        val priority = listOf("10", "12", "15", "24", "30")
        return priority.firstOrNull { it in normalized } ?: normalized.first()
    }

    private fun pickPreferredResolution(options: List<String>): String {
        val normalized = options.map { it.trim() }.filter { it.isNotEmpty() }
        if (normalized.isEmpty()) return state.resolution
        val priority = listOf("320x240", "480x270", "640x360", "640x480", "854x480", "960x540")
        return priority.firstOrNull { it in normalized } ?: normalized.first()
    }

    private fun persistCredentials() {
        val savedServerUrl = state.serverUrl.trim()
        val savedOwnerToken = state.ownerToken
        scope.launch(Dispatchers.IO) {
            dataStore.edit { prefs ->
                if (savedServerUrl.isBlank()) {
                    prefs.remove(PrefKeys.serverUrl)
                } else {
                    prefs[PrefKeys.serverUrl] = savedServerUrl
                }
                if (savedOwnerToken.isBlank()) {
                    prefs.remove(PrefKeys.ownerToken)
                } else {
                    prefs[PrefKeys.ownerToken] = savedOwnerToken
                }
            }
        }
    }

    private suspend fun restoreSavedCredentials() {
        runCatching {
            val prefs = dataStore.data.first()
            val savedServerUrl = prefs[PrefKeys.serverUrl]
            val savedOwnerToken = prefs[PrefKeys.ownerToken]
            state = state.copy(
                serverUrl = savedServerUrl ?: state.serverUrl,
                ownerToken = savedOwnerToken ?: state.ownerToken,
            )
        }.onFailure {
            log("gagal load local settings: ${it.message}")
        }
    }
}

private class WebRtcEngine(
    appContext: Context,
    private val api: FamilyCamApi,
    private val onState: (String) -> Unit,
    private val onSession: (String) -> Unit,
    private val onError: (String) -> Unit,
) {
    private val mainHandler = Handler(Looper.getMainLooper())
    private val json = Json {
        ignoreUnknownKeys = true
        explicitNulls = false
    }
    private val workerScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private val eglBase = EglBase.create()
    private val peerFactory: PeerConnectionFactory

    @Volatile
    private var peerConnection: PeerConnection? = null

    @Volatile
    private var renderer: SurfaceViewRenderer? = null

    @Volatile
    private var remoteVideoTrack: VideoTrack? = null

    @Volatile
    private var currentSessionId: String? = null

    private val pendingCandidates = mutableListOf<IceCandidate>()

    init {
        initializePeerFactory(appContext)
        val adm = JavaAudioDeviceModule.builder(appContext).createAudioDeviceModule()
        peerFactory = PeerConnectionFactory
            .builder()
            .setAudioDeviceModule(adm)
            .setVideoDecoderFactory(DefaultVideoDecoderFactory(eglBase.eglBaseContext))
            .setVideoEncoderFactory(DefaultVideoEncoderFactory(eglBase.eglBaseContext, true, true))
            .createPeerConnectionFactory()
        adm.release()
    }

    fun createRendererView(ctx: Context): SurfaceViewRenderer {
        val view = SurfaceViewRenderer(ctx)
        view.init(eglBase.eglBaseContext, null)
        view.setEnableHardwareScaler(true)
        view.setMirror(false)
        attachRenderer(view)
        return view
    }

    fun releaseRendererView(view: SurfaceViewRenderer) {
        val track = remoteVideoTrack
        mainHandler.post {
            try {
                track?.removeSink(view)
                view.release()
            } catch (_: Exception) {
            }
        }
        if (renderer === view) {
            renderer = null
        }
    }

    suspend fun connect(baseUrl: String, iceServers: List<String>) {
        disconnect()
        onState("connecting")
        pendingCandidates.clear()
        currentSessionId = null

        val config = PeerConnection.RTCConfiguration(
            iceServers.filter { it.isNotBlank() }.map {
                PeerConnection.IceServer.builder(it).createIceServer()
            },
        )

        val observer = object : PeerConnection.Observer {
            override fun onSignalingChange(newState: PeerConnection.SignalingState) = Unit
            override fun onIceConnectionChange(newState: PeerConnection.IceConnectionState) = Unit
            override fun onIceConnectionReceivingChange(receiving: Boolean) = Unit
            override fun onIceGatheringChange(newState: PeerConnection.IceGatheringState) = Unit

            override fun onIceCandidate(candidate: IceCandidate) {
                synchronized(pendingCandidates) {
                    pendingCandidates.add(candidate)
                }
                flushCandidates(baseUrl)
            }

            override fun onIceCandidatesRemoved(candidates: Array<IceCandidate>) = Unit
            override fun onAddStream(stream: MediaStream) = Unit
            override fun onRemoveStream(stream: MediaStream) = Unit
            override fun onDataChannel(dataChannel: DataChannel) = Unit
            override fun onRenegotiationNeeded() = Unit

            override fun onTrack(transceiver: RtpTransceiver) {
                val track = transceiver.receiver.track()
                if (track is VideoTrack) {
                    remoteVideoTrack = track
                    bindRemoteTrackToRenderer()
                }
            }

            override fun onConnectionChange(newState: PeerConnection.PeerConnectionState) {
                onState(newState.name.lowercase())
            }

            override fun onSelectedCandidatePairChanged(event: CandidatePairChangeEvent) = Unit
        }

        val pc = peerFactory.createPeerConnection(config, observer)
            ?: throw IllegalStateException("gagal membuat PeerConnection")

        peerConnection = pc

        val transceiver = pc.addTransceiver(
            MediaStreamTrack.MediaType.MEDIA_TYPE_VIDEO,
            RtpTransceiver.RtpTransceiverInit(RtpTransceiver.RtpTransceiverDirection.RECV_ONLY),
        )
        preferH264IfAvailable(transceiver)

        val offer = pc.createOfferSuspend()
        pc.setLocalDescriptionSuspend(offer)

        // Small delay so initial candidates can be gathered before posting offer.
        delay(300)

        val localSdp = pc.localDescription?.description ?: offer.description
        val answer = api.offer(baseUrl, OfferRequest(sdp = localSdp))

        currentSessionId = answer.sessionId
        onSession(answer.sessionId)

        flushCandidates(baseUrl)

        pc.setRemoteDescriptionSuspend(
            SessionDescription(SessionDescription.Type.ANSWER, answer.sdp),
        )

        onState("connected")
    }

    suspend fun disconnect() {
        val pc = peerConnection
        peerConnection = null

        if (pc != null) {
            try {
                pc.close()
            } catch (_: Exception) {
            }
        }

        currentSessionId = null

        val track = remoteVideoTrack
        val view = renderer
        if (track != null && view != null) {
            mainHandler.post {
                track.removeSink(view)
            }
        }
        remoteVideoTrack = null
    }

    fun release() {
        workerScope.cancel()
        val view = renderer
        renderer = null
        if (view != null) {
            mainHandler.post {
                try {
                    view.release()
                } catch (_: Exception) {
                }
            }
        }

        try {
            peerConnection?.close()
        } catch (_: Exception) {
        }
        peerConnection = null
        peerFactory.dispose()
        eglBase.release()
    }

    private fun bindRemoteTrackToRenderer() {
        val track = remoteVideoTrack
        val view = renderer
        if (track == null || view == null) return
        mainHandler.post {
            try {
                track.addSink(view)
            } catch (e: Exception) {
                onError("addSink gagal: ${e.message}")
            }
        }
    }

    private fun attachRenderer(view: SurfaceViewRenderer) {
        val old = renderer
        val track = remoteVideoTrack
        renderer = view
        mainHandler.post {
            try {
                if (old != null && old !== view) {
                    track?.removeSink(old)
                    old.release()
                }
                track?.addSink(view)
            } catch (e: Exception) {
                onError("renderer attach gagal: ${e.message}")
            }
        }
    }

    private fun flushCandidates(baseUrl: String) {
        val sid = currentSessionId ?: return

        val candidates = synchronized(pendingCandidates) {
            if (pendingCandidates.isEmpty()) {
                emptyList()
            } else {
                val copy = pendingCandidates.toList()
                pendingCandidates.clear()
                copy
            }
        }

        if (candidates.isEmpty()) return

        workerScope.launch {
            for (c in candidates) {
                val req = CandidateRequest(
                    sessionId = sid,
                    candidate = c.sdp,
                    sdpMid = c.sdpMid,
                    sdpMLineIndex = c.sdpMLineIndex,
                    usernameFragment = null,
                )
                try {
                    api.candidate(baseUrl, req)
                } catch (e: Exception) {
                    onError("candidate post gagal: ${e.message}")
                }
            }
        }
    }

    private fun preferH264IfAvailable(transceiver: RtpTransceiver) {
        // Some prebuilt WebRTC Android artifacts do not expose codec capability APIs consistently.
        // Keep default codec negotiation path to preserve compatibility across devices.
        if (transceiver.mid != null) {
            onError("codec preference: default negotiation")
        } else {
            onError("codec preference: default negotiation")
        }
    }

    private suspend fun PeerConnection.createOfferSuspend(): SessionDescription = suspendCancellableCoroutine { cont ->
        createOffer(object : SdpObserver {
            override fun onCreateSuccess(desc: SessionDescription?) {
                if (desc == null) {
                    cont.resumeWith(Result.failure(IllegalStateException("offer null")))
                } else {
                    cont.resumeWith(Result.success(desc))
                }
            }

            override fun onSetSuccess() = Unit
            override fun onCreateFailure(message: String?) {
                cont.resumeWith(Result.failure(IllegalStateException(message ?: "createOffer gagal")))
            }

            override fun onSetFailure(message: String?) = Unit
        }, MediaConstraints())
    }

    private suspend fun PeerConnection.setLocalDescriptionSuspend(desc: SessionDescription): Unit = suspendCancellableCoroutine { cont ->
        setLocalDescription(object : SdpObserver {
            override fun onCreateSuccess(desc: SessionDescription?) = Unit
            override fun onSetSuccess() {
                cont.resumeWith(Result.success(Unit))
            }

            override fun onCreateFailure(message: String?) = Unit
            override fun onSetFailure(message: String?) {
                cont.resumeWith(Result.failure(IllegalStateException(message ?: "setLocal gagal")))
            }
        }, desc)
    }

    private suspend fun PeerConnection.setRemoteDescriptionSuspend(desc: SessionDescription): Unit = suspendCancellableCoroutine { cont ->
        setRemoteDescription(object : SdpObserver {
            override fun onCreateSuccess(desc: SessionDescription?) = Unit
            override fun onSetSuccess() {
                cont.resumeWith(Result.success(Unit))
            }

            override fun onCreateFailure(message: String?) = Unit
            override fun onSetFailure(message: String?) {
                cont.resumeWith(Result.failure(IllegalStateException(message ?: "setRemote gagal")))
            }
        }, desc)
    }

    companion object {
        @Volatile
        private var initialized = false

        private fun initializePeerFactory(context: Context) {
            if (initialized) return
            synchronized(this) {
                if (initialized) return
                PeerConnectionFactory.initialize(
                    PeerConnectionFactory.InitializationOptions.builder(context)
                        .setEnableInternalTracer(false)
                        .createInitializationOptions(),
                )
                initialized = true
            }
        }
    }
}

private class FamilyCamApi(private val json: Json) {
    private val client = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .writeTimeout(30, TimeUnit.SECONDS)
        .build()

    suspend fun healthz(baseUrl: String): HealthzResponse {
        val body = request(baseUrl, "/healthz", method = "GET")
        return decode(body)
    }

    suspend fun offer(baseUrl: String, req: OfferRequest): OfferResponse {
        val body = request(baseUrl, "/webrtc/offer", method = "POST", bodyJson = encode(req))
        return decode(body)
    }

    suspend fun candidate(baseUrl: String, req: CandidateRequest) {
        request(baseUrl, "/webrtc/candidate", method = "POST", bodyJson = encode(req))
    }

    suspend fun cameraProbe(baseUrl: String, ownerToken: String): CameraProbeResponse {
        val body = request(baseUrl, "/camera/probe", method = "GET", token = ownerToken)
        return decode(body)
    }

    suspend fun publisherStatus(baseUrl: String, ownerToken: String): PublisherStatusResponse {
        val body = request(baseUrl, "/publisher/status", method = "GET", token = ownerToken)
        return decode(body)
    }

    suspend fun publisherStart(
        baseUrl: String,
        ownerToken: String,
        req: PublisherStartRequest,
    ): PublisherStatusResponse {
        val body = request(baseUrl, "/publisher/start", method = "POST", token = ownerToken, bodyJson = encode(req))
        return decode(body)
    }

    suspend fun publisherStop(baseUrl: String, ownerToken: String): PublisherStatusResponse {
        val body = request(baseUrl, "/publisher/stop", method = "POST", token = ownerToken, bodyJson = "{}")
        return decode(body)
    }

    private suspend fun request(
        baseUrl: String,
        path: String,
        method: String,
        token: String? = null,
        bodyJson: String? = null,
    ): String = withContext(Dispatchers.IO) {
        val url = buildUrl(baseUrl, path, token)
        val builder = Request.Builder().url(url)

        val requestBody = if (bodyJson != null) {
            bodyJson.toRequestBody("application/json; charset=utf-8".toMediaType())
        } else {
            null
        }

        when (method) {
            "GET" -> builder.get()
            "POST" -> builder.post(requestBody ?: "{}".toRequestBody("application/json; charset=utf-8".toMediaType()))
            else -> throw IllegalArgumentException("unsupported method: $method")
        }

        val response = client.newCall(builder.build()).execute()
        response.use {
            val raw = it.body?.string().orEmpty()
            if (!it.isSuccessful) {
                val error = parseError(raw)
                throw IOException("HTTP ${it.code}: $error")
            }
            return@withContext raw
        }
    }

    private fun buildUrl(baseUrl: String, path: String, token: String?): String {
        val normalized = baseUrl.trim().trimEnd('/')
        val raw = "$normalized$path"
        val base = raw.toHttpUrlOrNull() ?: throw IllegalArgumentException("base URL invalid: $raw")
        val withQuery = if (!token.isNullOrBlank()) {
            base.newBuilder().addQueryParameter("token", token).build()
        } else {
            base
        }
        return withQuery.toString()
    }

    private fun parseError(raw: String): String {
        return try {
            val obj = json.decodeFromString(JsonObject.serializer(), raw)
            obj["error"]?.jsonPrimitive?.content ?: raw.ifBlank { "unknown error" }
        } catch (_: Exception) {
            raw.ifBlank { "unknown error" }
        }
    }

    private inline fun <reified T> decode(raw: String): T {
        return try {
            json.decodeFromString(raw)
        } catch (e: SerializationException) {
            throw IOException("response decode gagal: ${e.message}")
        }
    }

    private inline fun <reified T> encode(v: T): String = json.encodeToString(v)
}

@Serializable
private data class HealthzResponse(
    @SerialName("ice_servers") val iceServers: List<String> = emptyList(),
    @SerialName("rtp_listen") val rtpListen: String = "127.0.0.1:6004",
)

@Serializable
private data class OfferRequest(
    val sdp: String,
)

@Serializable
private data class OfferResponse(
    @SerialName("session_id") val sessionId: String,
    val sdp: String,
    val type: String,
)

@Serializable
private data class CandidateRequest(
    @SerialName("session_id") val sessionId: String,
    val candidate: String,
    val sdpMid: String? = null,
    val sdpMLineIndex: Int? = null,
    val usernameFragment: String? = null,
)

@Serializable
private data class CameraProbeResponse(
    val cameras: List<CameraDevice> = emptyList(),
)

@Serializable
private data class CameraDevice(
    val name: String,
    val path: String,
    val formats: List<CameraFormat> = emptyList(),
    @SerialName("resolutions") val resolutions: List<String> = emptyList(),
    @SerialName("fps_options") val fpsOptions: List<Int> = emptyList(),
)

@Serializable
private data class CameraFormat(
    val code: String,
    @SerialName("ffmpeg_input") val ffmpegInput: String,
)

@Serializable
private data class PublisherStartRequest(
    val bin: String? = null,
    val args: List<String>? = null,
)

@Serializable
private data class PublisherStatusResponse(
    val running: Boolean,
    val pid: Int? = null,
)

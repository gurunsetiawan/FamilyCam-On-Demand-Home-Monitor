package com.familycam.viewer

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.familycam.viewer.ui.theme.FamilyCamViewerTheme
import kotlinx.coroutines.delay

class SplashActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            FamilyCamViewerTheme {
                Surface(modifier = Modifier.fillMaxSize(), color = Color(0xFF0A0C10)) {
                    SplashScreen {
                        startActivity(Intent(this, MainActivity::class.java))
                        finish()
                    }
                }
            }
        }
    }
}

@Composable
private fun SplashScreen(onDone: () -> Unit) {
    val rotateAnim = rememberInfiniteTransition(label = "ring")
    val ringRotation = rotateAnim.animateFloat(
        initialValue = 0f,
        targetValue = 360f,
        animationSpec = infiniteRepeatable(
            animation = tween(durationMillis = 6000, easing = LinearEasing),
            repeatMode = RepeatMode.Restart,
        ),
        label = "ringRotation",
    )

    LaunchedEffect(Unit) {
        delay(2200)
        onDone()
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(
                Brush.verticalGradient(
                    listOf(Color(0xFF0A0C10), Color(0xFF101722)),
                ),
            )
            .padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Box(
            modifier = Modifier
                .size(120.dp)
                .rotate(ringRotation.value)
                .background(
                    brush = Brush.linearGradient(
                        listOf(Color(0x2000E5A0), Color(0x3000B8D4)),
                    ),
                    shape = RoundedCornerShape(30.dp),
                ),
            contentAlignment = Alignment.Center,
        ) {
            Box(
                modifier = Modifier
                    .size(74.dp)
                    .background(Color(0xFF161B22), RoundedCornerShape(22.dp)),
                contentAlignment = Alignment.Center,
            ) {
                Text("CAM", color = Color(0xFF00E5A0), fontWeight = FontWeight.Bold)
            }
        }

        Text(
            text = "FamilyCam",
            style = MaterialTheme.typography.headlineLarge,
            color = Color(0xFFE8EDF5),
            fontWeight = FontWeight.ExtraBold,
            modifier = Modifier.padding(top = 24.dp),
        )
        Text(
            text = "ON-DEMAND HOME MONITOR",
            style = MaterialTheme.typography.labelSmall,
            color = Color(0xFF778299),
            modifier = Modifier.padding(top = 6.dp),
        )

        LinearProgressIndicator(
            modifier = Modifier
                .padding(top = 44.dp)
                .height(4.dp),
            color = Color(0xFF00E5A0),
            trackColor = Color(0x33212A36),
        )
        Text(
            text = "Booting secure stream...",
            style = MaterialTheme.typography.labelSmall,
            color = Color(0xFF778299),
            modifier = Modifier.padding(top = 10.dp),
        )
    }
}

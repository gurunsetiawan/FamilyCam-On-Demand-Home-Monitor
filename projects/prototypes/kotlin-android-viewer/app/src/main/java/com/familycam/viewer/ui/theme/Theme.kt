package com.familycam.viewer.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val FamilyCamDarkScheme = darkColorScheme(
    primary = Color(0xFF00E5A0),
    secondary = Color(0xFF00B8D4),
    background = Color(0xFF0A0C10),
    surface = Color(0xFF111418),
    onPrimary = Color(0xFF0A0C10),
    onSecondary = Color(0xFFE8EDF5),
    onBackground = Color(0xFFE8EDF5),
    onSurface = Color(0xFFE8EDF5),
)

@Composable
fun FamilyCamViewerTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = FamilyCamDarkScheme,
        typography = androidx.compose.material3.Typography(),
        content = content,
    )
}

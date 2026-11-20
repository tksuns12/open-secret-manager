package org.opensecretmanager.app

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.ColorScheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.Immutable
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.opensecretmanager.vault.ItemKind

// The desktop app's look, made for a phone: a warm near-black (or warm paper,
// in the light theme) with an amber accent. System fonts only: nothing is
// downloaded or bundled for it.

private val Amber = Color(0xFFDDA45B)
private val AmberDeep = Color(0xFF8D5A1E)

private val Dark = darkColorScheme(
    primary = Amber,
    onPrimary = Color(0xFF1D160E),
    primaryContainer = Color(0xFF33281C),
    onPrimaryContainer = Color(0xFFF0C47F),
    secondary = Color(0xFFB8AD9C),
    onSecondary = Color(0xFF1D160E),
    secondaryContainer = Color(0xFF2A261F),
    onSecondaryContainer = Color(0xFFE6DDCE),
    tertiary = Color(0xFF8FB3CF),
    background = Color(0xFF11100E),
    onBackground = Color(0xFFF4F0E7),
    surface = Color(0xFF11100E),
    onSurface = Color(0xFFF4F0E7),
    surfaceVariant = Color(0xFF1D1B18),
    onSurfaceVariant = Color(0xFFA39B8E),
    surfaceContainerLowest = Color(0xFF0D0C0A),
    surfaceContainerLow = Color(0xFF161512),
    surfaceContainer = Color(0xFF1B1916),
    surfaceContainerHigh = Color(0xFF221F1B),
    surfaceContainerHighest = Color(0xFF2A2621),
    outline = Color(0xFF6F685D),
    outlineVariant = Color(0xFF2D2A25),
    inverseSurface = Color(0xFFEDE5D6),
    inverseOnSurface = Color(0xFF1C1914),
    inversePrimary = AmberDeep,
    error = Color(0xFFE8A28A),
    onError = Color(0xFF2A1712),
    errorContainer = Color(0xFF2C1F1B),
    onErrorContainer = Color(0xFFF0B59F),
)

private val Light = lightColorScheme(
    primary = AmberDeep,
    onPrimary = Color(0xFFFFFBF5),
    primaryContainer = Color(0xFFF7E3C4),
    onPrimaryContainer = Color(0xFF4A2D08),
    secondary = Color(0xFF6B6153),
    onSecondary = Color(0xFFFFFFFF),
    secondaryContainer = Color(0xFFEDE5D6),
    onSecondaryContainer = Color(0xFF2B2418),
    tertiary = Color(0xFF3F6B8C),
    background = Color(0xFFFAF7F0),
    onBackground = Color(0xFF1C1914),
    surface = Color(0xFFFAF7F0),
    onSurface = Color(0xFF1C1914),
    surfaceVariant = Color(0xFFF0EADD),
    onSurfaceVariant = Color(0xFF6B6459),
    surfaceContainerLowest = Color(0xFFFFFFFF),
    surfaceContainerLow = Color(0xFFF6F1E6),
    surfaceContainer = Color(0xFFF1EBDD),
    surfaceContainerHigh = Color(0xFFEBE4D4),
    surfaceContainerHighest = Color(0xFFE5DDCB),
    outline = Color(0xFF8C8478),
    outlineVariant = Color(0xFFDDD5C4),
    inverseSurface = Color(0xFF2B261F),
    inverseOnSurface = Color(0xFFF4F0E7),
    inversePrimary = Amber,
    error = Color(0xFF9B3B22),
    onError = Color(0xFFFFFFFF),
    errorContainer = Color(0xFFF8DDD3),
    onErrorContainer = Color(0xFF4A1708),
)

private val Type = Typography().let { base ->
    fun TextStyle.tight(weight: FontWeight, spacing: Double = 0.0) = copy(fontWeight = weight, letterSpacing = spacing.sp)
    Typography(
        displaySmall = base.displaySmall.tight(FontWeight.Bold, -0.5),
        headlineMedium = base.headlineMedium.tight(FontWeight.Bold, -0.4),
        headlineSmall = base.headlineSmall.tight(FontWeight.Bold, -0.3),
        titleLarge = base.titleLarge.tight(FontWeight.Bold, -0.2),
        titleMedium = base.titleMedium.tight(FontWeight.SemiBold),
        titleSmall = base.titleSmall.tight(FontWeight.SemiBold),
        bodyLarge = base.bodyLarge,
        bodyMedium = base.bodyMedium,
        bodySmall = base.bodySmall,
        labelLarge = base.labelLarge.tight(FontWeight.SemiBold),
        labelMedium = base.labelMedium.tight(FontWeight.SemiBold, 0.4),
        labelSmall = base.labelSmall.tight(FontWeight.SemiBold, 0.8),
    )
}

private val Round = Shapes(
    extraSmall = RoundedCornerShape(12.dp), // text fields
    small = RoundedCornerShape(12.dp),
    medium = RoundedCornerShape(16.dp),
    large = RoundedCornerShape(22.dp),
    extraLarge = RoundedCornerShape(28.dp),
)

/** What the theme adds to Material's own: the colours of the kinds of item, and the mono face for secrets. */
@Immutable
class OsmExtras(
    val login: Color,
    val loginTint: Color,
    val note: Color,
    val noteTint: Color,
    val card: Color,
    val cardTint: Color,
    val identity: Color,
    val identityTint: Color,
    val good: Color,
    val mono: FontFamily = FontFamily.Monospace,
)

private val DarkExtras = OsmExtras(
    login = Color(0xFFDCA964), loginTint = Color(0xFF342A1E),
    note = Color(0xFF91AAA2), noteTint = Color(0xFF252A2A),
    card = Color(0xFF8FB3CF), cardTint = Color(0xFF1F2A33),
    identity = Color(0xFFA899C5), identityTint = Color(0xFF29243A),
    good = Color(0xFF86B768),
)

private val LightExtras = OsmExtras(
    login = Color(0xFF8D5A1E), loginTint = Color(0xFFF7E3C4),
    note = Color(0xFF3F6B5E), noteTint = Color(0xFFDDEBE5),
    card = Color(0xFF2F5F85), cardTint = Color(0xFFDCEAF5),
    identity = Color(0xFF5B4A8A), identityTint = Color(0xFFE7E0F4),
    good = Color(0xFF4F7D35),
)

val LocalOsm = staticCompositionLocalOf { DarkExtras }

val MaterialTheme.osm: OsmExtras
    @Composable get() = LocalOsm.current

/** The tint behind an item's icon and the colour of the icon, by kind. */
@Composable
fun kindColors(kind: ItemKind): Pair<Color, Color> {
    val osm = MaterialTheme.osm
    return when (kind) {
        ItemKind.LOGIN -> osm.loginTint to osm.login
        ItemKind.SECURE_NOTE -> osm.noteTint to osm.note
        ItemKind.CARD -> osm.cardTint to osm.card
        ItemKind.IDENTITY -> osm.identityTint to osm.identity
    }
}

@Composable
fun OsmTheme(dark: Boolean = isSystemInDarkTheme(), content: @Composable () -> Unit) {
    val scheme: ColorScheme = if (dark) Dark else Light
    androidx.compose.runtime.CompositionLocalProvider(LocalOsm provides if (dark) DarkExtras else LightExtras) {
        MaterialTheme(colorScheme = scheme, typography = Type, shapes = Round, content = content)
    }
}

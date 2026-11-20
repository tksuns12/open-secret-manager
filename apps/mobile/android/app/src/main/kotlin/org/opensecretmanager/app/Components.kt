package org.opensecretmanager.app

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.opensecretmanager.vault.ItemKind

/** The shield with a keyhole, as the app's icon draws it, in [tint]. */
@Composable
fun BrandMark(size: Dp, tint: Color = MaterialTheme.colorScheme.primary) {
    Canvas(Modifier.size(size)) {
        val w = this.size.width
        val h = this.size.height
        val shield = Path().apply {
            moveTo(w * .5f, h * .06f)
            lineTo(w * .86f, h * .2f)
            lineTo(w * .86f, h * .52f)
            cubicTo(w * .86f, h * .74f, w * .68f, h * .88f, w * .5f, h * .96f)
            cubicTo(w * .32f, h * .88f, w * .14f, h * .74f, w * .14f, h * .52f)
            lineTo(w * .14f, h * .2f)
            close()
        }
        drawPath(shield, tint, style = Stroke(width = w * .07f))
        // The keyhole: a ring over a short stem.
        drawCircle(tint, radius = w * .085f, center = Offset(w * .5f, h * .42f))
        drawRect(tint, topLeft = Offset(w * .465f, h * .45f), size = Size(w * .07f, h * .2f))
    }
}

/** An item's mark in a list: its first letter, on the colour of its kind. */
@Composable
fun ItemAvatar(title: String, kind: ItemKind, size: Dp = 44.dp) {
    val (tint, ink) = kindColors(kind)
    Box(
        Modifier.size(size).background(tint, RoundedCornerShape(size * 0.3f)),
        contentAlignment = Alignment.Center,
    ) {
        val mark = when (kind) {
            ItemKind.CARD -> "▭"
            ItemKind.SECURE_NOTE -> "≡"
            else -> title.trim().firstOrNull()?.uppercaseChar()?.toString() ?: "•"
        }
        // Decoration: the row's text already says what the item is.
        Text(
            mark,
            color = ink,
            fontWeight = FontWeight.ExtraBold,
            fontSize = (size.value * 0.42f).sp,
            modifier = Modifier.clearAndSetSemantics { },
        )
    }
}

/** A rounded block that groups rows, as the desktop's record card does. */
@Composable
fun Card(modifier: Modifier = Modifier, content: @Composable () -> Unit) {
    Surface(
        modifier = modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.medium,
        color = MaterialTheme.colorScheme.surfaceContainer,
        border = androidx.compose.foundation.BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant),
        content = content,
    )
}

/** A small caps heading over a group of rows. */
@Composable
fun SectionLabel(text: String, modifier: Modifier = Modifier) {
    Text(
        text.uppercase(),
        style = MaterialTheme.typography.labelSmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = modifier.padding(start = 4.dp, top = 8.dp, bottom = 2.dp),
    )
}

/** Rows in a [Card], with a hairline between them. */
@Composable
fun CardRows(rows: List<@Composable () -> Unit>) {
    Card {
        Column {
            rows.forEachIndexed { index, row ->
                if (index > 0) HorizontalDivider(Modifier.padding(horizontal = 16.dp), color = MaterialTheme.colorScheme.outlineVariant)
                row()
            }
        }
    }
}

/** A line of a settings list: a title with a help text under it, and a control to the right. */
@Composable
fun SettingRow(title: String, help: String? = null, modifier: Modifier = Modifier, control: @Composable () -> Unit) {
    Row(
        modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(title, style = MaterialTheme.typography.bodyLarge)
            help?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant) }
        }
        control()
    }
}

/** The mark of a row that opens something. */
@Composable
fun Chevron() {
    Text("›", color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.clearAndSetSemantics { })
}

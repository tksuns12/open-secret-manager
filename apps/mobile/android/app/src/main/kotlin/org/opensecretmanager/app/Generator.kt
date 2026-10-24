package org.opensecretmanager.app

import android.content.Context
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Slider
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import kotlin.math.roundToInt
import org.opensecretmanager.vault.PasswordOptions
import org.opensecretmanager.vault.defaultPasswordOptions

/**
 * What the password generator makes on this phone, kept with its other
 * settings: the shared code's choice until the owner changes it, which the
 * editor's Generate, and a password made at a sign-up, use.
 */
object Generator {
    private const val PREFERENCES = "settings"
    private const val LENGTH = "generator-length"
    private const val LOWERCASE = "generator-lowercase"
    private const val UPPERCASE = "generator-uppercase"
    private const val DIGITS = "generator-digits"
    private const val SYMBOLS = "generator-symbols"
    private const val AVOID_LOOK_ALIKE = "generator-avoid-look-alike"

    /** The lengths offered. */
    val LENGTHS = 8..64

    /** The owner's choice, or the shared code's if none is kept, or one kept is not one it can be. */
    fun options(context: Context): PasswordOptions {
        val defaults = defaultPasswordOptions()
        val kept = context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)
        val options = PasswordOptions(
            length = kept.getInt(LENGTH, defaults.length.toInt()).coerceAtLeast(0).toUInt(),
            lowercase = kept.getBoolean(LOWERCASE, defaults.lowercase),
            uppercase = kept.getBoolean(UPPERCASE, defaults.uppercase),
            digits = kept.getBoolean(DIGITS, defaults.digits),
            symbols = kept.getBoolean(SYMBOLS, defaults.symbols),
            avoidLookAlike = kept.getBoolean(AVOID_LOOK_ALIKE, defaults.avoidLookAlike),
        )
        return options.takeIf(::allowed) ?: defaults
    }

    fun set(context: Context, options: PasswordOptions) {
        require(allowed(options))
        context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE).edit()
            .putInt(LENGTH, options.length.toInt())
            .putBoolean(LOWERCASE, options.lowercase)
            .putBoolean(UPPERCASE, options.uppercase)
            .putBoolean(DIGITS, options.digits)
            .putBoolean(SYMBOLS, options.symbols)
            .putBoolean(AVOID_LOOK_ALIKE, options.avoidLookAlike)
            .apply()
    }

    /** Back to the shared code's choice: for tests. */
    internal fun forget(context: Context) {
        context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE).edit()
            .remove(LENGTH).remove(LOWERCASE).remove(UPPERCASE).remove(DIGITS).remove(SYMBOLS).remove(AVOID_LOOK_ALIKE)
            .commit()
    }

    private fun allowed(options: PasswordOptions) =
        options.length.toInt() in LENGTHS && (options.lowercase || options.uppercase || options.digits || options.symbols)
}

/**
 * The generator's choice, to change: the length, the kinds of characters,
 * the last of which cannot be turned off, and the look-alikes. The length
 * is given to [onChange] once the slider is let go.
 */
@Composable
fun GeneratorOptions(options: PasswordOptions, onChange: (PasswordOptions) -> Unit) {
    var length by remember(options.length) { mutableFloatStateOf(options.length.toFloat()) }
    val kinds = listOf(
        Triple("A–Z", options.uppercase) { on: Boolean -> options.copy(uppercase = on) },
        Triple("a–z", options.lowercase) { on: Boolean -> options.copy(lowercase = on) },
        Triple("0–9", options.digits) { on: Boolean -> options.copy(digits = on) },
        Triple("!@#$", options.symbols) { on: Boolean -> options.copy(symbols = on) },
    )
    val chosen = kinds.count { it.second }
    Column(Modifier.fillMaxWidth().testTag("generator-options"), verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text("Length ${length.roundToInt()}", style = MaterialTheme.typography.labelLarge, modifier = Modifier.testTag("generator-length-shown"))
        Slider(
            value = length,
            onValueChange = { length = it },
            onValueChangeFinished = { onChange(options.copy(length = length.roundToInt().toUInt())) },
            valueRange = Generator.LENGTHS.first.toFloat()..Generator.LENGTHS.last.toFloat(),
            steps = Generator.LENGTHS.last - Generator.LENGTHS.first - 1,
            modifier = Modifier.testTag("generator-length"),
        )
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            kinds.forEach { (label, on, with) ->
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(
                        checked = on,
                        onCheckedChange = { onChange(with(it)) },
                        enabled = !(on && chosen == 1),
                        modifier = Modifier.testTag("generator-kind:$label"),
                    )
                    Text(label)
                }
            }
        }
        Row(verticalAlignment = Alignment.CenterVertically) {
            Checkbox(
                checked = options.avoidLookAlike,
                onCheckedChange = { onChange(options.copy(avoidLookAlike = it)) },
                modifier = Modifier.testTag("generator-avoid-look-alike"),
            )
            Text("Avoid look-alikes: l I 1 O 0")
        }
    }
}

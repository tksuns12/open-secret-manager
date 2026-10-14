package org.opensecretmanager.app

import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.google.zxing.BinaryBitmap
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.ReaderException
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/** How every invitation's text begins (`crates/vault-peer/src/pairing.rs`). */
private const val INVITATION_PREFIX = "OSM-PAIR1-"

/**
 * The text of a QR code in a frame of brightness values, one byte a pixel,
 * `rowWidth` bytes a row of which the first `width` are the frame's; null
 * when no QR code can be read there. A code turned in the frame, as a
 * camera's sensor gives it, reads the same.
 */
fun decodeQr(luminance: ByteArray, rowWidth: Int, width: Int, height: Int): String? {
    val source = PlanarYUVLuminanceSource(luminance, rowWidth, height, 0, 0, width, height, false)
    return try {
        QRCodeReader().decode(BinaryBitmap(HybridBinarizer(source))).text
    } catch (_: ReaderException) {
        null
    }
}

/** The text of a QR code in a camera frame, from its brightness plane. */
private fun decodeFrame(image: ImageProxy): String? {
    val plane = image.planes[0]
    val bytes = ByteArray(plane.rowStride * image.height)
    val buffer = plane.buffer
    buffer.get(bytes, 0, minOf(buffer.remaining(), bytes.size))
    return decodeQr(bytes, plane.rowStride, image.width, image.height)
}

/**
 * The camera, reading the QR code of an invitation that a computer shows:
 * its frames go to [decodeQr] in memory, one at a time, and none is kept.
 * The first invitation read goes to [onInvitation], once; another QR code is
 * said not to be one, and the camera reads on.
 */
@Composable
fun ScanInvitation(onInvitation: (String) -> Unit, onCancel: () -> Unit, onFailed: () -> Unit) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    val previewView = remember { PreviewView(context) }
    var notInvitation by remember { mutableStateOf(false) }
    Column(Modifier.fillMaxSize().padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("Scan the QR code", style = MaterialTheme.typography.titleLarge)
        Text("Point the camera at the QR code on your computer.", style = MaterialTheme.typography.bodyMedium)
        AndroidView(factory = { previewView }, modifier = Modifier.fillMaxWidth().aspectRatio(3f / 4f).testTag("scan-preview"))
        if (notInvitation) {
            Text(
                "That QR code is not an invitation",
                color = MaterialTheme.colorScheme.error,
                modifier = Modifier.testTag("scan-not-invitation"),
            )
        }
        OutlinedButton(onClick = onCancel, modifier = Modifier.testTag("scan-cancel")) { Text("Cancel") }
    }
    DisposableEffect(lifecycleOwner) {
        val main = ContextCompat.getMainExecutor(context)
        val frames = Executors.newSingleThreadExecutor()
        val read = AtomicBoolean(false)
        val providing = ProcessCameraProvider.getInstance(context)
        var provider: ProcessCameraProvider? = null
        var gone = false
        providing.addListener({
            if (gone) return@addListener
            try {
                val cameras = providing.get().also { provider = it }
                val preview = Preview.Builder().build().also { it.setSurfaceProvider(previewView.surfaceProvider) }
                val analysis = ImageAnalysis.Builder()
                    .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                    .build()
                analysis.setAnalyzer(frames) { image ->
                    val text = image.use { if (read.get()) null else decodeFrame(it) }?.trim() ?: return@setAnalyzer
                    if (!text.startsWith(INVITATION_PREFIX)) {
                        main.execute { notInvitation = true }
                    } else if (read.compareAndSet(false, true)) {
                        main.execute { onInvitation(text) }
                    }
                }
                val camera = if (cameras.hasCamera(CameraSelector.DEFAULT_BACK_CAMERA)) {
                    CameraSelector.DEFAULT_BACK_CAMERA
                } else {
                    CameraSelector.DEFAULT_FRONT_CAMERA
                }
                cameras.unbindAll()
                cameras.bindToLifecycle(lifecycleOwner, camera, preview, analysis)
            } catch (_: Exception) {
                onFailed()
            }
        }, main)
        onDispose {
            gone = true
            provider?.unbindAll()
            frames.shutdown()
        }
    }
}

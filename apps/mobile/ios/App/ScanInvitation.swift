import AVFoundation
import SwiftUI

/// How every invitation's text begins (`crates/vault-peer/src/pairing.rs`).
private let invitationPrefix = "OSM-PAIR1-"

/// Whether this phone can scan an invitation, and the camera's permission.
enum InvitationScanner {
    /// A camera, or in a debug build a text the UI tests give as scanned.
    static var available: Bool {
        #if DEBUG
        if TestSupport.scanned != nil { return true }
        #endif
        return AVCaptureDevice.default(for: .video) != nil
    }

    /// Asks for the camera the first time; whether it may be used.
    static func mayUseCamera() async -> Bool {
        #if DEBUG
        if TestSupport.scanned != nil { return true }
        #endif
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized: return true
        case .notDetermined: return await AVCaptureDevice.requestAccess(for: .video)
        default: return false
        }
    }
}

/// The camera, reading the QR code of an invitation that a computer shows.
/// AVFoundation reads the codes; no frame is kept. The first invitation read
/// goes to `onInvitation`, once; another QR code is said not to be one, and
/// the camera reads on.
struct ScanInvitation: View {
    let onInvitation: (String) -> Void
    let onCancel: () -> Void
    @State private var notInvitation = false

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Scan the QR code").font(.title2)
            Text("Point the camera at the QR code on your computer.")
            preview
                .aspectRatio(3.0 / 4.0, contentMode: .fit)
                .frame(maxWidth: .infinity)
                .accessibilityIdentifier("scan-preview")
            if notInvitation {
                Text("That QR code is not an invitation")
                    .foregroundStyle(.red)
                    .accessibilityIdentifier("scan-not-invitation")
            }
            Button("Cancel", action: onCancel)
                .buttonStyle(.bordered)
                .accessibilityIdentifier("scan-cancel")
        }
        .padding(24)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }

    @ViewBuilder private var preview: some View {
        #if DEBUG
        if let text = TestSupport.scanned {
            Color.black.onAppear { _ = read(text) }
        } else {
            CameraView(onCode: read)
        }
        #else
        CameraView(onCode: read)
        #endif
    }

    /// Takes `text` if it is an invitation; whether the camera may stop.
    private func read(_ text: String) -> Bool {
        let text = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard text.hasPrefix(invitationPrefix) else {
            notInvitation = true
            return false
        }
        onInvitation(text)
        return true
    }
}

/// The back camera's picture, with its QR codes given to `onCode` until it
/// takes one.
private struct CameraView: UIViewRepresentable {
    let onCode: (String) -> Bool

    func makeCoordinator() -> Coordinator { Coordinator(onCode: onCode) }

    func makeUIView(context: Context) -> PreviewView {
        let view = PreviewView()
        view.previewLayer.session = context.coordinator.session
        view.previewLayer.videoGravity = .resizeAspectFill
        context.coordinator.start()
        return view
    }

    func updateUIView(_ view: PreviewView, context: Context) {
        context.coordinator.onCode = onCode
    }

    static func dismantleUIView(_ view: PreviewView, coordinator: Coordinator) {
        coordinator.stop()
    }

    final class PreviewView: UIView {
        override class var layerClass: AnyClass { AVCaptureVideoPreviewLayer.self }
        var previewLayer: AVCaptureVideoPreviewLayer { layer as! AVCaptureVideoPreviewLayer }
    }

    final class Coordinator: NSObject, AVCaptureMetadataOutputObjectsDelegate {
        let session = AVCaptureSession()
        var onCode: (String) -> Bool
        private var taken = false
        /// The session is set up and started off the main thread, as it blocks.
        private let queue = DispatchQueue(label: "org.opensecretmanager.app.scan")

        init(onCode: @escaping (String) -> Bool) {
            self.onCode = onCode
        }

        func start() {
            queue.async { [self] in
                guard let camera = AVCaptureDevice.default(for: .video),
                      let input = try? AVCaptureDeviceInput(device: camera) else { return }
                let output = AVCaptureMetadataOutput()
                session.beginConfiguration()
                guard session.canAddInput(input), session.canAddOutput(output) else {
                    session.commitConfiguration()
                    return
                }
                session.addInput(input)
                session.addOutput(output)
                output.setMetadataObjectsDelegate(self, queue: .main)
                output.metadataObjectTypes = [.qr]
                session.commitConfiguration()
                session.startRunning()
            }
        }

        func stop() {
            queue.async { [session] in session.stopRunning() }
        }

        func metadataOutput(_ output: AVCaptureMetadataOutput, didOutput objects: [AVMetadataObject], from connection: AVCaptureConnection) {
            guard !taken else { return }
            for case let code as AVMetadataMachineReadableCodeObject in objects {
                if let text = code.stringValue, onCode(text) {
                    taken = true
                    stop()
                    return
                }
            }
        }
    }
}

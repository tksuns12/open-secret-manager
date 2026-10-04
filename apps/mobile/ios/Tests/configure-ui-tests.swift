// Writes the configuration XCTest's runner reads to run UI tests, as Xcode
// does when it runs them itself. scripts/test-mobile.sh runs the UI tests
// this way in a simulator of its own device set, which xcodebuild cannot
// use. Run inside the simulator, with XCTEST_FRAMEWORK naming the runner's
// XCTest and AUTOMATION_FRAMEWORK its XCTAutomationSupport:
//
//   configure-ui-tests <test bundle> <app> <app's bundle ID> <output> [Class or Class/method ...]
import Foundation

guard let framework = ProcessInfo.processInfo.environment["XCTEST_FRAMEWORK"], dlopen(framework, RTLD_NOW) != nil else {
    print("cannot load XCTest: \(String(cString: dlerror()))")
    exit(1)
}

func make(_ name: String, _ initializer: String, _ arguments: [Any]) -> NSObject {
    let cls = NSClassFromString(name) as! NSObject.Type
    let object = cls.perform(NSSelectorFromString("alloc")).takeUnretainedValue()
    let selector = NSSelectorFromString(initializer)
    switch arguments.count {
    case 1: return object.perform(selector, with: arguments[0]).takeUnretainedValue() as! NSObject
    default: return object.perform(selector, with: arguments[0], with: arguments[1]).takeUnretainedValue() as! NSObject
    }
}

let arguments = CommandLine.arguments
let configuration = (NSClassFromString("XCTestConfiguration") as! NSObject.Type).init()
configuration.setValue(URL(fileURLWithPath: arguments[1]), forKey: "testBundleURL")
configuration.setValue(UUID(), forKey: "sessionIdentifier")
configuration.setValue(false, forKey: "reportResultsToIDE")
configuration.setValue(false, forKey: "testsDrivenByIDE")
configuration.setValue(true, forKey: "initializeForUITesting")
configuration.setValue(arguments[2], forKey: "targetApplicationPath")
configuration.setValue(arguments[3], forKey: "targetApplicationBundleID")
configuration.setValue(URL(fileURLWithPath: arguments[1]).deletingPathExtension().lastPathComponent, forKey: "productModuleName")
configuration.setValue(ProcessInfo.processInfo.environment["AUTOMATION_FRAMEWORK"], forKey: "automationFrameworkPath")
let selected = arguments.dropFirst(5).map { test -> NSObject in
    let parts = test.split(separator: "/").map(String.init)
    return parts.count == 2
        ? make("XCTTestIdentifier", "initWithClassName:methodName:", parts)
        : make("XCTTestIdentifier", "initWithClassName:", parts)
}
if !selected.isEmpty {
    configuration.setValue(make("XCTTestIdentifierSet", "initWithArray:", [selected]), forKey: "testsToRun")
}
try NSKeyedArchiver.archivedData(withRootObject: configuration, requiringSecureCoding: false)
    .write(to: URL(fileURLWithPath: arguments[4]))

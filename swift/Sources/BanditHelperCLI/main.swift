import BanditCore
import Foundation

let args = Array(CommandLine.arguments.dropFirst())
do {
    try App().run(args)
} catch {
    let msg: String
    if let e = error as? BanditError { msg = e.message }
    else { msg = "\(error)" }
    FileHandle.standardError.write("error: \(msg)\n".data(using: .utf8) ?? Data())
    exit(1)
}

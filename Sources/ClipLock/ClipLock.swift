import AppKit
import CryptoKit
import Security
import ServiceManagement

// MARK: - Errors

enum VaultError: Error, CustomStringConvertible {
    case random
    case badKey
    case keychain(OSStatus)

    var description: String {
        switch self {
        case .random: return "could not generate a random key"
        case .badKey:
            return "the Keychain entry \"ClipLock\" is not a valid key. Delete it in Keychain Access"
        case .keychain(let status):
            let text = SecCopyErrorMessageString(status, nil) as String? ?? "unknown error"
            return "Keychain error \(status): \(text)"
        }
    }
}

// MARK: - Encryption key (stored in the login Keychain, never on disk in plain text)

enum KeyStore {
    static let service = "ClipLock"
    static let account = "history-key"

    static func loadOrCreateKey() throws -> SymmetricKey {
        if let data = try readKey() {
            return SymmetricKey(data: data)
        }
        var bytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            throw VaultError.random
        }
        let data = Data(bytes)
        try writeKey(data)
        return SymmetricKey(data: data)
    }

    static func readKey() throws -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data else {
            throw VaultError.keychain(status)
        }
        // A key of any other length would make every save fail, so refuse it up front.
        guard data.count == 32 else { throw VaultError.badKey }
        return data
    }

    static func writeKey(_ data: Data) throws {
        let attributes: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        let status = SecItemAdd(attributes as CFDictionary, nil)
        guard status == errSecSuccess else { throw VaultError.keychain(status) }
    }

    // Deleting the key makes any encrypted history file unreadable, even if a copy exists.
    @discardableResult
    static func deleteKey() -> OSStatus {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        return SecItemDelete(query as CFDictionary)
    }
}

// MARK: - Encrypted history store

struct ClipItem: Codable {
    let id: UUID
    let text: String
    let date: Date
}

final class Vault {
    private let fileURL: URL
    private let directory: URL
    private var key: SymmetricKey?
    private(set) var items: [ClipItem] = []

    // Shown in the menu when something needs the user's attention.
    private(set) var notice: String?

    // Every save rewrites the whole file, so both the number of entries and the total size are capped.
    let maxItems = 200
    let maxBytes = 10_000_000        // the largest single copy that is kept
    let maxTotalBytes = 50_000_000   // all saved text together
    // Search looks at this many characters of each entry, so typing stays quick however big the history is.
    static let searchLimit = 20_000

    // Set when older entries were dropped to make room for a large copy, so the menu can say so.
    private(set) var lastMadeRoom: (count: Int, at: Date)?

    var totalBytes: Int { items.reduce(0) { $0 + $1.text.utf8.count } }

    // Encrypting and writing the file happens here, never on the main thread.
    private let queue = DispatchQueue(label: "cliplock.save", qos: .utility)
    private var pendingSave: DispatchWorkItem?

    // Set while a copy of the history cannot be replaced safely, so it is never overwritten.
    private var saveBlocked = false
    // When the oldest unsaved change was made, so steady copying cannot postpone saving forever.
    private var dirtySince: Date?
    private let maxSaveDelay: TimeInterval = 10

    private static let setAsidePrefix = "history.enc.unreadable-"

    init() throws {
        let support = try FileManager.default.url(
            for: .applicationSupportDirectory, in: .userDomainMask,
            appropriateFor: nil, create: true)
        directory = support.appendingPathComponent("ClipLock", isDirectory: true)
        try FileManager.default.createDirectory(
            at: directory, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        // Tighten permissions even if the folder already existed.
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o700], ofItemAtPath: directory.path)
        // Keep the history out of Time Machine and other backups, which would also copy the key.
        var folder = directory
        var excluded = URLResourceValues()
        excluded.isExcludedFromBackup = true
        try? folder.setResourceValues(excluded)
        fileURL = directory.appendingPathComponent("history.enc")

        key = try KeyStore.loadOrCreateKey()
        loadExisting()
    }

    // A file that can't be read is moved aside, never overwritten, so a temporary
    // problem (wrong key, damaged file) can't destroy the saved history.
    private func loadExisting() {
        guard FileManager.default.fileExists(atPath: fileURL.path), let key else { return }
        do {
            let blob = try Data(contentsOf: fileURL)
            let box = try AES.GCM.SealedBox(combined: blob)
            let plain = try AES.GCM.open(box, using: key)
            let loaded = try JSONDecoder().decode([ClipItem].self, from: plain)
            // Apply the same limits as when saving.
            items = Array(loaded.filter { $0.text.utf8.count <= maxBytes }.prefix(maxItems))
            trimToLimits()
        } catch {
            let stamp = "\(Int(Date().timeIntervalSince1970 * 1000))-\(UUID().uuidString.prefix(8))"
            let aside = directory.appendingPathComponent("\(Vault.setAsidePrefix)\(stamp)")
            do {
                try FileManager.default.moveItem(at: fileURL, to: aside)
                notice = "Earlier history could not be decrypted. The old file was set aside."
            } catch {
                // Saving now would overwrite the unreadable file, so don't save until it is resolved.
                saveBlocked = true
                notice = "Earlier history could not be read and could not be set aside. History will not be saved. Use Clear History to start over."
            }
        }
    }

    func add(_ text: String) {
        if items.first?.text == text { return }
        if key == nil { key = try? KeyStore.loadOrCreateKey() }
        items.removeAll { $0.text == text }
        items.insert(ClipItem(id: UUID(), text: text, date: Date()), at: 0)
        let droppedForSize = trimToLimits()
        if droppedForSize > 0 {
            // A burst of large copies adds up, instead of showing only the last one.
            let earlier = lastMadeRoom.map { Date().timeIntervalSince($0.at) < 120 ? $0.count : 0 } ?? 0
            lastMadeRoom = (earlier + droppedForSize, Date())
        }
        scheduleSave()
    }

    // Drops the oldest entries until both limits are met. The newest entry is always kept.
    // Returns how many were dropped because of the total size, not the number of entries.
    @discardableResult
    private func trimToLimits() -> Int {
        if items.count > maxItems { items.removeLast(items.count - maxItems) }
        var total = totalBytes
        var droppedForSize = 0
        while total > maxTotalBytes, items.count > 1 {
            total -= items.removeLast().text.utf8.count
            droppedForSize += 1
        }
        return droppedForSize
    }

    // Waits briefly so a burst of copies causes one write instead of many.
    private func scheduleSave() {
        guard !saveBlocked else { return }
        pendingSave?.cancel()
        let snapshot = items
        let key = self.key
        let url = fileURL
        if dirtySince == nil { dirtySince = Date() }
        let waited = Date().timeIntervalSince(dirtySince ?? Date())
        let work = DispatchWorkItem { [weak self] in
            Vault.write(snapshot, key: key, to: url)
            DispatchQueue.main.async { self?.dirtySince = nil }
        }
        pendingSave = work
        queue.asyncAfter(deadline: .now() + (waited >= maxSaveDelay ? 0 : 1.0), execute: work)
    }

    // Called on quit so a copy made in the last second isn't lost.
    func flush() {
        pendingSave?.cancel()
        pendingSave = nil
        guard !items.isEmpty, !saveBlocked else { return }
        let snapshot = items
        let key = self.key
        let url = fileURL
        queue.sync { Vault.write(snapshot, key: key, to: url) }
    }

    private static func write(_ items: [ClipItem], key: SymmetricKey?, to url: URL) {
        guard let key else {
            NSLog("ClipLock: no encryption key, history was not saved")
            return
        }
        do {
            let plain = try JSONEncoder().encode(items)
            guard let combined = try AES.GCM.seal(plain, using: key).combined else { return }
            try combined.write(to: url, options: .atomic)
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o600], ofItemAtPath: url.path)
        } catch {
            NSLog("ClipLock: could not save history: \(error)")
        }
    }

    // Deletes the history file (and any set-aside files) and the key. A new key is made
    // on the next copy. Returns a message if anything could not be removed.
    func clearAll() -> String? {
        pendingSave?.cancel()
        pendingSave = nil
        items.removeAll()
        notice = nil
        lastMadeRoom = nil
        saveBlocked = false
        dirtySince = nil
        queue.sync {}  // let any write already in progress finish before deleting

        var problems: [String] = []
        let fm = FileManager.default
        let names = (try? fm.contentsOfDirectory(atPath: directory.path)) ?? []
        for name in names where name == "history.enc" || name.hasPrefix(Vault.setAsidePrefix) {
            do {
                // `name` is a file name read from our own folder, filtered to two known patterns.
                try fm.removeItem(at: directory.appendingPathComponent(name))  // nosemgrep: swift-path-traversal-append
            } catch {
                problems.append("could not delete \(name)")
            }
        }
        let status = KeyStore.deleteKey()
        if status != errSecSuccess && status != errSecItemNotFound {
            problems.append("could not delete the encryption key")
        }
        key = nil
        return problems.isEmpty ? nil : problems.joined(separator: "; ") + "."
    }
}

// MARK: - Likely-secret detection

// Best-effort check for text that looks like a credential. It cannot catch everything. In
// particular an ordinary short password looks like any other word, so it is not recognised.
enum SecretDetector {
    private static let patterns: [NSRegularExpression] = {
        let sources = [
            #"-----BEGIN [A-Z ]*PRIVATE KEY-----"#,
            #"\beyJ[A-Za-z0-9_-]{8,1024}\.[A-Za-z0-9_-]{8,1024}\.[A-Za-z0-9_-]{4,}"#,  // JWT (bounded, so it cannot run away)
            #"\bAKIA[0-9A-Z]{16}\b"#,  // AWS access key ID
            #"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}"#,  // GitHub tokens
            #"\bgithub_pat_[A-Za-z0-9_]{30,}"#,
            #"\bglpat-[A-Za-z0-9_-]{16,}"#,  // GitLab
            #"\bsk-[A-Za-z0-9_-]{20,}"#,  // common API secret keys
            #"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}"#,  // Stripe
            #"\bxox[abprs]-[A-Za-z0-9-]{10,}"#,  // Slack
            #"\bAIza[0-9A-Za-z_-]{35}\b"#,  // Google API key
            #"\bnpm_[A-Za-z0-9]{30,}"#,
            #"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{20,}"#,
            #"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)\b\s*[:=]\s*\S{6,}"#,
        ]
        return sources.compactMap { try? NSRegularExpression(pattern: $0) }
    }()

    static func looksLikeSecret(_ text: String) -> Bool {
        // Very long text: look at the start and the end, where a pasted key usually is.
        // The size is checked in bytes: counting characters would read all of a very long text.
        let sample = text.utf8.count > 20_000
            ? String(text.prefix(10_000)) + "\n" + String(text.suffix(10_000))
            : text
        let range = NSRange(sample.startIndex..., in: sample)
        for pattern in patterns where pattern.firstMatch(in: sample, range: range) != nil {
            return true
        }
        return looksLikeRandomToken(text)
    }

    // The first few characters followed by dots. The dot count is fixed so the length is not revealed.
    static func masked(_ text: String) -> String {
        // Skips leading white space without copying the whole text.
        let start = text.firstIndex(where: { !$0.isWhitespace }) ?? text.endIndex
        let head = String(text[start...].prefix(5))
            .replacingOccurrences(of: "\n", with: " ")
            .replacingOccurrences(of: "\r", with: " ")
            .replacingOccurrences(of: "\t", with: " ")
        return head + "••••••••"
    }

    // A single long run of mixed letters and digits with no spaces, like a generated token.
    private static func looksLikeRandomToken(_ text: String) -> Bool {
        // Find the trimmed text without copying all of a long text. A token this short is under 800 bytes.
        guard let first = text.firstIndex(where: { !$0.isWhitespace }),
              let last = text.lastIndex(where: { !$0.isWhitespace }),
              text.utf8.distance(from: first, to: last) <= 800 else { return false }
        let s = String(text[first...last])
        guard s.count >= 24, s.count <= 200, !s.contains(where: { $0.isWhitespace }) else { return false }
        guard !s.contains("://"), !s.hasPrefix("/"), !s.hasPrefix("~") else { return false }  // URLs and paths
        guard s.contains(where: { $0.isLowercase }),
              s.contains(where: { $0.isUppercase }),
              s.contains(where: { $0.isNumber }) else { return false }
        var counts: [Character: Int] = [:]
        for c in s { counts[c, default: 0] += 1 }
        let n = Double(s.count)
        let entropy = counts.values.reduce(0.0) { $0 - (Double($1) / n) * log2(Double($1) / n) }
        return entropy >= 4.0
    }
}

// MARK: - Search box row

// Holds the search box. The box is plain until the user clicks it. Then it takes keyboard focus and
// shows a cursor and an outline.
//
// A menu window never becomes the active window, so macOS does not draw the blinking text cursor
// in a box inside a menu. This row draws its own cursor and an outline in the accent colour, so it
// is clear that the box is selected and ready for typing.
final class SearchRowView: NSView {
    var onAttach: (() -> Void)?
    private weak var field: NSSearchField?
    private let caret = NSView()
    private var blinkTimer: Timer?
    private(set) var isActive = false

    override init(frame: NSRect) {
        super.init(frame: frame)
        caret.wantsLayer = true
        caret.layer?.backgroundColor = NSColor.labelColor.cgColor
        caret.isHidden = true
        NotificationCenter.default.addObserver(
            self, selector: #selector(selectionChanged(_:)),
            name: NSTextView.didChangeSelectionNotification, object: nil)
    }

    required init?(coder: NSCoder) { fatalError("not used") }

    deinit {
        NotificationCenter.default.removeObserver(self)
        blinkTimer?.invalidate()
    }

    func attach(_ field: NSSearchField) {
        self.field = field
        addSubview(field)
        addSubview(caret)  // above the box
    }

    // Turns the cursor and outline on or off.
    func setActive(_ on: Bool) {
        isActive = on
        needsDisplay = true
        blinkTimer?.invalidate()
        blinkTimer = nil
        guard on else {
            caret.isHidden = true
            return
        }
        updateCaret()
        let timer = Timer(timeInterval: 0.55, repeats: true) { [weak self] _ in
            guard let self, self.isActive else { return }
            self.caret.isHidden.toggle()
        }
        RunLoop.main.add(timer, forMode: .common)  // also runs while the menu is open
        blinkTimer = timer
    }

    @objc private func selectionChanged(_ note: Notification) {
        guard isActive, let editor = field?.currentEditor(), note.object as AnyObject? === editor else { return }
        updateCaret()
    }

    // Places the cursor after the last typed character, and shows it straight away.
    private func updateCaret() {
        guard isActive, let field else { return }
        guard let editor = field.currentEditor() as? NSTextView,
              let layout = editor.layoutManager, let container = editor.textContainer
        else {
            // Nothing typed yet and no editor: put it where the text will start.
            caret.frame = NSRect(x: field.frame.minX + 26, y: field.frame.minY + 4, width: 1.5, height: field.frame.height - 8)
            caret.isHidden = false
            return
        }
        let origin = editor.textContainerOrigin
        let position = min(editor.selectedRange().location, layout.numberOfGlyphs)
        var x = origin.x
        if position > 0 {
            x += layout.boundingRect(forGlyphRange: NSRange(location: 0, length: position), in: container).maxX
        }
        let height = max(10, editor.bounds.height - origin.y * 2)
        caret.frame = convert(NSRect(x: x, y: origin.y, width: 1.5, height: height), from: editor)
        caret.isHidden = false
    }

    override func draw(_ dirtyRect: NSRect) {
        guard isActive, let field else { return }
        NSColor.controlAccentColor.setStroke()
        let path = NSBezierPath(roundedRect: field.frame.insetBy(dx: -1, dy: -1), xRadius: 13, yRadius: 13)
        path.lineWidth = 2
        path.stroke()
    }

    // Clicking the row around the box gives the box focus.
    override func mouseDown(with event: NSEvent) { onAttach?() }
    override var acceptsFirstResponder: Bool { true }
}

// The search box itself. It tells the row when it gains focus, so the cursor and outline appear
// when the user clicks into it, and only then.
final class SearchBoxField: NSSearchField {
    var onFocus: (() -> Void)?

    override func becomeFirstResponder() -> Bool {
        let accepted = super.becomeFirstResponder()
        if accepted { onFocus?() }
        return accepted
    }
}

// MARK: - Menu row for a hidden secret

// A menu row with an eye button on the right. Clicking the eye shows or hides just this entry and
// keeps the menu open. Clicking anywhere else on the row copies the entry, like any other row.
final class SecretRowView: NSView {
    private let label = NSTextField(labelWithString: "")
    private let eyeButton = NSButton()
    private var highlighted = false {
        didSet {
            needsDisplay = true
            updateColors()
        }
    }
    private(set) var isRevealed = false
    var onCopy: (() -> Void)?
    var onToggle: (() -> Void)?

    var shownText: String { label.stringValue }

    init(text: String, revealed: Bool) {
        super.init(frame: NSRect(x: 0, y: 0, width: 320, height: 22))
        autoresizingMask = [.width]
        label.font = NSFont.menuFont(ofSize: 0)
        label.lineBreakMode = .byTruncatingTail
        addSubview(label)

        eyeButton.isBordered = false
        eyeButton.imagePosition = .imageOnly
        eyeButton.target = self
        eyeButton.action = #selector(eyeClicked)
        addSubview(eyeButton)

        addTrackingArea(NSTrackingArea(
            rect: .zero, options: [.mouseEnteredAndExited, .activeAlways, .inVisibleRect],
            owner: self, userInfo: nil))
        update(text: text, revealed: revealed)
    }

    required init?(coder: NSCoder) { fatalError("not used") }

    func update(text: String, revealed: Bool) {
        isRevealed = revealed
        label.stringValue = text
        eyeButton.image = NSImage(
            systemSymbolName: revealed ? "eye.slash" : "eye",
            accessibilityDescription: revealed ? "Hide this value" : "Show this value")
        updateColors()
    }

    private func updateColors() {
        label.textColor = highlighted ? .white : .labelColor
        eyeButton.contentTintColor = highlighted ? .white : .secondaryLabelColor
    }

    override func layout() {
        super.layout()
        label.frame = NSRect(x: 14, y: (bounds.height - 17) / 2, width: max(0, bounds.width - 14 - 40), height: 17)
        eyeButton.frame = NSRect(x: bounds.width - 34, y: 1, width: 24, height: bounds.height - 2)
    }

    override func draw(_ dirtyRect: NSRect) {
        guard highlighted else { return }
        NSColor.selectedContentBackgroundColor.setFill()
        NSBezierPath(roundedRect: bounds.insetBy(dx: 5, dy: 0), xRadius: 5, yRadius: 5).fill()
    }

    override func mouseEntered(with event: NSEvent) { highlighted = true }
    override func mouseExited(with event: NSEvent) { highlighted = false }
    override var acceptsFirstResponder: Bool { false }
    override func acceptsFirstMouse(for event: NSEvent?) -> Bool { true }
    override func mouseDown(with event: NSEvent) {}  // the copy happens on mouse up
    override func mouseUp(with event: NSEvent) { onCopy?() }

    @objc private func eyeClicked() { onToggle?() }
}

// MARK: - Menu row that does not close the menu

// A menu row for settings and toggles. Standard menu items always close the menu when clicked,
// so these rows handle the click themselves and the menu stays open until a saved entry is chosen.
final class ToggleRowView: NSView {
    private let iconView = NSImageView()
    private let label = NSTextField(labelWithString: "")
    private let iconX: CGFloat
    private let labelX: CGFloat
    private var highlighted = false {
        didSet {
            needsDisplay = true
            updateColors()
        }
    }
    private(set) var isEnabledRow = true
    private(set) var hasImage = false
    var onClick: (() -> Void)?

    var shownTitle: String { label.stringValue }

    init(iconX: CGFloat, labelX: CGFloat) {
        self.iconX = iconX
        self.labelX = labelX
        super.init(frame: NSRect(x: 0, y: 0, width: 280, height: 22))
        autoresizingMask = [.width]
        label.font = NSFont.menuFont(ofSize: 0)
        label.lineBreakMode = .byTruncatingTail
        iconView.imageScaling = .scaleProportionallyDown
        addSubview(iconView)
        addSubview(label)
        addTrackingArea(NSTrackingArea(
            rect: .zero, options: [.mouseEnteredAndExited, .activeAlways, .inVisibleRect],
            owner: self, userInfo: nil))
    }

    required init?(coder: NSCoder) { fatalError("not used") }

    func update(title: String, image: NSImage?, enabled: Bool) {
        label.stringValue = title
        iconView.image = image
        hasImage = image != nil
        isEnabledRow = enabled
        if !enabled { highlighted = false }
        updateColors()
    }

    private func updateColors() {
        let active = highlighted && isEnabledRow
        label.textColor = !isEnabledRow ? .disabledControlTextColor : (active ? .white : .labelColor)
        iconView.contentTintColor = !isEnabledRow ? .disabledControlTextColor : (active ? .white : .labelColor)
    }

    override func layout() {
        super.layout()
        iconView.frame = NSRect(x: iconX, y: (bounds.height - 16) / 2, width: 16, height: 16)
        label.frame = NSRect(x: labelX, y: (bounds.height - 17) / 2, width: max(0, bounds.width - labelX - 12), height: 17)
    }

    override func draw(_ dirtyRect: NSRect) {
        guard highlighted && isEnabledRow else { return }
        NSColor.selectedContentBackgroundColor.setFill()
        NSBezierPath(roundedRect: bounds.insetBy(dx: 5, dy: 0), xRadius: 5, yRadius: 5).fill()
    }

    override func mouseEntered(with event: NSEvent) { highlighted = true }
    override func mouseExited(with event: NSEvent) { highlighted = false }
    override var acceptsFirstResponder: Bool { false }
    override func acceptsFirstMouse(for event: NSEvent?) -> Bool { true }
    override func mouseDown(with event: NSEvent) {}  // the action happens on mouse up
    override func mouseUp(with event: NSEvent) {
        if isEnabledRow { onClick?() }
    }
}

// MARK: - App

final class AppDelegate: NSObject, NSApplicationDelegate, NSMenuDelegate, NSSearchFieldDelegate {
    private var statusItem: NSStatusItem!
    private var vault: Vault?
    private var vaultError: String?
    private var timer: Timer?
    private var activity: NSObjectProtocol?
    private var lastChangeCount = NSPasteboard.general.changeCount
    private var paused = false
    private var ticksSinceRetry = 0
    private var opening = false
    private var lastSkippedSecretAt: Date?
    private var lastSkippedLarge: (bytes: Int, at: Date)?

    private enum SecretMode { case skip, hide, show }

    // Two settings that exclude each other. With neither on, likely secrets are saved and shown in full.
    // Only on/off values are stored here, never a secret.
    private var skipLikelySecrets: Bool {
        get { UserDefaults.standard.object(forKey: "skipLikelySecrets") as? Bool ?? false }
        set { UserDefaults.standard.set(newValue, forKey: "skipLikelySecrets") }  // nosemgrep: swift-cleartext-storage-preferences
    }
    private var hideLikelySecrets: Bool {
        get { UserDefaults.standard.object(forKey: "hideLikelySecrets") as? Bool ?? true }
        set { UserDefaults.standard.set(newValue, forKey: "hideLikelySecrets") }  // nosemgrep: swift-cleartext-storage-preferences
    }

    // Skip wins, so an older stored "skip" setting keeps working and both can never be active.
    private var secretMode: SecretMode {
        if skipLikelySecrets { return .skip }
        return hideLikelySecrets ? .hide : .show
    }

    // Hidden values are shown in full until this time.
    private var revealUntil: Date?
    private let revealSeconds: TimeInterval = 30

    // The history as drawn in the menu, kept so the search box can filter it without rebuilding.
    private struct Row {
        let id: UUID
        let title: String       // what the menu shows
        let searchable: String  // what a search is matched against (never the hidden part of a secret)
        let masked: Bool        // drawn as a hidden-secret row with an eye button
        let plain: String       // how the entry looks when its value is shown
    }
    private var rows: [Row] = []
    private var searchQuery = ""
    private var revealedIDs: Set<UUID> = []  // hidden entries whose eye was clicked, while the menu is open
    private var entriesStart = 0
    private var currentMenu: NSMenu?
    private var anySecretLooking = false
    private var secretCache: [UUID: Bool] = [:]  // an entry's text never changes, so decide once

    // Rows that stay open when clicked, kept so they can be updated in place.
    private var headerItem: NSMenuItem?
    private var pauseRow: ToggleRowView?
    private var revealRow: ToggleRowView?
    private var skipRow: ToggleRowView?
    private var hideRow: ToggleRowView?
    private var loginRow: ToggleRowView?
    private var isRevealing: Bool { (revealUntil ?? .distantPast) > Date() }

    private lazy var searchField: SearchBoxField = {
        let field = SearchBoxField(frame: NSRect(x: 12, y: 5, width: 296, height: 24))
        field.placeholderString = "Search history"
        field.delegate = self
        field.sendsSearchStringImmediately = true
        field.target = self
        field.action = #selector(searchFieldChanged(_:))  // also runs when the clear (x) button is used
        return field
    }()
    private lazy var searchContainer: SearchRowView = {
        let view = SearchRowView(frame: NSRect(x: 0, y: 0, width: 320, height: 34))
        view.attach(searchField)
        // A click on the row around the box gives the box focus. A click on the box itself does
        // the same through its own onFocus.
        searchField.onFocus = { [weak view] in view?.setActive(true) }
        view.onAttach = { [weak self, weak view] in
            DispatchQueue.main.async {
                guard let self, let view, let window = view.window else { return }
                window.makeKey()
                window.makeFirstResponder(self.searchField)
                view.setActive(true)
            }
        }
        return view
    }()

    // Password managers mark secrets with these types. Never save them.
    private let ignoredTypes: Set<String> = [
        "org.nspasteboard.ConcealedType",
        "org.nspasteboard.TransientType",
        "org.nspasteboard.AutoGeneratedType",
        "de.petermaurer.TransientPasteboardType",
        "com.agilebits.onepassword",
        "com.typeit4me.clipping",
    ]

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)

        // Only one copy at a time, otherwise two copies overwrite each other's history.
        if let id = Bundle.main.bundleIdentifier {
            let others = NSRunningApplication.runningApplications(withBundleIdentifier: id)
                .filter { $0 != NSRunningApplication.current }
            if !others.isEmpty {
                NSApp.terminate(nil)
                return
            }
        }

        // Stops macOS from slowing the polling timer while the app is idle in the background.
        activity = ProcessInfo.processInfo.beginActivity(
            options: .userInitiatedAllowingIdleSystemSleep,
            reason: "Watching the clipboard")

        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        // Use the app icon from the app bundle in the menu bar. If it cannot be loaded, fall back to a
        // system symbol that adapts to light and dark menu bars (never the blank generic app icon).
        if let icon = Bundle.main.image(forResource: "AppIcon") {
            icon.size = NSSize(width: 18, height: 18)
            statusItem.button?.image = icon
        } else {
            let symbol = NSImage(
                systemSymbolName: "lock.doc", accessibilityDescription: "ClipLock")
                ?? NSImage(systemSymbolName: "doc.on.clipboard", accessibilityDescription: "ClipLock")
            symbol?.isTemplate = true
            statusItem.button?.image = symbol
        }
        statusItem.button?.setAccessibilityLabel("ClipLock")

        let menu = NSMenu()
        menu.delegate = self
        statusItem.menu = menu

        openVault()

        let timer = Timer.scheduledTimer(withTimeInterval: 0.5, repeats: true) { [weak self] _ in
            self?.poll()
        }
        timer.tolerance = 0.1
        // Also run while a menu is open. In the default mode the timer pauses during menu
        // tracking, so a copy made with the menu open would be missed.
        RunLoop.main.add(timer, forMode: .common)
        self.timer = timer
    }

    func applicationWillTerminate(_ notification: Notification) {
        vault?.flush()
    }

    // Opening the vault reads the Keychain, which can wait on a permission dialog or a locked
    // Keychain. That happens in the background so the menu bar icon always appears, and on
    // failure it is shown in the menu and tried again.
    private func openVault() {
        guard !opening else { return }
        opening = true
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let result = Result { try Vault() }
            DispatchQueue.main.async {
                guard let self else { return }
                self.opening = false
                switch result {
                case .success(let opened):
                    self.vault = opened
                    self.vaultError = nil
                case .failure(let error):
                    self.vault = nil
                    self.vaultError = "\(error)"
                }
            }
        }
    }

    private func poll() {
        guard let vault else {
            if !opening {
                ticksSinceRetry += 1
                if ticksSinceRetry >= 20 {  // about every 10 seconds
                    ticksSinceRetry = 0
                    openVault()
                }
            }
            return
        }

        let pasteboard = NSPasteboard.general
        let current = pasteboard.changeCount
        guard current != lastChangeCount else { return }
        guard !paused else {
            lastChangeCount = current
            return
        }

        // Read the types and the text together, then make sure the clipboard did not change in
        // between. Otherwise a secret flagged as concealed could arrive after the types were checked.
        let types = pasteboard.types?.map { $0.rawValue } ?? []
        let data = pasteboard.data(forType: .string)
        guard pasteboard.changeCount == current else { return }  // changed mid-read: try again next tick
        lastChangeCount = current
        if types.contains(where: { ignoredTypes.contains($0) }) { return }

        // The size is checked before the data is turned into text. The read itself is not limited.
        guard let data else { return }
        if data.count > vault.maxBytes {
            lastSkippedLarge = (data.count, Date())
            return
        }
        guard let text = String(data: data, encoding: .utf8),
              text.contains(where: { !$0.isWhitespace }) else { return }  // stops at the first visible character
        if secretMode == .skip && SecretDetector.looksLikeSecret(text) {
            lastSkippedSecretAt = Date()
            return
        }
        vault.add(text)
    }

    func menuNeedsUpdate(_ menu: NSMenu) {
        menu.removeAllItems()
        // Each item decides for itself whether it is enabled, instead of macOS enabling anything
        // that has an action.
        menu.autoenablesItems = false
        currentMenu = menu
        searchQuery = ""
        revealedIDs = []
        searchField.stringValue = ""

        func disabled(_ title: String) -> NSMenuItem {
            let item = NSMenuItem(title: title, action: nil, keyEquivalent: "")
            item.isEnabled = false
            return item
        }

        // A settings row that does not close the menu when clicked.
        func toggleItem(iconX: CGFloat, labelX: CGFloat, _ action: @escaping () -> Void)
            -> (NSMenuItem, ToggleRowView)
        {
            let view = ToggleRowView(iconX: iconX, labelX: labelX)
            view.onClick = action
            let item = NSMenuItem()
            item.view = view
            return (item, view)
        }

        buildRows()

        // Quick search at the very top.
        let searchItem = NSMenuItem()
        searchItem.view = searchContainer
        menu.addItem(searchItem)

        // Controls come next, so they stay in reach however long the history is.
        let status: String?
        if vault == nil {
            status = vaultError.map { "Encryption key unavailable, retrying: \($0)" }
                ?? "Opening encrypted history… (approve the Keychain prompt if shown)"
        } else {
            status = vault?.notice
        }
        if let message = status { menu.addItem(disabled(message)) }
        if let skipped = lastSkippedSecretAt, Date().timeIntervalSince(skipped) < 120 {
            menu.addItem(disabled("Skipped a copy that looks like a secret (not saved)"))
        }
        if let large = lastSkippedLarge, let vault, Date().timeIntervalSince(large.at) < 120 {
            menu.addItem(disabled(
                "Skipped a \(byteString(large.bytes)) copy: over the \(byteString(vault.maxBytes)) limit (not saved)"))
        }
        if let room = vault?.lastMadeRoom, Date().timeIntervalSince(room.at) < 120 {
            let what = room.count == 1 ? "1 older entry" : "\(room.count) older entries"
            menu.addItem(disabled("Dropped \(what) to make room for a large copy"))
        }
        menu.addItem(.separator())

        let (pauseItem, pause) = toggleItem(iconX: 12, labelX: 34) { [weak self] in self?.togglePause() }
        pauseRow = pause
        menu.addItem(pauseItem)

        let (revealItem, reveal) = toggleItem(iconX: 12, labelX: 34) { [weak self] in self?.toggleReveal() }
        revealRow = reveal
        menu.addItem(revealItem)

        // Settings submenu. The two secret settings exclude each other. Neither ticked = save and
        // show everything. These rows keep the menu open.
        let settings = NSMenu()
        settings.autoenablesItems = false

        let (skipItem, skip) = toggleItem(iconX: 10, labelX: 32) { [weak self] in self?.toggleSkipSecrets() }
        skipRow = skip
        settings.addItem(skipItem)

        let (hideItem, hide) = toggleItem(iconX: 10, labelX: 32) { [weak self] in self?.toggleHideSecrets() }
        hideRow = hide
        settings.addItem(hideItem)

        settings.addItem(.separator())

        let (loginItem, login) = toggleItem(iconX: 10, labelX: 32) { [weak self] in self?.toggleLaunchAtLogin() }
        loginRow = login
        settings.addItem(loginItem)

        let settingsItem = NSMenuItem(title: "Settings", action: nil, keyEquivalent: "")
        settingsItem.submenu = settings
        menu.addItem(settingsItem)

        let helpItem = NSMenuItem(title: "Help", action: nil, keyEquivalent: "")
        helpItem.submenu = makeHelpMenu()
        menu.addItem(helpItem)

        let clearItem = NSMenuItem(
            title: "Clear History and Delete Key…",
            action: #selector(clearHistory), keyEquivalent: "")
        clearItem.target = self
        menu.addItem(clearItem)

        menu.addItem(NSMenuItem(
            title: "Quit ClipLock",
            action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q"))

        menu.addItem(.separator())

        // The title sits just above the history, with how full it is.
        let header = disabled("Clipboard History")
        headerItem = header
        menu.addItem(header)

        // The legend for the … ⏎ •••• marks lives in the Help submenu, not here.
        entriesStart = menu.items.count
        renderEntries(into: menu)
        refreshControls()
    }

    // Works out how every saved entry is drawn. Every entry is listed, and macOS scrolls the menu
    // on its own when it is taller than the screen.
    private func buildRows() {
        anySecretLooking = false
        let revealing = isRevealing
        rows = []
        // Forget entries that are no longer in the history.
        if secretCache.count > 500 {
            let current = Set((vault?.items ?? []).map { $0.id })
            secretCache = secretCache.filter { current.contains($0.key) }
        }
        for item in vault?.items ?? [] {
            // Decided here, when the menu is drawn, so entries saved earlier are covered too.
            let looksSecret = secretMode != .show && isLikelySecret(item)
            if looksSecret { anySecretLooking = true }

            let preview = String(item.text.prefix(200))
                .replacingOccurrences(of: "\n", with: " ")
                .replacingOccurrences(of: "\r", with: " ")
                .replacingOccurrences(of: "\t", with: " ")
                .trimmingCharacters(in: .whitespaces)
            // Show when an entry is cut short or has several lines, because clicking an item
            // copies all of it, not just what the menu shows.
            let isCut = preview.count > 60 || item.text.count > 200
            let hasLineBreaks = item.text.utf8.contains(where: { $0 == 10 || $0 == 13 })  // bytes, so it stays fast on long text
            let plain = String(preview.prefix(60)) + (isCut ? "…" : "") + (hasLineBreaks ? " ⏎" : "")

            let hidden = looksSecret && !revealing
            let title = hidden ? SecretDetector.masked(item.text) : plain
            // A hidden secret is searched by what is shown, so a search cannot reveal the part
            // that is hidden.
            rows.append(Row(
                id: item.id, title: title,
                searchable: hidden ? title : String(item.text.prefix(Vault.searchLimit)),
                masked: hidden, plain: plain))
        }
    }

    private func isLikelySecret(_ item: ClipItem) -> Bool {
        if let known = secretCache[item.id] { return known }
        let result = SecretDetector.looksLikeSecret(item.text)
        secretCache[item.id] = result
        return result
    }

    private func byteString(_ bytes: Int) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(bytes), countStyle: .file)
    }

    // The title above the history. It also says how full the history is, by whichever limit is
    // closer: the number of entries or the total size.
    private func headerTitle() -> String {
        let base = paused ? "Capturing paused" : "Clipboard History"
        guard let vault, !vault.items.isEmpty else { return base }
        let count = vault.items.count
        let bytes = vault.totalBytes
        let countShare = Double(count) / Double(vault.maxItems)
        let sizeShare = Double(bytes) / Double(vault.maxTotalBytes)
        let detail = sizeShare > countShare
            ? "\(byteString(bytes)) of \(byteString(vault.maxTotalBytes))"
            : "\(count) of \(vault.maxItems)"
        let share = max(countShare, sizeShare)
        if share >= 1 { return "\(base) · full, \(detail) (oldest drop as you copy)" }
        return "\(base) · \(Int(share * 100))% full (\(detail))"
    }

    // Brings the rows that stay open up to date after a click, without closing the menu.
    private func refreshControls() {
        func symbol(_ name: String) -> NSImage? {
            NSImage(systemSymbolName: name, accessibilityDescription: nil)
        }
        let check = symbol("checkmark")
        headerItem?.title = headerTitle()
        pauseRow?.update(title: paused ? "Resume Capturing" : "Pause Capturing", image: nil, enabled: true)

        let revealing = isRevealing
        revealRow?.update(
            title: revealing ? "Hide Values Again" : "Reveal Hidden Values (\(Int(revealSeconds)) s)",
            image: symbol(revealing ? "eye.slash" : "eye"),
            enabled: anySecretLooking || revealing)  // nothing to reveal otherwise

        skipRow?.update(title: "Skip Likely Secrets (don't save)", image: secretMode == .skip ? check : nil, enabled: true)
        hideRow?.update(title: "Save, Hide Part of Likely Secrets", image: secretMode == .hide ? check : nil, enabled: true)

        let loginStatus = SMAppService.mainApp.status
        loginRow?.update(
            title: loginStatus == .requiresApproval ? "Launch at Login (needs approval)" : "Launch at Login",
            image: loginStatus == .enabled ? check : nil, enabled: true)
    }

    // After a setting changes: redraw the history and the rows, leaving the menu open.
    private func refreshAll() {
        buildRows()
        if let menu = currentMenu { renderEntries(into: menu) }
        refreshControls()
    }

    // Draws the history, filtered by the search text. Removing and adding items works while the
    // menu is open.
    private func renderEntries(into menu: NSMenu) {
        while menu.items.count > entriesStart { menu.removeItem(at: menu.items.count - 1) }

        func note(_ title: String) {
            let item = NSMenuItem(title: title, action: nil, keyEquivalent: "")
            item.isEnabled = false
            menu.addItem(item)
        }
        if rows.isEmpty {
            note("Nothing copied yet")
            return
        }
        let query = searchQuery.trimmingCharacters(in: .whitespacesAndNewlines)
        let matches = query.isEmpty ? rows : rows.filter { $0.searchable.localizedCaseInsensitiveContains(query) }
        if !query.isEmpty {
            note(matches.isEmpty ? "No matches" : "\(matches.count) of \(rows.count) match")
        }
        for row in matches {
            if row.masked {
                menu.addItem(makeSecretRow(row))
                continue
            }
            let entry = NSMenuItem(title: row.title, action: #selector(copyItem(_:)), keyEquivalent: "")
            entry.target = self
            entry.representedObject = row.id
            menu.addItem(entry)
        }
    }

    // A hidden secret gets an eye button. The eye shows or hides this entry only, in place.
    private func makeSecretRow(_ row: Row) -> NSMenuItem {
        let shown = revealedIDs.contains(row.id)
        let view = SecretRowView(text: shown ? row.plain : row.title, revealed: shown)
        view.onCopy = { [weak self] in
            self?.copyText(of: row.id)
            self?.currentMenu?.cancelTracking()
        }
        view.onToggle = { [weak self, weak view] in
            guard let self, let view else { return }
            if self.revealedIDs.contains(row.id) {
                self.revealedIDs.remove(row.id)
            } else {
                self.revealedIDs.insert(row.id)
            }
            let nowShown = self.revealedIDs.contains(row.id)
            view.update(text: nowShown ? row.plain : row.title, revealed: nowShown)
        }
        let item = NSMenuItem()
        item.view = view
        return item
    }

    private func applySearch(_ text: String) {
        searchQuery = text
        if let menu = currentMenu { renderEntries(into: menu) }
    }

    @objc private func searchFieldChanged(_ sender: NSSearchField) {
        applySearch(sender.stringValue)
    }

    func controlTextDidBeginEditing(_ obj: Notification) {
        searchContainer.setActive(true)
    }

    func controlTextDidChange(_ obj: Notification) {
        applySearch(searchField.stringValue)
    }

    // Return copies the first match and closes the menu.
    func control(_ control: NSControl, textView: NSTextView, doCommandBy selector: Selector) -> Bool {
        if selector == #selector(NSResponder.insertNewline(_:)) {
            let query = searchQuery.trimmingCharacters(in: .whitespacesAndNewlines)
            if !query.isEmpty,
               let first = rows.first(where: { $0.searchable.localizedCaseInsensitiveContains(query) }) {
                copyText(of: first.id)
                currentMenu?.cancelTracking()
            }
            return true
        }
        return false
    }

    private func setSearch(_ text: String) {
        searchField.stringValue = text
        applySearch(text)
    }

    func menuDidClose(_ menu: NSMenu) {
        searchContainer.setActive(false)
        searchQuery = ""
        revealedIDs = []
        searchField.stringValue = ""
    }

    @objc private func copyItem(_ sender: NSMenuItem) {
        guard let id = sender.representedObject as? UUID else { return }
        copyText(of: id)
    }

    private func copyText(of id: UUID) {
        guard let item = vault?.items.first(where: { $0.id == id }) else { return }
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.setString(item.text, forType: .string)
        // A secret copied back out is marked as concealed, the same flag password managers use, so
        // other clipboard tools can skip it.
        if secretMode != .show && isLikelySecret(item) {
            pasteboard.setData(Data(), forType: NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType"))
        }
        // Don't record our own copy as a new history entry.
        lastChangeCount = pasteboard.changeCount
    }

    @objc private func togglePause() {
        paused.toggle()
        refreshControls()
    }

    // Turning one setting on turns the other off. Turning the active one off leaves neither on,
    // which means likely secrets are saved and shown in full.
    @objc private func toggleSkipSecrets() {
        let turnOn = secretMode != .skip
        skipLikelySecrets = turnOn
        hideLikelySecrets = false
        revealUntil = nil
        refreshAll()
    }

    @objc private func toggleHideSecrets() {
        let turnOn = secretMode != .hide
        hideLikelySecrets = turnOn
        skipLikelySecrets = false
        revealUntil = nil
        refreshAll()
    }

    // Shows hidden values in full for a short time, then hides them again.
    @objc private func toggleReveal() {
        if (revealUntil ?? .distantPast) > Date() {
            revealUntil = nil
        } else {
            revealUntil = Date().addingTimeInterval(revealSeconds)
        }
        refreshAll()
    }

    @objc private func toggleLaunchAtLogin() {
        let service = SMAppService.mainApp
        do {
            if service.status == .enabled {
                try service.unregister()
            } else {
                try service.register()
            }
        } catch {
            currentMenu?.cancelTracking()
            notify("Could not change Launch at Login", "\(error.localizedDescription)")
            return
        }
        refreshControls()
        if service.status == .requiresApproval {
            currentMenu?.cancelTracking()
            notify(
                "Approve ClipLock in Login Items",
                "macOS needs your approval. Turn ClipLock on in System Settings → General → Login Items.")
            SMAppService.openSystemSettingsLoginItems()
        }
    }

    private func notify(_ title: String, _ info: String) {
        let alert = NSAlert()
        alert.messageText = title
        alert.informativeText = info
        NSApp.activate(ignoringOtherApps: true)
        alert.runModal()
    }

    // Plain explanations, shown as greyed-out lines.
    private func makeHelpMenu() -> NSMenu {
        let lines: [String?] = [
            "…   the entry is longer than the menu shows",
            "⏎   the entry has several lines",
            "••••   part of a likely secret is hidden",
            "Click the search box, then type to filter the list.",
            "Search reads the first 20,000 characters of each entry",
            "Return copies the first match",
            nil,
            "Click the eye next to a hidden entry to show or hide just that one",
            "Clicking the entry itself copies all of it, including hidden parts",
            nil,
            "Never saved: copies that a password manager marks secret",
            "Likely secrets: private keys, tokens, API keys and",
            "'password=…' text that ClipLock recognises",
            "Skip Likely Secrets: they are not saved at all",
            "Save, Hide Part: saved encrypted, first 5 characters shown",
            "Neither ticked: saved and shown in full",
            "Reveal Hidden Values shows them in full for 30 seconds",
            "Short passwords cannot be recognised. Pause Capturing first.",
            nil,
            "Saved text is encrypted on disk but shown here as plain text",
            nil,
            "Limits: 200 entries, 10 MB per copy, 50 MB in all",
            "When full, the oldest entries are dropped first",
            "Copies over 10 MB are not saved, and the menu says so",
        ]
        let help = NSMenu()
        for line in lines {
            if let line {
                let item = NSMenuItem(title: line, action: nil, keyEquivalent: "")
                item.isEnabled = false
                help.addItem(item)
            } else {
                help.addItem(.separator())
            }
        }
        return help
    }

    @objc private func clearHistory() {
        guard let vault else { return }
        guard confirm(
            message: "Clear all clipboard history?",
            info: "This deletes every saved item, the encrypted file and the encryption key. It cannot be undone.",
            button: "Clear")
        else { return }

        if let problem = vault.clearAll() {
            let alert = NSAlert()
            alert.messageText = "Some history could not be removed"
            alert.informativeText = problem
            alert.alertStyle = .critical
            NSApp.activate(ignoringOtherApps: true)
            alert.runModal()
        }
    }

    // Cancel is the first button, so it is the default if Return is pressed by accident.
    private func confirm(message: String, info: String, button: String) -> Bool {
        let alert = NSAlert()
        alert.messageText = message
        alert.informativeText = info
        alert.alertStyle = .warning
        alert.addButton(withTitle: "Cancel")
        alert.addButton(withTitle: button)
        alert.buttons[1].hasDestructiveAction = true
        NSApp.activate(ignoringOtherApps: true)
        return alert.runModal() == .alertSecondButtonReturn
    }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.run()

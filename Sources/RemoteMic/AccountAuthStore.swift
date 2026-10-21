import Combine
import CryptoKit
import Foundation
import Security

// MARK: - Models

struct AccountProfile: Codable, Equatable {
    let username: String
    let displayName: String
}

struct AccountSession: Codable, Equatable {
    let token: String
    let account: AccountProfile
    let signedInAt: Date
}

// MARK: - Errors

enum AccountAuthError: Error, Equatable, LocalizedError {
    case invalidCredentials
    case usernameTaken
    case weakPassword
    case usernameInvalid
    case storageUnavailable
    case sessionExpired

    var errorDescription: String? {
        switch self {
        case .invalidCredentials:
            return "用户名或密码错误 / Incorrect username or password"
        case .usernameTaken:
            return "该用户名已注册 / Username already registered"
        case .weakPassword:
            return "密码至少 8 位，需包含字母和数字 / Password needs 8+ characters with letters and digits"
        case .usernameInvalid:
            return "用户名需 3-32 位字母、数字或下划线 / Username must be 3-32 letters, digits or underscore"
        case .storageUnavailable:
            return "本地账号存储不可用 / Local account storage unavailable"
        case .sessionExpired:
            return "登录会话已过期 / Session expired"
        }
    }
}

// MARK: - Service protocol (可插拔后端)

protocol AccountAuthenticating: Sendable {
    func signIn(username: String, password: String) async throws -> AccountSession
    func signUp(username: String, password: String) async throws -> AccountSession
}

// MARK: - Local demo service
// 本地演示模式：账号与口令哈希存本地，未来把 service 换成
// RemoteAccountService(endpoint:) 即可切换到真实服务器，UI 与门禁逻辑不变。

struct LocalDemoAccountService: AccountAuthenticating {
    struct StoredCredential: Codable {
        let username: String
        let displayName: String
        let salt: String
        let passwordHash: String
        let createdAt: Date
    }

    private let queue = DispatchQueue(label: "SayAll.account.demo")
    private let fileURL: URL

    init() {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)
            .first ?? FileManager.default.temporaryDirectory
        let directory = base.appendingPathComponent("SayAllAccounts", isDirectory: true)
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        fileURL = directory.appendingPathComponent("accounts.json")
    }

    func signIn(username: String, password: String) async throws -> AccountSession {
        try queue.sync { try authenticate(mode: .signIn, username: username, password: password) }
    }

    func signUp(username: String, password: String) async throws -> AccountSession {
        try queue.sync { try authenticate(mode: .signUp, username: username, password: password) }
    }

    private enum AuthMode { case signIn, signUp }

    private func authenticate(mode: AuthMode, username: String, password: String) throws -> AccountSession {
        guard Self.isValidUsername(username) else { throw AccountAuthError.usernameInvalid }
        if mode == .signUp, !Self.isStrongEnoughPassword(password) {
            throw AccountAuthError.weakPassword
        }

        var credentials = loadCredentials()
        let normalized = username.lowercased()

        switch mode {
        case .signUp:
            guard !credentials.contains(where: { $0.username == normalized }) else {
                throw AccountAuthError.usernameTaken
            }
            let salt = UUID().uuidString
            let credential = StoredCredential(
                username: normalized,
                displayName: username,
                salt: salt,
                passwordHash: Self.hash(password: password, salt: salt),
                createdAt: Date()
            )
            credentials.append(credential)
            try saveCredentials(credentials)
        case .signIn:
            guard let credential = credentials.first(where: { $0.username == normalized }),
                  credential.passwordHash == Self.hash(password: password, salt: credential.salt)
            else { throw AccountAuthError.invalidCredentials }
            _ = credential
        }

        return AccountSession(
            token: UUID().uuidString + "-" + UUID().uuidString,
            account: AccountProfile(username: normalized, displayName: username),
            signedInAt: Date()
        )
    }

    private func loadCredentials() -> [StoredCredential] {
        guard let data = try? Data(contentsOf: fileURL),
              let credentials = try? JSONDecoder().decode([StoredCredential].self, from: data)
        else { return [] }
        return credentials
    }

    private func saveCredentials(_ credentials: [StoredCredential]) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try encoder.encode(credentials)
        try data.write(to: fileURL, options: [.atomic, .completeFileProtection])
    }

    static func isValidUsername(_ username: String) -> Bool {
        guard (3...32).contains(username.count) else { return false }
        return username.allSatisfy { $0.isLetter || $0.isNumber || $0 == "_" }
    }

    static func isStrongEnoughPassword(_ password: String) -> Bool {
        guard password.count >= 8 else { return false }
        return password.contains(where: { $0.isLetter }) && password.contains(where: { $0.isNumber })
    }

    static func hash(password: String, salt: String) -> String {
        let digest = SHA256.hash(data: Data((salt + ":" + password).utf8))
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}

// MARK: - Keychain token storage

enum AccountTokenKeychain {
    private static let service = "com.hd838a.RemoteMic.account"

    static func save(token: String, account: String) -> Bool {
        guard let data = token.data(using: .utf8) else { return false }
        delete(account: account)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        return SecItemAdd(query as CFDictionary, nil) == errSecSuccess
    }

    static func load(account: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess,
              let data = item as? Data,
              let token = String(data: data, encoding: .utf8)
        else { return nil }
        return token
    }

    @discardableResult
    static func delete(account: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        let status = SecItemDelete(query as CFDictionary)
        return status == errSecSuccess || status == errSecItemNotFound
    }
}

// MARK: - Store

@MainActor
final class AccountAuthStore: ObservableObject {
    @Published private(set) var session: AccountSession?

    var isSignedIn: Bool { session != nil }
    var currentUsername: String? { session?.account.username }

    private let service: AccountAuthenticating
    private let sessionDefaultsKey = "sayall.account.session.v1"

    init(service: AccountAuthenticating = LocalDemoAccountService()) {
        self.service = service
        restoreSession()
    }

    /// 启动时恢复会话：元数据存 UserDefaults，token 存 Keychain，二者齐全才算已登录。
    func restoreSession() {
        guard let data = UserDefaults.standard.data(forKey: sessionDefaultsKey),
              let stored = try? JSONDecoder().decode(AccountSession.self, from: data)
        else { return }
        guard let token = AccountTokenKeychain.load(account: stored.account.username),
              token == stored.token
        else {
            AccountTokenKeychain.delete(account: stored.account.username)
            UserDefaults.standard.removeObject(forKey: sessionDefaultsKey)
            return
        }
        session = stored
    }

    func signIn(username: String, password: String) async throws {
        let newSession = try await service.signIn(username: username, password: password)
        try persist(newSession)
    }

    func signUp(username: String, password: String) async throws {
        let newSession = try await service.signUp(username: username, password: password)
        try persist(newSession)
    }

    func signOut() {
        if let username = session?.account.username {
            AccountTokenKeychain.delete(account: username)
        }
        UserDefaults.standard.removeObject(forKey: sessionDefaultsKey)
        session = nil
    }

    private func persist(_ newSession: AccountSession) throws {
        guard AccountTokenKeychain.save(token: newSession.token, account: newSession.account.username),
              let data = try? JSONEncoder().encode(newSession)
        else { throw AccountAuthError.storageUnavailable }
        UserDefaults.standard.set(data, forKey: sessionDefaultsKey)
        session = newSession
    }
}

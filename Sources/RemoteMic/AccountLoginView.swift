import SwiftUI

/// 账号密码登录/注册视图。
/// 登录成功后通过 onAuthenticated 回调通知宿主（App 启动门禁），宿主再继续正常启动流程。
struct AccountLoginView: View {
    enum Mode: String, CaseIterable, Identifiable {
        case signIn
        case signUp

        var id: String { rawValue }

        var title: String {
            switch self {
            case .signIn: return "登录 / Sign In"
            case .signUp: return "注册 / Sign Up"
            }
        }
    }

    @ObservedObject var store: AccountAuthStore
    var onAuthenticated: () -> Void

    @State private var mode: Mode = .signIn
    @State private var username = ""
    @State private var password = ""
    @State private var confirmPassword = ""
    @State private var isSubmitting = false
    @State private var errorMessage: String?

    var body: some View {
        VStack(spacing: 0) {
            VStack(spacing: 8) {
                Image(systemName: "mic.badge.xmark")
                    .font(.system(size: 44))
                    .foregroundStyle(.tint)
                Text("无线麦 SayAll")
                    .font(.title2.bold())
                Text("登录后开始使用")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            .padding(.top, 40)
            .padding(.bottom, 28)

            Picker("", selection: $mode) {
                ForEach(Mode.allCases) { mode in
                    Text(mode.title).tag(mode)
                }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .padding(.horizontal, 36)

            VStack(alignment: .leading, spacing: 14) {
                fieldLabel("用户名 / Username")
                TextField("3-32 位字母、数字或下划线", text: $username)
                    .textFieldStyle(.roundedBorder)
                    .disableAutocorrection(true)

                fieldLabel("密码 / Password")
                SecureField(mode == .signUp ? "至少 8 位，含字母和数字" : "请输入密码", text: $password)
                    .textFieldStyle(.roundedBorder)

                if mode == .signUp {
                    fieldLabel("确认密码 / Confirm Password")
                    SecureField("再次输入密码", text: $confirmPassword)
                        .textFieldStyle(.roundedBorder)
                }

                if let errorMessage {
                    Text(errorMessage)
                        .font(.footnote)
                        .foregroundStyle(.red)
                        .fixedSize(horizontal: false, vertical: true)
                }

                Button {
                    submit()
                } label: {
                    HStack {
                        if isSubmitting {
                            ProgressView()
                                .controlSize(.small)
                        }
                        Text(mode == .signIn ? "登录" : "创建账号")
                    }
                    .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .disabled(isSubmitting || !isInputValid)
            }
            .padding(.horizontal, 36)
            .padding(.top, 24)

            Spacer(minLength: 0)

            Text("本地演示模式：账号数据仅保存在本机。接入服务器后可切换为在线账号。")
                .font(.caption2)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, 30)
                .padding(.bottom, 18)
        }
        .frame(width: 420, height: 560)
    }

    private var isInputValid: Bool {
        !username.trimmingCharacters(in: .whitespaces).isEmpty
            && !password.isEmpty
            && (mode == .signIn || password == confirmPassword)
    }

    private func fieldLabel(_ text: String) -> some View {
        Text(text)
            .font(.callout.weight(.medium))
    }

    private func submit() {
        let trimmedUsername = username.trimmingCharacters(in: .whitespaces)
        errorMessage = nil
        isSubmitting = true
        Task {
            do {
                switch mode {
                case .signIn:
                    try await store.signIn(username: trimmedUsername, password: password)
                case .signUp:
                    try await store.signUp(username: trimmedUsername, password: password)
                }
                isSubmitting = false
                onAuthenticated()
            } catch let error as AccountAuthError {
                isSubmitting = false
                errorMessage = error.errorDescription
            } catch {
                isSubmitting = false
                errorMessage = "登录失败，请重试 / Something went wrong, please retry"
            }
        }
    }
}

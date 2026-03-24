import UIKit
import Foundation
import CoreTelephony
import AdSupport
import AppTrackingTransparency
import WebKit

public final class DeepLinkNow {
    private static var shared: DeepLinkNow?
    private let config: DLNConfig
    private let urlSession: URLSessionProtocol
    private let installTime: String
    private var initResponse: InitResponse?
    private var validDomains: Set<String> = []
    private var safariOSVersion: String?
    
    private init(config: DLNConfig, urlSession: URLSessionProtocol = URLSession.shared) {
        self.config = config
        self.urlSession = urlSession
        self.installTime = ISO8601DateFormatter().string(from: Date())
    }
    
    private func log(_ message: String, _ args: Any...) {
        if config.enableLogs {
            print("[DeepLinkNow]", message, args)
        }
    }

    private func warn(_ message: String) {
        print("[DeepLinkNow] Warning:", message)
    }

    private func simpleHash(_ str: String) -> String {
        var hash: Int = 0
        for char in str.unicodeScalars {
            hash = ((hash << 5) &- hash) &+ Int(char.value)
            hash = hash & hash // Convert to 32bit integer
        }
        return String(hash, radix: 16)
    }

    private func generateHardwareFingerprint(
        platform: String,
        osVersion: String,
        screenWidth: Int,
        screenHeight: Int,
        pixelRatio: Double,
        language: String,
        timezone: String
    ) -> String {
        let components = [
            platform,
            osVersion,
            String(screenWidth),
            String(screenHeight),
            String(pixelRatio),
            language,
            timezone
        ]

        let fingerprintString = components.joined(separator: "|")
        return simpleHash(fingerprintString)
    }
    
    /// Resolves the OS version as reported by Safari's user agent.
    /// On iOS 26+, Safari freezes the UA version to 18.x, which differs from
    /// UIDevice.current.systemVersion. We need to match what the web side captured.
    @MainActor
    private func resolveSafariOSVersion() async -> String {
        let webView = WKWebView(frame: .zero)
        do {
            let ua = try await webView.evaluateJavaScript("navigator.userAgent") as? String ?? ""
            if let match = ua.range(of: #"CPU (?:iPhone )?OS (\d+[_\.]\d+(?:[_\.]\d+)?)"#, options: .regularExpression) {
                let fullMatch = String(ua[match])
                // Extract just the version part after "OS "
                if let osRange = fullMatch.range(of: #"(\d+[_\.]\d+(?:[_\.]\d+)?)"#, options: .regularExpression) {
                    return String(fullMatch[osRange]).replacingOccurrences(of: "_", with: ".")
                }
            }
        } catch {
            // Fall back to system version if WKWebView fails
        }
        return UIDevice.current.systemVersion
    }

    public static func initialize(config: DLNConfig, urlSession: URLSessionProtocol = URLSession.shared) async {
        let instance = DeepLinkNow(config: config, urlSession: urlSession)
        shared = instance

        // On iOS 26+, Safari freezes the UA version to 18.x while
        // UIDevice.current.systemVersion returns the real version (e.g. 26.3.1).
        // Resolve Safari's reported version so fingerprints match the web side.
        if #available(iOS 26.0, *) {
            instance.safariOSVersion = await instance.resolveSafariOSVersion()
            instance.log("Resolved Safari OS version:", instance.safariOSVersion ?? "nil",
                          "System version:", UIDevice.current.systemVersion)
        }

        instance.log("Initializing with config:", config)
        
        do {
            let initRequest = ["api_key": config.apiKey]
            let data = try await instance.makeAPIRequest(
                endpoint: "init",
                method: "POST",
                body: initRequest
            )
            
            let decoder = JSONDecoder()
            let response = try decoder.decode(InitResponse.self, from: data)
            instance.initResponse = response
            
            // Set up base domains using app alias
            let appAlias = response.app.alias
            instance.validDomains.insert("\(appAlias).deeplinknow.com")
            instance.validDomains.insert("\(appAlias).deeplink.now")
            
            // Add custom domains
            response.app.customDomains
                .filter { $0.domain != nil && $0.verified == true }
                .forEach { domain in
                    if let domain = domain.domain {
                        instance.validDomains.insert(domain)
                    }
                }
            
            instance.log("Init response:", response)
            instance.log("Valid domains:", instance.validDomains)
        } catch {
            instance.warn("Initialization failed: \(error)")
        }
    }
    
    public static func isValidDomain(_ domain: String) -> Bool {
        guard let shared = shared else { return false }
        return shared.validDomains.contains(domain)
    }
    
    private func getFingerprint() -> Fingerprint {
        let device = UIDevice.current
        let screen = UIScreen.main
        let dateFormatter = ISO8601DateFormatter()

        let currentTime = dateFormatter.string(from: Date())

        // Use Safari's reported OS version for fingerprint matching.
        // On iOS 26+, Safari freezes the UA version to 18.x while
        // UIDevice.current.systemVersion returns the real version (e.g. 26.3.1).
        let osVersion = safariOSVersion ?? device.systemVersion
        let osVersionUA = osVersion.replacingOccurrences(of: ".", with: "_")

        // Generate user agent string that matches Safari's actual format
        let userAgent = "Mozilla/5.0 (\(device.model); CPU iPhone OS \(osVersionUA) like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/\(osVersion) Mobile/15E148 Safari/604.1"

        // Determine device model based on device type, matching web implementation
        let deviceModel: String
        switch device.userInterfaceIdiom {
        case .pad:
            deviceModel = "iPad"
        case .phone:
            deviceModel = "iPhone"
        default:
            deviceModel = "iPhone" // Default to iPhone for other cases
        }

        // Get screen dimensions in LOGICAL pixels (CSS pixels) to match web behavior
        // window.screen.width on Safari iOS returns logical pixels, not physical
        // Database analysis: production stores 393×852 (logical), not 1179×2556 (physical)
        // Example: iPhone 14 Pro → bounds.width=393 (not 393×3=1179)
        let screenWidth = Int(screen.bounds.width)
        let screenHeight = Int(screen.bounds.height)
        let pixelRatio = round(Double(screen.scale) * 100) / 100 // Round to 2 decimal places

        // Get BCP 47 language tag (e.g., "en-US") to match Safari's navigator.language.
        // Locale.current.identifier can return extended identifiers like "en_US@rg=plzzzz"
        // which breaks fingerprint matching against web values.
        let language: String = {
            if #available(iOS 16, *) {
                let languageCode = Locale.current.language.languageCode?.identifier ?? "en"
                if let regionCode = Locale.current.language.region?.identifier {
                    return "\(languageCode)-\(regionCode)"
                }
                return languageCode
            }
            return Locale.current.identifier.replacingOccurrences(of: "_", with: "-")
        }()
        let timezone = TimeZone.current.identifier

        // Generate hardware fingerprint using the same algorithm as web
        let hardwareFingerprint = generateHardwareFingerprint(
            platform: "ios",
            osVersion: osVersion,
            screenWidth: screenWidth,
            screenHeight: screenHeight,
            pixelRatio: pixelRatio,
            language: language,
            timezone: timezone
        )

        let metadata = FingerprintMetadata(
            screenWidth: screenWidth,
            screenHeight: screenHeight,
            pixelRatio: pixelRatio,
            colorDepth: 32, // Standard for iOS
            isTablet: device.userInterfaceIdiom == .pad,
            connectionType: nil,
            cpuCores: ProcessInfo.processInfo.processorCount,
            deviceMemory: nil,
            source: "mobile"
        )

        return Fingerprint(
            ipAddress: "", // Will be set by server
            userAgent: userAgent,
            platform: "ios",
            osVersion: osVersion,
            deviceModel: deviceModel,
            language: language,
            timezone: timezone,
            installedAt: installTime,
            lastOpenedAt: currentTime,
            deviceId: device.identifierForVendor?.uuidString,
            advertisingId: {
                if #available(iOS 14, *) {
                    return ATTrackingManager.trackingAuthorizationStatus == .authorized ?
                        ASIdentifierManager.shared().advertisingIdentifier.uuidString : nil
                } else {
                    return ASIdentifierManager.shared().isAdvertisingTrackingEnabled ?
                        ASIdentifierManager.shared().advertisingIdentifier.uuidString : nil
                }
            }(),
            vendorId: device.identifierForVendor?.uuidString,
            hardwareFingerprint: hardwareFingerprint,
            metadata: metadata
        )
    }
    
    public static func findDeferredUser() async -> MatchResponse? {
        guard let shared = shared else {
            print("[DeepLinkNow] SDK not initialized. Call initialize() first")
            return nil
        }
        
        shared.log("Finding deferred user...")
        
        let fingerprint = shared.getFingerprint()
        
        // Break down the metadata dictionary creation
        var metadata: [String: Any] = [:]
        if let fingerprintMetadata = fingerprint.metadata {
            metadata["screen_width"] = fingerprintMetadata.screenWidth
            metadata["screen_height"] = fingerprintMetadata.screenHeight
            if let pixelRatio = fingerprintMetadata.pixelRatio {
                // Ensure the number is properly formatted for JSON
                let roundedRatio = NSNumber(value: round(pixelRatio * 100) / 100)
                metadata["pixel_ratio"] = roundedRatio
            }
            metadata["color_depth"] = fingerprintMetadata.colorDepth
            metadata["is_tablet"] = fingerprintMetadata.isTablet
            metadata["connection_type"] = fingerprintMetadata.connectionType
            metadata["cpu_cores"] = fingerprintMetadata.cpuCores
            metadata["device_memory"] = fingerprintMetadata.deviceMemory
            metadata["source"] = fingerprintMetadata.source
        }
        
        // Create the main fingerprint dictionary
        var fingerprintDict: [String: Any] = [:]
        fingerprintDict["platform"] = fingerprint.platform
        fingerprintDict["os_version"] = fingerprint.osVersion
        fingerprintDict["device_model"] = fingerprint.deviceModel
        fingerprintDict["language"] = fingerprint.language
        fingerprintDict["timezone"] = fingerprint.timezone
        fingerprintDict["installed_at"] = fingerprint.installedAt
        fingerprintDict["last_opened_at"] = fingerprint.lastOpenedAt
        fingerprintDict["device_id"] = fingerprint.deviceId ?? ""
        fingerprintDict["advertising_id"] = fingerprint.advertisingId ?? ""
        fingerprintDict["vendor_id"] = fingerprint.vendorId ?? ""
        fingerprintDict["hardware_fingerprint"] = fingerprint.hardwareFingerprint ?? ""
        fingerprintDict["user_agent"] = fingerprint.userAgent

        // Move screen dimensions to top level for API matching (required by match endpoint schema)
        if let fingerprintMetadata = fingerprint.metadata {
            fingerprintDict["screen_width"] = fingerprintMetadata.screenWidth
            fingerprintDict["screen_height"] = fingerprintMetadata.screenHeight
            if let pixelRatio = fingerprintMetadata.pixelRatio {
                fingerprintDict["pixel_ratio"] = pixelRatio
            }
        }

        fingerprintDict["metadata"] = metadata
        
        let matchRequest = ["fingerprint": fingerprintDict]
        
        shared.log("Sending match request:", matchRequest)
        
        do {
            let data = try await shared.makeAPIRequest(
                endpoint: "match",
                method: "POST",
                body: matchRequest
            )
            
            let decoder = JSONDecoder()
            let response = try decoder.decode(MatchResponse.self, from: data)
            shared.log("Match response:", response)
            return response
            
        } catch {
            shared.warn("API request failed: \(error)")
            return nil
        }
    }
    
    private func makeAPIRequest(endpoint: String, method: String = "GET", body: [String: Any]? = nil) async throws -> Data {
        let baseUrl = config.baseUrl ?? "https://deeplinknow.com"
        let url = URL(string: "\(baseUrl)/api/v1/sdk/\(endpoint)")!
        
        var request = URLRequest(url: url)
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue(config.apiKey, forHTTPHeaderField: "x-api-key")
        request.httpMethod = method
        
        if let timeout = config.timeout {
            request.timeoutInterval = timeout
        }
        
        if let body = body {
            request.httpBody = try JSONSerialization.data(withJSONObject: body)
        }
        
        let (data, response) = try await urlSession.data(for: request)
        guard let httpResponse = response as? HTTPURLResponse else {
            log("API request failed: Invalid response type")
            throw DLNError.serverError("Invalid response type", nil, nil)
        }
        
        if !(200...299).contains(httpResponse.statusCode) {
            log("API request failed: \(httpResponse.statusCode)")
            if let errorString = String(data: data, encoding: .utf8) {
                log("Error response: \(errorString)")
                
                // Try to decode error response
                if let errorResponse = try? JSONDecoder().decode([String: String].self, from: data) {
                    throw DLNError.serverError(
                        errorResponse["error"] ?? "Unknown error",
                        errorResponse["status"],
                        errorResponse["details"]
                    )
                }
            }
            
            // Map status codes to specific errors
            switch httpResponse.statusCode {
            case 400: throw DLNError.badRequest
            case 401: throw DLNError.unauthorized
            case 403: throw DLNError.forbidden
            case 404: throw DLNError.notFound
            case 429: throw DLNError.tooManyRequests
            case 500: throw DLNError.internalServerError
            default: throw DLNError.serverError("Unknown error", String(httpResponse.statusCode), nil)
            }
        }
        
        return data
    }
    
    public static func hasDeepLinkToken() -> Bool {
        guard shared != nil else {
            print("[DeepLinkNow] SDK not initialized. Call initialize() first")
            return false
        }
        
        guard UIPasteboard.general.hasStrings else {
            return false
        }
        
        if let content = UIPasteboard.general.string {
            return content.hasPrefix("dln://") || 
                   content.contains("deeplinknow.com") || 
                   content.contains("deeplink.now")
        }
        
        return false
    }
    
    public static func checkClipboard() -> String? {
        guard let shared = shared else {
            print("[DeepLinkNow] SDK not initialized. Call initialize() first")
            return nil
        }
        
        guard let content = UIPasteboard.general.string else {
            return nil
        }
        
        // Parse domain from URL
        if let urlComponents = URLComponents(string: content),
           let host = urlComponents.host {
            if host.contains("deeplinknow.com") ||
               host.contains("deeplink.now") ||
               shared.validDomains.contains(host) {
                shared.log("Found deep link token in clipboard")
                shared.log("Clipboard content:", content)
                return content
            }
        }
        
        return nil
    }
    
    public static func handleUniversalLink(_ url: URL) {
        // Handle universal links
    }
    
    public static func handleCustomScheme(_ url: URL) {
        // Handle custom scheme deep links
    }
    
    public static func createDeepLink(
        path: String,
        customParameters: DLNCustomParameters? = nil
    ) -> URL? {
        let components = URLComponents {
            $0.scheme = "deeplinknow"
            $0.host = "app"
            $0.path = path
            
            if let params = customParameters?.dictionary {
                $0.queryItems = params.compactMap { key, value in
                    URLQueryItem(name: key, value: String(describing: value))
                }
            }
        }
        
        return components.url
    }
    
    public static func parseDeepLink(_ url: URL) -> (path: String, parameters: [String: Any])? {
        guard let shared = shared,
              let components = URLComponents(url: url, resolvingAgainstBaseURL: true),
              shared.validDomains.contains(components.host ?? "") else {
            return nil
        }
        
        let path = components.path
        var parameters: [String: Any] = [:]
        
        // Parse query parameters
        components.queryItems?.forEach { item in
            if let value = item.value {
                parameters[item.name] = value
            }
        }
        
        return (path, parameters)
    }
} 
import SwiftUI

/// Reminds the user monthly to pull upstream VoiceInk improvements into Apex Flow.
class UpstreamSyncService {
    static let shared = UpstreamSyncService()

    private let lastReminderKey = "ApexFlowLastUpstreamSyncReminder"
    private let reminderIntervalDays = 30

    private init() {}

    @MainActor
    func checkAndRemind() {
        guard shouldRemind() else { return }

        // Delay slightly so the app is fully visible before showing the banner
        DispatchQueue.main.asyncAfter(deadline: .now() + 2.0) {
            NotificationManager.shared.showNotification(
                title: "Tip: sync Apex Flow with upstream VoiceInk updates — cd ~/VoiceInk && git fetch upstream && git merge upstream/main",
                type: .info,
                duration: 12.0
            )
            self.markReminderShown()
        }
    }

    private func shouldRemind() -> Bool {
        guard let last = UserDefaults.standard.object(forKey: lastReminderKey) as? Date else {
            return true // Never reminded before
        }
        let daysSince = Calendar.current.dateComponents([.day], from: last, to: Date()).day ?? 0
        return daysSince >= reminderIntervalDays
    }

    private func markReminderShown() {
        UserDefaults.standard.set(Date(), forKey: lastReminderKey)
    }
}

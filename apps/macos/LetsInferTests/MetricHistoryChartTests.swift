import AppKit
import Foundation
import Testing
@testable import LetsInfer

struct MetricHistoryChartTests {
    @Test @MainActor
    func presentationHistoryIsTimeAndMemoryBounded() {
        let newest = Date(timeIntervalSince1970: 1_700_000_000)
        var points = (0..<2_100).map { offset in
            MetricHistoryPoint(
                timestamp: newest.addingTimeInterval(TimeInterval(offset - 2_099)),
                gpuUtilization: Double(offset % 100),
                memoryUtilization: nil,
                cpuUtilization: nil,
                diskUtilization: nil,
                temperature: nil,
                generationTokensPerSecond: nil
            )
        }

        SiteMonitoringController.trimPresentationHistory(&points, newest: newest)

        #expect(points.count == SiteMonitoringController.maximumPresentationPoints)
        #expect(points.first?.timestamp == newest.addingTimeInterval(-1_800))
        #expect(points.last?.timestamp == newest)
        #expect(
            points.allSatisfy {
                newest.timeIntervalSince($0.timestamp)
                    <= SiteMonitoringController.presentationHistorySeconds
            }
        )
    }

    @Test @MainActor
    func hoverSelectsAndExposesEverySeries() {
        let start = Date(timeIntervalSince1970: 1_700_000_000)
        let points = [
            MetricHistoryPoint(
                timestamp: start,
                gpuUtilization: 91,
                memoryUtilization: 82,
                cpuUtilization: 17,
                diskUtilization: 54,
                temperature: 68,
                generationTokensPerSecond: nil
            ),
            MetricHistoryPoint(
                timestamp: start.addingTimeInterval(10),
                gpuUtilization: 92,
                memoryUtilization: 83,
                cpuUtilization: 18,
                diskUtilization: 54,
                temperature: 69,
                generationTokensPerSecond: nil
            )
        ]
        let view = MetricHistoryView(points: points)
        view.frame = NSRect(x: 0, y: 0, width: 340, height: 205)

        view.updateHover(at: CGPoint(x: 42, y: 100))

        let value = view.accessibilityValue() as? String
        #expect(value?.contains("GPU 91 percent") == true)
        #expect(value?.contains("Memory 82 percent") == true)
        #expect(value?.contains("CPU 17 percent") == true)
        #expect(value?.contains("Disk 54 percent") == true)
    }
}

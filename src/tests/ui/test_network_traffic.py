from src.network.traffic_monitor import TrafficRateSample
from src.ui.components.network_traffic import NetworkTrafficPanel


def test_traffic_panel_alerts_after_three_spikes_and_requires_review(qtbot):
    panel = NetworkTrafficPanel()
    qtbot.addWidget(panel)
    spike = TrafficRateSample(2_000_000, 1_000_000, 1_048_576, True)

    panel.set_sample(spike)
    panel.set_sample(spike)
    assert panel.review_button.isHidden()

    panel.set_sample(spike)

    assert not panel.review_button.isHidden()
    assert "Sustained traffic spike" in panel.status_label.text()
    with qtbot.waitSignal(panel.reviewConnectionsRequested):
        panel.review_button.click()


def test_traffic_panel_clears_spike_when_rate_returns_to_baseline(qtbot):
    panel = NetworkTrafficPanel()
    qtbot.addWidget(panel)
    panel.set_sample(TrafficRateSample(2_000_000, 0, 1_048_576, True))
    panel.set_sample(TrafficRateSample(2_000_000, 0, 1_048_576, True))
    panel.set_sample(TrafficRateSample(2_000_000, 0, 1_048_576, True))

    panel.set_sample(TrafficRateSample(0, 0, 1_048_576, False))

    assert panel.review_button.isHidden()
    assert "adaptive spike threshold" in panel.status_label.text()

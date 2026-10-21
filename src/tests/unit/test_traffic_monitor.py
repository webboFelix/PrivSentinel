import pytest

from src.network.traffic_monitor import TrafficRateSampler


def test_traffic_sampler_detects_adaptive_spikes_and_handles_counter_reset():
    sampler = TrafficRateSampler()
    assert not sampler.update(100, 100).is_spike

    ordinary = sampler.update(100_100, 100_100)
    assert ordinary.upload_bytes_per_second == 100_000
    assert ordinary.download_bytes_per_second == 100_000
    assert not ordinary.is_spike

    spike = sampler.update(1_400_100, 1_400_100)
    assert spike.is_spike
    assert spike.spike_threshold_bytes_per_second >= 1_048_576

    reset = sampler.update(20, 20)
    assert reset.upload_bytes_per_second == 0
    assert reset.download_bytes_per_second == 0
    assert not reset.is_spike


def test_traffic_sampler_rejects_invalid_counter_values():
    sampler = TrafficRateSampler()

    with pytest.raises(ValueError, match="cannot be negative"):
        sampler.update(-1, 0)

    with pytest.raises(ValueError, match="at least three"):
        TrafficRateSampler(history_size=2)

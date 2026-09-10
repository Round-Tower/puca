import pytest
from puca.timing import compare


def test_no_leak_for_similar_samples():
    v = compare.compare([0.10, 0.10, 0.11], [0.10, 0.11, 0.10])
    assert not v.leak_suspected


def test_leak_for_separated_medians():
    v = compare.compare([0.10, 0.10, 0.10], [0.20, 0.21, 0.20])
    assert v.leak_suspected
    assert v.delta >= 0.10


def test_empty_samples_raise():
    with pytest.raises(ValueError):
        compare.compare([], [0.1])

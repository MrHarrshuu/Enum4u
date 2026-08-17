from enum4u.config import load_config
from enum4u.core.engine import Engine
from enum4u.core.orchestrator import initialize_pipeline


def test_fast_pipeline_initialization():
    config = load_config("fast")

    engine = Engine(
        target="127.0.0.1:8000",
        mode="fast",
        config=config,
    )

    initialize_pipeline(engine)

    assert engine is not None
    assert engine.target == "127.0.0.1:8000"
    assert engine.mode == "fast"


def test_deep_pipeline_initialization():
    config = load_config("deep")

    engine = Engine(
        target="127.0.0.1:8000",
        mode="deep",
        config=config,
    )

    initialize_pipeline(engine)

    assert engine is not None
    assert engine.target == "127.0.0.1:8000"
    assert engine.mode == "deep"


def test_fast_config_enables_expected_modules():
    config = load_config("fast")

    assert config["modules"]["recon"] is True
    assert config["modules"]["enumeration"] is True
    assert config["modules"]["web"] is True
    assert config["modules"]["assessment"] is False


def test_deep_config_enables_assessment():
    config = load_config("deep")

    assert config["modules"]["recon"] is True
    assert config["modules"]["enumeration"] is True
    assert config["modules"]["web"] is True
    assert config["modules"]["assessment"] is True


def test_pipeline_registration():
    config = load_config("fast")

    engine = Engine(
        target="127.0.0.1:8000",
        mode="fast",
        config=config,
    )

    initialize_pipeline(engine)

    pipeline = engine.pipeline

    assert pipeline is not None

    registered_tasks = getattr(
        pipeline,
        "tasks",
        None,
    )

    assert registered_tasks is not None
    assert len(registered_tasks) > 0
"""Service banner grabber module."""


def grab_banners(
    host: str, ports: list[int], timeout: float = 3.0, workers: int = 10
) -> list[dict]:
    """Grab service banners from open ports. Returns list of {port, banner, service}."""
    return []
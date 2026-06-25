def calculate_decay(score: float, age_seconds: float, ttl: float, half_life: float = 300.0) -> float:
    """
    Calculate the decayed score based on exponential decay using half-life.
    If the age exceeds the TTL, the score decays to 0.0.
    """
    if age_seconds < 0:
        age_seconds = 0.0
    if age_seconds >= ttl:
        return 0.0
    if half_life <= 0:
        return 0.0
    
    factor = 0.5 ** (age_seconds / half_life)
    return score * factor

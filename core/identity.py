from requests_tor import RequestsTor

# Add this corrected function definition:
def rotate_identity(session):
    """
    Attempts to rotate the Tor identity.
    If the library doesn't support reset_identity, we simply return
    to avoid crashing the crawler.
    """
    try:
        # The requests_tor library usually manages this internally,
        # but if you need to explicitly reset:
        if hasattr(session, 'reset_identity'):
            session.reset_identity()
    except Exception as e:
        # Logging specific errors for identity rotation
        print(f"[!] Identity rotation issue: {e}")
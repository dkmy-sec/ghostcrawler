def rotate_identity(session):
    try:
        session.reset_identity()
        print("[~] Tor identity changed.")
    except Exception as e:
        print(f"[!] Failed to rotate identity: {e}")

class OpenVPNSignatureDetector:
    def __init__(self) -> None:
        pass

    def analyze(self, flow: dict) -> tuple[bool, str | None]:
        """
        Analyze a flow dictionary for OpenVPN signatures.
        Returns:
            (is_openvpn, reason)
        """
        signals = flow.get("analysis_signals") or []
        for sig in signals:
            if sig.startswith("openvpn_udp_opcode_"):
                opcode = sig.split("_")[-1]
                return True, f"OpenVPN UDP opcode {opcode} detected in packet payload"
            elif sig.startswith("openvpn_tcp_opcode_"):
                opcode = sig.split("_")[-1]
                return True, f"OpenVPN TCP opcode {opcode} detected in packet payload"
        return False, None

    def clear(self) -> None:
        pass

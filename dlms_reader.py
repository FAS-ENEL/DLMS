import argparse
import socket
from typing import Optional

from gurux_dlms import Authentication, GXByteBuffer, GXDLMSClient, InterfaceType

# OBIS codes for active energy import and export
OBIS_A_PLUS = "1.0.1.8.0.255"  # A+ active energy import
OBIS_R_PLUS = "1.0.2.8.0.255"  # R+ active energy export


def recv_exact(sock: socket.socket, length: int) -> bytes:
    data = bytearray()
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise ConnectionError("Connection closed while receiving data")
        data.extend(chunk)
    return bytes(data)


def recv_wrapper_frame(sock: socket.socket) -> bytes:
    header = recv_exact(sock, 8)
    payload_len = int.from_bytes(header[6:8], "big")
    payload = recv_exact(sock, payload_len) if payload_len > 0 else b""
    return header + payload


def strip_wrapper_frame(frame: bytes) -> bytes:
    if len(frame) < 8:
        raise ValueError("Wrapper frame too short")
    payload_len = int.from_bytes(frame[6:8], "big")
    payload = frame[8 : 8 + payload_len]
    if len(payload) != payload_len:
        raise ValueError("Wrapper frame payload length mismatch")
    return payload


def read_channel(
    ip: str,
    port: int,
    logical_name: str,
    client_address: int = 16,
    server_address: int = 1,
    password: Optional[str] = None,
    auth_type: str = "NONE",
) -> object:
    auth_type = auth_type.upper()
    auth = Authentication.NONE
    if auth_type == "LOW":
        auth = Authentication.LOW
    elif auth_type == "HIGH":
        auth = Authentication.HIGH
    elif auth_type == "HIGH_GMAC":
        auth = Authentication.HIGH_GMAC
    elif auth_type == "HIGH_SHA256":
        auth = Authentication.HIGH_SHA256
    elif auth_type == "HIGH_ECDSA":
        auth = Authentication.HIGH_ECDSA

    if auth != Authentication.NONE and not password:
        raise ValueError("Authentication type requires a password.")

    client = GXDLMSClient(
        useLogicalNameReferencing=True,
        clientAddress=client_address,
        serverAddress=server_address,
        forAuthentication=auth,
        password=password.encode() if isinstance(password, str) else password,
        interfaceType=InterfaceType.WRAPPER,
    )
    settings = client.settings
    settings.clientAddress = client_address
    settings.serverAddress = server_address
    settings.interfaceType = InterfaceType.WRAPPER
    settings.authentication = auth

    sock = socket.create_connection((ip, port), timeout=10.0)
    try:
        # AARQ association request
        aarq_messages = client.aarqRequest()
        if not aarq_messages:
            raise RuntimeError("Failed to create AARQ request.")
        for msg in aarq_messages:
            sock.sendall(msg)

        reply = recv_wrapper_frame(sock)
        dlms_payload = strip_wrapper_frame(reply)
        client.parseAareResponse(dlms_payload)

        # Read all objects from meter
        get_objects_request = client.getObjectsRequest()
        if not get_objects_request:
            raise RuntimeError("Failed to create getObjects request.")
        sock.sendall(get_objects_request)

        reply = recv_wrapper_frame(sock)
        dlms_payload = strip_wrapper_frame(reply)
        client.parseObjects(GXByteBuffer(dlms_payload))

        target = next((obj for obj in client.objects if obj.logicalName == logical_name), None)
        if target is None:
            raise RuntimeError(f"Logical name {logical_name} not found on meter.")

        read_messages = client.read(target, 2)
        if not read_messages:
            raise RuntimeError("Failed to create read request.")
        for msg in read_messages:
            sock.sendall(msg)

        reply = recv_wrapper_frame(sock)
        dlms_payload = strip_wrapper_frame(reply)
        value = GXDLMSClient.getValue(dlms_payload, settings.useUtc2NormalTime)
        return value
    finally:
        sock.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Leer A+ o R+ de un medidor DLMS sobre IP.")
    parser.add_argument("--ip", required=True, help="Dirección IP del medidor DLMS")
    parser.add_argument("--port", type=int, default=4059, help="Puerto TCP del medidor DLMS (por defecto 4059)")
    parser.add_argument("--channel", choices=["A+", "R+"], required=True, help="Canal a leer")
    parser.add_argument("--client", type=int, default=16, help="Dirección cliente DLMS")
    parser.add_argument("--server", type=int, default=1, help="Dirección servidor DLMS")
    parser.add_argument(
        "--auth",
        choices=["NONE", "LOW", "HIGH", "HIGH_GMAC", "HIGH_SHA256", "HIGH_ECDSA"],
        default="NONE",
        help="Tipo de autenticación DLMS",
    )
    parser.add_argument("--password", help="Password para autenticación si es necesario")
    args = parser.parse_args()

    logical_name = OBIS_A_PLUS if args.channel == "A+" else OBIS_R_PLUS
    value = read_channel(
        args.ip,
        args.port,
        logical_name,
        client_address=args.client,
        server_address=args.server,
        password=args.password,
        auth_type=args.auth,
    )
    print(f"Valor {args.channel}: {value}")


if __name__ == "__main__":
    main()

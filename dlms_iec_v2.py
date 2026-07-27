import argparse
import os
import socket
from pathlib import Path
from typing import Optional

from gurux_dlms import GXByteBuffer, GXDLMSClient
from gurux_dlms.enums import Authentication, InterfaceType

DEFAULT_WORKDIR = Path(r"C:\Users\cl098998012\enel_dev")
OBIS_BY_CHANNEL = {
    "A+": "1.0.1.8.0.255",
    "R+": "1.0.2.8.0.255",
}
AUTH_BY_NAME = {
    "NONE": Authentication.NONE,
    "LOW": Authentication.LOW,
    "HIGH": Authentication.HIGH,
    "HIGH_GMAC": Authentication.HIGH_GMAC,
    "HIGH_SHA256": Authentication.HIGH_SHA256,
    "HIGH_ECDSA": Authentication.HIGH_ECDSA,
}


def recv_exact(sock: socket.socket, length: int) -> bytes:
    data = bytearray()
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise ConnectionError("La conexion se cerro mientras se recibian datos.")
        data.extend(chunk)
    return bytes(data)


def recv_wrapper_frame(sock: socket.socket) -> bytes:
    header = recv_exact(sock, 8)
    payload_len = int.from_bytes(header[6:8], "big")
    payload = recv_exact(sock, payload_len) if payload_len > 0 else b""
    return header + payload


def strip_wrapper_frame(frame: bytes) -> bytes:
    if len(frame) < 8:
        raise ValueError("La trama wrapper es demasiado corta.")
    payload_len = int.from_bytes(frame[6:8], "big")
    payload = frame[8 : 8 + payload_len]
    if len(payload) != payload_len:
        raise ValueError("La longitud del payload wrapper no coincide.")
    return payload


def resolve_authentication(auth_type: str) -> Authentication:
    normalized_auth = auth_type.upper()
    try:
        return AUTH_BY_NAME[normalized_auth]
    except KeyError as exc:
        valid_options = ", ".join(sorted(AUTH_BY_NAME))
        raise ValueError(
            f"Tipo de autenticacion no soportado: {auth_type}. Use uno de: {valid_options}."
        ) from exc


def encode_password(password):
    if password is None:
        return None
    return password.encode("utf-8")


def read_channel(
    ip: str,
    port: int,
    logical_name: str,
    client_address: int = 16,
    server_address: int = 1,
    password=None,
    auth_type: str = "NONE",
) -> object:
    authentication = resolve_authentication(auth_type)
    if authentication != Authentication.NONE and not password:
        raise ValueError("El tipo de autenticacion seleccionado requiere password.")

    client = GXDLMSClient(
        useLogicalNameReferencing=True,
        clientAddress=client_address,
        serverAddress=server_address,
        forAuthentication=authentication,
        password=encode_password(password),
        interfaceType=InterfaceType.WRAPPER,
    )
    settings = client.settings
    settings.clientAddress = client_address
    settings.serverAddress = server_address
    settings.interfaceType = InterfaceType.WRAPPER
    settings.authentication = authentication

    sock = socket.create_connection((ip, port), timeout=10.0)
    try:
        aarq_messages = client.aarqRequest()
        if not aarq_messages:
            raise RuntimeError("No fue posible generar la solicitud AARQ.")
        for message in aarq_messages:
            sock.sendall(message)

        reply = recv_wrapper_frame(sock)
        client.parseAareResponse(strip_wrapper_frame(reply))

        objects_request = client.getObjectsRequest()
        if not objects_request:
            raise RuntimeError("No fue posible generar la solicitud de objetos DLMS.")
        sock.sendall(objects_request)

        reply = recv_wrapper_frame(sock)
        client.parseObjects(GXByteBuffer(strip_wrapper_frame(reply)))

        target = next((obj for obj in client.objects if obj.logicalName == logical_name), None)
        if target is None:
            raise RuntimeError(f"No se encontro el logical name {logical_name} en el medidor.")

        read_messages = client.read(target, 2)
        if not read_messages:
            raise RuntimeError("No fue posible generar la solicitud de lectura.")
        for message in read_messages:
            sock.sendall(message)

        reply = recv_wrapper_frame(sock)
        return GXDLMSClient.getValue(strip_wrapper_frame(reply), settings.useUtc2NormalTime)
    finally:
        sock.close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Lee A+ o R+ de un medidor DLMS sobre IP.")
    parser.add_argument("--ip", required=True, help="Direccion IP del medidor DLMS.")
    parser.add_argument("--port", type=int, default=4059, help="Puerto TCP del medidor DLMS (default: 4059).")
    parser.add_argument("--channel", choices=sorted(OBIS_BY_CHANNEL), required=True, help="Canal a leer.")
    parser.add_argument("--client", type=int, default=16, help="Direccion cliente DLMS.")
    parser.add_argument("--server", type=int, default=1, help="Direccion servidor DLMS.")
    parser.add_argument(
        "--auth",
        choices=sorted(AUTH_BY_NAME),
        default="NONE",
        help="Tipo de autenticacion DLMS.",
    )
    parser.add_argument("--password", help="Password para autenticacion cuando aplique.")
    parser.add_argument(
        "--workdir",
        type=Path,
        default=DEFAULT_WORKDIR,
        help=f"Carpeta de trabajo (default: {DEFAULT_WORKDIR}).",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    workdir = args.workdir.expanduser().resolve()
    workdir.mkdir(parents=True, exist_ok=True)
    os.chdir(workdir)

    logical_name = OBIS_BY_CHANNEL[args.channel]
    value = read_channel(
        args.ip,
        args.port,
        logical_name,
        client_address=args.client,
        server_address=args.server,
        password=args.password,
        auth_type=args.auth,
    )
    print(f"Directorio de trabajo: {workdir}")
    print(f"Valor {args.channel}: {value}")


if __name__ == "__main__":
    main()

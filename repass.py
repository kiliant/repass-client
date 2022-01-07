"""
The RePass client.

Uses code stubs from https://github.com/Yubico/python-fido2

Run with python repass.py and follow the instructions.
"""

from __future__ import absolute_import, print_function, unicode_literals

import ctypes
import hashlib
import json
import sys
from getpass import getpass

import requests
from fido2.client import (ClientData, ClientError, Fido2Client,
                          PinRequiredError, WindowsClient)
from fido2.ctap import STATUS, CtapError
from fido2.ctap2 import AttestedCredentialData, AuthenticatorData
from fido2.hid import CtapHidDevice
from fido2.server import Fido2Server
from fido2.utils import websafe_decode, websafe_encode
from fido2.webauthn import AuthenticatorAssertionResponse


def generate(args=[]):
    def on_keepalive(status):
        if status == STATUS.UPNEEDED:  # Waiting for touch
            print("\nTouch your authenticator device now...\n")

    uv = "discouraged"

    if WindowsClient.is_available() and not ctypes.windll.shell32.IsUserAnAdmin():
        # Use the Windows WebAuthn API if available, and we're not running as admin
        client = WindowsClient("https://example.com")
    else:
        # Locate a device
        dev = next(CtapHidDevice.list_devices(), None)
        if dev is not None:
            print("Using USB HID channel.")
        else:
            try:
                from fido2.pcsc import CtapPcscDevice

                dev = next(CtapPcscDevice.list_devices(), None)
                print("Use NFC channel.")
            except Exception as e:
                print("NFC channel search error:", e)

    if not dev:
        print("No FIDO device found")
        sys.exit(1)

    # create a FIDO 2 client using the origin https://example.com
    # todo: use individual, fictive RPs
    client = Fido2Client(dev, "https://example.com")

    # prefer UV if supported and configured
    if client.info.options.get("uv"):
        uv = "preferred"
        print("Authenticator supports User Verification")

    server = Fido2Server(
        {"id": "example.com", "name": "Example RP"}, attestation="direct")

    user = {"id": b"user_id", "name": "A. User"}

    # prepare parameters for makeCredential
    create_options, state = server.register_begin(
        user, user_verification=uv, authenticator_attachment="cross-platform"
    )

    try:
        result = client.make_credential(
            create_options["publicKey"], on_keepalive=on_keepalive
        )
    except PinRequiredError as e:
        if isinstance(e.cause, CtapError):
            print(e.cause)
        result = client.make_credential(
            create_options["publicKey"],
            on_keepalive=on_keepalive,
            pin=getpass("Enter PIN: "),
        )
    except ClientError as e:
        print(f"error: {ClientError.ERR(e.code)} ({e.code})")
        return

    # complete registration
    auth_data = server.register_complete(
        state, result.client_data, result.attestation_object
    )
    credentials = [auth_data.credential_data]

    id = hashlib.sha256(auth_data.credential_data.credential_id).hexdigest()
    print(f"New credential {id} has been created!")

    credential = {id: {
        "websafe_encoded": websafe_encode(auth_data.credential_data)}
    }

    # store credential
    try:
        with open("credentials.json", "r") as f:
            contents = json.loads(f.read())
    except Exception as e:
        contents = {}

    with open("credentials.json", "w+") as f:
        contents.update(credential)
        json.dump(contents, f, ensure_ascii=False, indent=4)

    # print("CLIENT DATA:", result.client_data)
    # print("ATTESTATION OBJECT:", result.attestation_object)
    # print()
    # print("CREDENTIAL DATA:", auth_data.credential_data)
    # print(websafe_encode(auth_data.credential_data))


# load credentials' meta data from file
def load_credential(id):
    try:
        with open("credentials.json") as f:
            contents = json.load(f)
    except Exception as e:
        return None

    if contents[id] is not None:
        return AttestedCredentialData(
            websafe_decode(contents[id]["websafe_encoded"]))
    else:
        return None


def serializeAuthenticatorAssertionResponse(data):
    # extract data
    transport = {}

    transport.update({"client_data": websafe_encode(data.client_data)})
    transport.update({"signature": websafe_encode(data.signature)})
    transport.update({"credential_id": websafe_encode(data.credential_id)})
    # transport.update({"authenticator_data":
    #    {"rp_id_hash": websafe_encode(data.authenticator_data.rp_id_hash),
    #           "flags": data.authenticator_data.flags,
    #           "counter": data.authenticator_data.counter}})
    transport.update(
        {"authenticator_data": websafe_encode(data.authenticator_data)})

    # returns dict object that can easily be serialized to json
    return transport


def unserializeAuthenticatorAssertionResponse(data):
    cl_da = websafe_decode(data["client_data"])
    aar = AuthenticatorAssertionResponse(
        client_data=ClientData(websafe_decode(data["client_data"])),
        signature=websafe_decode(data["signature"]),
        credential_id=websafe_decode(data["credential_id"]),
        #        rp_id_hash=websafe_decode(data["authenticator_data"]["rp_id_hash"]),
        #        flags=data["authenticator_data"]["flags"],
        #        counter=data["authenticator_data"]["counter"]
        authenticator_data=AuthenticatorData(
            websafe_decode(data["authenticator_data"])),
        user_handle=None,
        extension_results={}
    )
    return aar


def authenticate(args=[]):

    url = args[1].split("/")

    credential = url[-1]
    credentials = [load_credential(credential)]

    # fetch challenge
    r = requests.get(args[1], verify=False)
    challenge = r.json()["challenge"]

    # prepare parameters for getAssertion
    def on_keepalive(status):
        if status == STATUS.UPNEEDED:  # Waiting for touch
            print("\nTouch your authenticator device now...\n")

    uv = "discouraged"

    if WindowsClient.is_available() and not ctypes.windll.shell32.IsUserAnAdmin():
        # use the Windows WebAuthn API if available, and we're not running as admin
        client = WindowsClient("https://example.com")
    else:
        # Locate a device
        dev = next(CtapHidDevice.list_devices(), None)
        if dev is not None:
            print("Using USB HID channel.")
        else:
            try:
                from fido2.pcsc import CtapPcscDevice

                dev = next(CtapPcscDevice.list_devices(), None)
                print("Use NFC channel.")
            except Exception as e:
                print("NFC channel search error:", e)

    if not dev:
        print("No FIDO device found")
        sys.exit(1)

    # set up a FIDO 2 client using the origin https://example.com
    client = Fido2Client(dev, "https://example.com")

    # prefer UV if supported and configured
    if client.info.options.get("uv"):
        uv = "preferred"
        print("Authenticator supports User Verification")

    server = Fido2Server(
        {"id": "example.com", "name": "Example RP"}, attestation="direct")
    request_options, state = server.authenticate_begin(
        credentials, user_verification=uv, challenge=challenge.encode())

    # state['challenge'] = base64.b64encode(b'Thomas Alexander Kilian')
    # print(state)

    # authenticate the credential
    try:
        result = client.get_assertion(
            request_options["publicKey"], on_keepalive=on_keepalive
        )
    except PinRequiredError as e:
        if isinstance(e.cause, CtapError):
            print(e.cause)

        result = client.get_assertion(
            request_options["publicKey"],
            on_keepalive=on_keepalive,
            pin=getpass("Enter PIN: "),
        )

    # only one cred is in allowCredentials, thus only one response.
    result = result.get_response(0)

    ser = serializeAuthenticatorAssertionResponse(result)

    payload = {"AAR": ser,
               "cred": websafe_encode(credentials[0])}

    # print("************")
    # print(payload)
    # print("************")

    requests.post(args[1].replace("recovery_approve_begin",
                  "recovery_approve_complete"), json=payload, verify=False)

    # result = unserializeAuthenticatorAssertionResponse(ser)

    # server = Fido2Server(
    #     {"id": "example.com", "name": "Example RP"}, attestation="direct")
    # request_options, state = server.authenticate_begin(
    #     credentials, user_verification=uv, challenge=challenge.encode())

    # # complete authenticator
    # server.authenticate_complete(
    #     state,
    #     credentials,
    #     result.credential_id,
    #     result.client_data,
    #     result.authenticator_data,
    #     result.signature,
    # )

    print("Credential authenticated! Request successful.")


def list(args=[]):
    try:
        with open("credentials.json") as f:
            contents = json.loads(f.read())
    except Exception as e:
        # print(e)
        contents = {}

    print("The following credentials are available (by ID)")
    for k in contents.keys():
        print(f"{k}")


def error():
    print("Invalid choice!")


def help(args=[]):
    print("1 Generate new credential")
    print("l List available credentials")
    print("a [URL] approve a request")
    print("h Help")
    print("q Quit")


def main():
    funcs = {"1": generate,
             "a": authenticate,
             "l": list,
             "q": exit,
             "h": help,
             "": lambda: None}

    print("Welcome to RePass!")
    print("What do you want to do?")
    help()

    while(True):
        try:
            choice = input().split()
        except:
            exit()
        if len(choice) > 1:
            funcs.get(choice[0], error)(choice)
        elif len(choice) == 1:
            funcs.get(choice[0], error)()
        else:
            funcs.get("", error)()


if __name__ == "__main__":
    main()

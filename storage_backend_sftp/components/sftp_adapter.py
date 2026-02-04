# Copyright 2017 Akretion (http://www.akretion.com).
# @author Sébastien BEAU <sebastien.beau@akretion.com>
# Copyright 2019 Camptocamp SA (http://www.camptocamp.com).
# Copyright 2020 ACSONE SA/NV (<http://acsone.eu>)
# @author Simone Orsi <simahawk@gmail.com>
# License LGPL-3.0 or later (http://www.gnu.org/licenses/lgpl).
import base64
import errno
import logging
import os
from contextlib import contextmanager
from io import StringIO

from odoo.addons.component.core import Component

_logger = logging.getLogger(__name__)

try:
    import paramiko
except ImportError as err:  # pragma: no cover
    _logger.debug(err)


def normalize_key_input(value):
    """Normalize key input to string content.

    Accepts:
        - str: file path or direct key content
        - bytes: key content as bytes
        - file-like object: readable object with key content

    Returns:
        str: the key content
    """
    if value is None:
        return None

    # Handle file-like objects (have read method)
    if hasattr(value, "read"):
        content = value.read()
        if hasattr(value, "seek"):
            value.seek(0)  # Reset for potential reuse
        if isinstance(content, bytes):
            return content.decode("utf-8")
        return content

    # Handle bytes
    if isinstance(value, bytes):
        return value.decode("utf-8")

    # Handle string (path or content)
    if isinstance(value, str):
        value = value.strip()

        # Check if it looks like a file path (not key content)
        is_path = value.startswith(("/", "~", "./", "../")) or (
            not value.startswith("-----")  # Not PEM format
            and not value.startswith("ssh-")  # Not SSH public key
            and len(value) < 500  # Paths are short
            and "\n" not in value  # Keys have newlines
        )

        if is_path:
            expanded_path = os.path.expanduser(value)
            if not os.path.isabs(expanded_path):
                # Relative paths from home directory
                expanded_path = os.path.join(os.path.expanduser("~"), expanded_path)

            if os.path.exists(expanded_path):
                with open(expanded_path, "r") as f:
                    return f.read()
            # If path doesn't exist but looks like a path, raise error
            if value.startswith(("/", "~", "./", "../")):
                raise FileNotFoundError(f"Key file not found: {expanded_path}")

        # It's direct content
        return value

    raise TypeError(f"Unsupported key input type: {type(value)}")


def sftp_mkdirs(client, path, mode=511):
    try:
        client.mkdir(path, mode)
    except IOError as e:
        if e.errno == errno.ENOENT and path:
            sftp_mkdirs(client, os.path.dirname(path), mode=mode)
            client.mkdir(path, mode)
        else:
            raise  # pragma: no cover


def load_ssh_key(ssh_key_input):
    """Load SSH private key from various input types.

    Args:
        ssh_key_input: str (path or content), bytes, or file-like object

    Returns:
        paramiko private key object
    """
    key_content = normalize_key_input(ssh_key_input)
    ssh_key_buffer = StringIO(key_content)

    # Build list of supported key classes.
    # Conditionally including DSSKey for backward compatibility with older
    # versions of paramiko
    pkey_classes = [
        paramiko.RSAKey,
        paramiko.ECDSAKey,
        paramiko.Ed25519Key,
    ]
    # Insert after RSAKey to maintain original order
    if hasattr(paramiko, "DSSKey"):
        pkey_classes.insert(1, paramiko.DSSKey)
    for pkey_class in pkey_classes:
        try:
            return pkey_class.from_private_key(ssh_key_buffer)
        except paramiko.SSHException:
            ssh_key_buffer.seek(0)  # reset the buffer "file"
    raise Exception("Invalid ssh private key")


def parse_hostkey(hostkey_input, hostname=None):
    """Parse a host key from various input types.

    Args:
        hostkey_input: str (path or content), bytes, or file-like object
        hostname: If provided, search for this host in known_hosts format

    Returns:
        paramiko key object
    """
    hostkey_str = normalize_key_input(hostkey_input)
    if not hostkey_str:
        return None

    lines = hostkey_str.strip().split("\n")

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        parts = line.split()

        # known_hosts format: hostname key-type key-data [comment]
        # direct format: key-type key-data [comment]
        if len(parts) >= 3 and not parts[0].startswith("ssh-"):
            # known_hosts format
            host_field, key_type, key_data = parts[0], parts[1], parts[2]
            # Check if hostname matches (supports comma-separated hosts)
            if hostname:
                hosts = host_field.split(",")
                if not any(
                    h == hostname or h.startswith(f"[{hostname}]") for h in hosts
                ):
                    continue
        elif len(parts) >= 2:
            # direct format: key-type key-data
            key_type, key_data = parts[0], parts[1]
        else:
            continue

        try:
            key_bytes = base64.b64decode(key_data)
        except Exception:
            continue

        try:
            if key_type == "ssh-rsa":
                return paramiko.RSAKey(data=key_bytes)
            elif key_type == "ssh-ed25519":
                return paramiko.Ed25519Key(data=key_bytes)
            elif key_type.startswith("ecdsa-"):
                return paramiko.ECDSAKey(data=key_bytes)
            elif key_type == "ssh-dss" and hasattr(paramiko, "DSSKey"):
                return paramiko.DSSKey(data=key_bytes)
        except paramiko.SSHException:
            continue

    raise ValueError(f"No valid host key found for {hostname or 'server'}")


@contextmanager
def sftp(backend):
    transport = paramiko.Transport((backend.sftp_server, backend.sftp_port))

    # Configure legacy algorithms if enabled (for older servers like banks)
    if backend.sftp_legacy_algorithms:
        security_options = transport.get_security_options()
        if "ssh-rsa" not in security_options.key_types:
            security_options.key_types = ("ssh-rsa",) + tuple(
                security_options.key_types
            )

    # Prepare hostkey verification if enabled
    hostkey = None
    if backend.sftp_verify_hostkey and backend.sftp_hostkey:
        hostkey = parse_hostkey(backend.sftp_hostkey, hostname=backend.sftp_server)

    # Connect with appropriate auth method
    if backend.sftp_auth_method == "pwd":
        transport.connect(
            username=backend.sftp_login,
            password=backend.sftp_password,
            hostkey=hostkey,
        )
    elif backend.sftp_auth_method == "ssh_key":
        # load_ssh_key handles path/content/bytes/file-object
        private_key = load_ssh_key(backend.sftp_ssh_private_key)
        transport.connect(
            username=backend.sftp_login,
            pkey=private_key,
            hostkey=hostkey,
        )
    client = paramiko.SFTPClient.from_transport(transport)
    yield client
    transport.close()


class SFTPStorageBackendAdapter(Component):
    _name = "sftp.adapter"
    _inherit = "base.storage.adapter"
    _usage = "sftp"

    def add(self, relative_path, data, **kwargs):
        with sftp(self.collection) as client:
            full_path = self._fullpath(relative_path)
            dirname = os.path.dirname(full_path)
            if dirname:
                try:
                    client.stat(dirname)
                except IOError as e:
                    if e.errno == errno.ENOENT:
                        sftp_mkdirs(client, dirname)
                    else:
                        raise  # pragma: no cover
            remote_file = client.open(full_path, "w")
            remote_file.write(data)
            remote_file.close()

    def get(self, relative_path, **kwargs):
        full_path = self._fullpath(relative_path)
        with sftp(self.collection) as client:
            file_data = client.open(full_path, "r")
            data = file_data.read()
            # TODO: shouldn't we close the file?
        return data

    def list(self, relative_path):
        full_path = self._fullpath(relative_path)
        with sftp(self.collection) as client:
            try:
                return client.listdir(full_path)
            except IOError as e:
                if e.errno == errno.ENOENT:
                    # The path do not exist return an empty list
                    return []
                else:
                    raise  # pragma: no cover

    def move_files(self, files, destination_path):
        _logger.debug("mv %s %s", files, destination_path)
        fp = self._fullpath
        with sftp(self.collection) as client:
            for sftp_file in files:
                dest_file_path = os.path.join(
                    destination_path, os.path.basename(sftp_file)
                )
                # Remove existing file at the destination path (an error is raised
                # otherwise)
                try:
                    client.lstat(dest_file_path)
                except FileNotFoundError:
                    _logger.debug("destination %s is free", dest_file_path)
                else:
                    client.unlink(dest_file_path)
                # Move the file using absolute filepaths
                client.rename(fp(sftp_file), fp(dest_file_path))

    def delete(self, relative_path):
        full_path = self._fullpath(relative_path)
        with sftp(self.collection) as client:
            return client.remove(full_path)

    def validate_config(self):
        with sftp(self.collection) as client:
            client.listdir()

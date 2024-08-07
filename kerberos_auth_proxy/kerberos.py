import asyncio
from logging import getLogger
import os
import time
from typing import Optional

from timelength import TimeLength

LOGGER = getLogger(__name__)


class KerberosCache:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialize()
        return cls._instance

    def _initialize(self):
        cache_name = os.getenv("KRB5CCNAME") or ""
        if not cache_name.startswith("DIR:"):
            raise ValueError("$KRB5CCNAME should be set to a DIR: type")

        self.realm = os.getenv('KERBEROS_REALM') or 'LOCALHOST'
        self.keytabs_path = os.getenv('KEYTABS_PATH') or '/etc/security/keytabs'
        self.expiration = TimeLength(os.getenv('CACHE_EXPIRATION') or '30m').total_seconds
        self.last_kinits: dict[str, float] = {}
        self.principals: dict[str, str] = {}
        self.lock = asyncio.Lock()

    async def get_principal(
        self, username: str, refresh: bool = False
    ) -> Optional[str]:
        if username in self.principals and not refresh:
            return self.principals[username]

        keytab_path = self.get_keytab_path(username)

        LOGGER.debug(f"getting principal from keytab {keytab_path}")
        principal = await self.get_principal_from_keytab(keytab_path)
        if not principal:
            LOGGER.info(f"no credencials available for user {username!r}")
            return

        self.principals[username] = principal
        return principal

    def get_keytab_path(self, username: str) -> str:
        return os.path.join(self.keytabs_path, username + ".keytab")

    async def login(self, username: str, refresh: bool = False) -> Optional[str]:
        """
        Returns a logged-in principal corresponding to the username

        None is returned in case of failure
        """
        principal = await self.get_principal(username, refresh=True)
        if not principal:
            LOGGER.info(f"no credencials available for user {username!r}")
            return

        keytab_path = self.get_keytab_path(username)

        LOGGER.debug(
            f"principal for {username!r} is {principal}, now acquiring cache lock"
        )

        async with self.lock:
            if not refresh and self.has_valid_login(username):
                LOGGER.info(f"now using cached credentials for user {username!r}")
                return principal

            LOGGER.info(
                f"getting credencials for {principal} from keytab {keytab_path}"
            )
            process = await asyncio.create_subprocess_exec(
                "kinit",
                "-kt",
                keytab_path,
                principal,
            )
            await process.communicate()
            if process.returncode != 0:
                LOGGER.warn(
                    f"failed to authenticate {username} using principal {principal}"
                )
                return

            self.last_kinits[username] = time.monotonic()
            self.principals[principal] = principal

            LOGGER.debug(
                f"successfully authenticated {principal} from keytab {keytab_path}"
            )
            return principal

    def has_valid_login(self, username) -> bool:
        last_kinit = self.last_kinits.get(username)
        return last_kinit and time.monotonic() - last_kinit <= self.expiration

    async def get_principal_from_keytab(self, keytab_path: str) -> Optional[str]:
        process = await asyncio.create_subprocess_exec(
            "klist",
            "-kt",
            keytab_path,
            stdout=asyncio.subprocess.PIPE,
        )
        stdout, _ = await process.communicate()
        if process.returncode != 0:
            return None

        stdout: str = stdout and stdout.decode("ascii") or ""
        for line in stdout.splitlines():
            parts = line.split(" ")
            if parts and parts[-1].endswith("@" + self.realm):
                return parts[-1]

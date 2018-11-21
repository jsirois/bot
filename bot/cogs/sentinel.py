import hashlib
import io
import logging
from typing import Set, List

from discord import Attachment, Message, HTTPException, NotFound
from discord.ext.commands import Bot

from bot.constants import Keys, Sentinel as Config

log = logging.getLogger(__name__)


# TODO: rate limiting
class Sentinel:
    """Checks message attachments for malicious content using VirusTotal."""
    BASE = "https://www.virustotal.com/vtapi/v2"
    FURL = f"{BASE}/file"

    def __init__(self, bot: Bot):
        self.bot = bot
        self.good = set()  # type: Set[str]
        self.queue = []  # type: List[Message]

    async def on_message(self, msg: Message):
        if msg.attachments:
            for attachment in msg.attachments:
                await self.scan_attachment(attachment)

    async def scan_attachment(self, attachment: Attachment):
        file = io.BytesIO()
        try:
            await attachment.save(file)
        except NotFound:
            log.warning(f"Attachment {attachment.filename} was "
                        f"deleted before it could be scanned")
            return
        except HTTPException as ex:
            log.error(f"Failed to scan attachment "
                      f"{attachment.filename}: {str(ex)} ")
            return
        file_data = file.getvalue()  # type: bytes
        file.close()  # Close the file object

        # Get a hash of the file
        file_hash = hashlib.sha256(file_data).hexdigest()  # type: str

        # Check if we've already scanned this (since the bot restarted)
        # Sort of handles any cases of common server-specific uploads
        if file_hash not in self.good:
            # Check if the file has been uploaded to VirusTotal already
            response = await self.get_report(file_hash)

            # If it's a new sample, do a full upload
            response = await self.scan_file(attachment.filename, file_data)

    async def handle_evil(self, attachment: Attachment):
        pass

    async def check_vt(self):
        pass

    async def scan_file(self, file_name: str, file_data: bytes):
        response = await self.bot.http_session.post(
            url=f"{self.FURL}/scan",
            files={'file': (file_name, file_data)},
            params={"apikey": Keys.virustotal}
        )
        return response

    async def get_report(self, resource: str):
        response = await self.bot.http_session.get(
            url=f"{self.FURL}/report",
            params={"apikey": Keys.virustotal, 'resource': resource}
        )
        return response

    def process_response(self, response):
        if response.status_code == 200:
            pass

        # Rate limit exceeded
        elif response.status_code == 204:
            pass

        # Cannot call without API key
        elif response.status_code == 403:
            pass

        # File not found
        elif response.status_code == 404:
            pass

        # Unknown!
        else:
            pass


def setup(bot: Bot):
    bot.add_cog(Sentinel(bot))
    log.info("Cog loaded: Sentinel")

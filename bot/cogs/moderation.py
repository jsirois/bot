import asyncio
import logging
import textwrap
from typing import Union

from aiohttp import ClientError
from discord import (
    Colour, Embed, Forbidden, Guild, HTTPException, Member, Object, User
)
from discord.ext.commands import (
    BadArgument, BadUnionArgument, Bot, Context, command, group
)

from bot import constants
from bot.cogs.modlog import ModLog
from bot.constants import Colours, Event, Icons, Keys, Roles, URLs
from bot.converters import InfractionSearchQuery
from bot.decorators import with_role
from bot.pagination import LinePaginator
from bot.utils.moderation import post_infraction
from bot.utils.scheduling import Scheduler, create_task
from bot.utils.time import parse_rfc1123, wait_until

log = logging.getLogger(__name__)

MODERATION_ROLES = Roles.owner, Roles.admin, Roles.moderator
INFRACTION_ICONS = {
    "Mute": Icons.user_mute,
    "Kick": Icons.sign_out,
    "Ban": Icons.user_ban
}
RULES_URL = "https://pythondiscord.com/about/rules"


def proxy_user(user_id: str) -> Object:
    try:
        user_id = int(user_id)
    except ValueError:
        raise BadArgument
    user = Object(user_id)
    user.mention = user.id
    user.avatar_url_as = lambda static_format: None
    return user


UserTypes = Union[Member, User, proxy_user]


class Moderation(Scheduler):
    """
    Server moderation tools.
    """

    def __init__(self, bot: Bot):
        self.bot = bot
        self.headers = {"X-API-KEY": Keys.site_api}
        self._muted_role = Object(constants.Roles.muted)
        super().__init__()

    @property
    def mod_log(self) -> ModLog:
        return self.bot.get_cog("ModLog")

    async def on_ready(self):
        # Schedule expiration for previous infractions
        response = await self.bot.http_session.get(
            URLs.site_infractions,
            params={"dangling": "true"},
            headers=self.headers
        )
        infraction_list = await response.json()
        for infraction_object in infraction_list:
            if infraction_object["expires_at"] is not None:
                self.schedule_task(self.bot.loop, infraction_object["id"], infraction_object)

    # region: Permanent infractions

    @with_role(*MODERATION_ROLES)
    @command()
    async def warn(self, ctx: Context, user: UserTypes, *, reason: str = None):
        """
        Create a warning infraction in the database for a user.

        **`user`:** Accepts user mention, ID, etc.
        **`reason`:** The reason for the warning.
        """

        response_object = await post_infraction(ctx, user, type="warning", reason=reason)
        if response_object is None:
            return

        notified = await self.notify_infraction(
            user=user,
            infr_type="Warning",
            reason=reason
        )

        dm_result = ":incoming_envelope: " if notified else ""
        action = f"{dm_result}:ok_hand: warned {user.mention}"

        if reason is None:
            await ctx.send(f"{action}.")
        else:
            await ctx.send(f"{action} ({reason}).")

        if notified:
            dm_status = "Sent"
            log_content = None
        else:
            dm_status = "**Failed**"
            log_content = ctx.author.mention

        await self.mod_log.send_log_message(
            icon_url=Icons.user_warn,
            colour=Colour(Colours.soft_red),
            title="Member warned",
            thumbnail=user.avatar_url_as(static_format="png"),
            text=textwrap.dedent(f"""
                Member: {user.mention} (`{user.id}`)
                Actor: {ctx.author}
                DM: {dm_status}
                Reason: {reason}
            """),
            content=log_content,
            footer=f"ID {response_object['infraction']['id']}"
        )

    @with_role(*MODERATION_ROLES)
    @command()
    async def kick(self, ctx: Context, user: Member, *, reason: str = None):
        """
        Kicks a user.

        **`user`:** Accepts user mention, ID, etc.
        **`reason`:** The reason for the kick.
        """

        if not await self.respect_role_hierarchy(ctx, user, 'kick'):
            # Ensure ctx author has a higher top role than the target user
            # Warning is sent to ctx by the helper method
            return

        response_object = await post_infraction(ctx, user, type="kick", reason=reason)
        if response_object is None:
            return

        notified = await self.notify_infraction(
            user=user,
            infr_type="Kick",
            reason=reason
        )

        self.mod_log.ignore(Event.member_remove, user.id)

        try:
            await user.kick(reason=reason)
            action_result = True
        except Forbidden:
            action_result = False

        dm_result = ":incoming_envelope: " if notified else ""
        action = f"{dm_result}:ok_hand: kicked {user.mention}"

        if reason is None:
            await ctx.send(f"{action}.")
        else:
            await ctx.send(f"{action} ({reason}).")

        dm_status = "Sent" if notified else "**Failed**"
        title = "Member kicked" if action_result else "Member kicked (Failed)"
        log_content = None if all((notified, action_result)) else ctx.author.mention

        await self.mod_log.send_log_message(
            icon_url=Icons.sign_out,
            colour=Colour(Colours.soft_red),
            title=title,
            thumbnail=user.avatar_url_as(static_format="png"),
            text=textwrap.dedent(f"""
                Member: {user.mention} (`{user.id}`)
                Actor: {ctx.message.author}
                DM: {dm_status}
                Reason: {reason}
            """),
            content=log_content,
            footer=f"ID {response_object['infraction']['id']}"
        )

    @with_role(*MODERATION_ROLES)
    @command()
    async def ban(self, ctx: Context, user: UserTypes, *, reason: str = None):
        """
        Create a permanent ban infraction in the database for a user.

        **`user`:** Accepts user mention, ID, etc.
        **`reason`:** The reason for the ban.
        """

        if not await self.respect_role_hierarchy(ctx, user, 'ban'):
            # Ensure ctx author has a higher top role than the target user
            # Warning is sent to ctx by the helper method
            return

        response_object = await post_infraction(ctx, user, type="ban", reason=reason)
        if response_object is None:
            return

        notified = await self.notify_infraction(
            user=user,
            infr_type="Ban",
            duration="Permanent",
            reason=reason
        )

        self.mod_log.ignore(Event.member_ban, user.id)
        self.mod_log.ignore(Event.member_remove, user.id)

        try:
            await ctx.guild.ban(user, reason=reason, delete_message_days=0)
            action_result = True
        except Forbidden:
            action_result = False

        dm_result = ":incoming_envelope: " if notified else ""
        action = f"{dm_result}:ok_hand: permanently banned {user.mention}"

        if reason is None:
            await ctx.send(f"{action}.")
        else:
            await ctx.send(f"{action} ({reason}).")

        dm_status = "Sent" if notified else "**Failed**"
        log_content = None if all((notified, action_result)) else ctx.author.mention
        title = "Member permanently banned"
        if not action_result:
            title += " (Failed)"

        await self.mod_log.send_log_message(
            icon_url=Icons.user_ban,
            colour=Colour(Colours.soft_red),
            title=title,
            thumbnail=user.avatar_url_as(static_format="png"),
            text=textwrap.dedent(f"""
                Member: {user.mention} (`{user.id}`)
                Actor: {ctx.message.author}
                DM: {dm_status}
                Reason: {reason}
            """),
            content=log_content,
            footer=f"ID {response_object['infraction']['id']}"
        )

    @with_role(*MODERATION_ROLES)
    @command()
    async def mute(self, ctx: Context, user: Member, *, reason: str = None):
        """
        Create a permanent mute infraction in the database for a user.

        **`user`:** Accepts user mention, ID, etc.
        **`reason`:** The reason for the mute.
        """

        response_object = await post_infraction(ctx, user, type="mute", reason=reason)
        if response_object is None:
            return

        self.mod_log.ignore(Event.member_update, user.id)
        await user.add_roles(self._muted_role, reason=reason)

        notified = await self.notify_infraction(
            user=user,
            infr_type="Mute",
            duration="Permanent",
            reason=reason
        )

        dm_result = ":incoming_envelope: " if notified else ""
        action = f"{dm_result}:ok_hand: permanently muted {user.mention}"

        if reason is None:
            await ctx.send(f"{action}.")
        else:
            await ctx.send(f"{action} ({reason}).")

        if notified:
            dm_status = "Sent"
            log_content = None
        else:
            dm_status = "**Failed**"
            log_content = ctx.author.mention

        await self.mod_log.send_log_message(
            icon_url=Icons.user_mute,
            colour=Colour(Colours.soft_red),
            title="Member permanently muted",
            thumbnail=user.avatar_url_as(static_format="png"),
            text=textwrap.dedent(f"""
                Member: {user.mention} (`{user.id}`)
                Actor: {ctx.message.author}
                DM: {dm_status}
                Reason: {reason}
            """),
            content=log_content,
            footer=f"ID {response_object['infraction']['id']}"
        )

    # endregion
    # region: Temporary infractions

    @with_role(*MODERATION_ROLES)
    @command()
    async def tempmute(self, ctx: Context, user: Member, duration: str, *, reason: str = None):
        """
        Create a temporary mute infraction in the database for a user.

        **`user`:** Accepts user mention, ID, etc.
        **`duration`:** The duration for the temporary mute infraction
        **`reason`:** The reason for the temporary mute.
        """

        response_object = await post_infraction(
            ctx, user, type="mute", reason=reason, duration=duration
        )
        if response_object is None:
            return

        self.mod_log.ignore(Event.member_update, user.id)
        await user.add_roles(self._muted_role, reason=reason)

        notified = await self.notify_infraction(
            user=user,
            infr_type="Mute",
            duration=duration,
            reason=reason
        )

        infraction_object = response_object["infraction"]
        infraction_expiration = infraction_object["expires_at"]

        self.schedule_task(ctx.bot.loop, infraction_object["id"], infraction_object)

        dm_result = ":incoming_envelope: " if notified else ""
        action = f"{dm_result}:ok_hand: muted {user.mention} until {infraction_expiration}"

        if reason is None:
            await ctx.send(f"{action}.")
        else:
            await ctx.send(f"{action} ({reason}).")

        if notified:
            dm_status = "Sent"
            log_content = None
        else:
            dm_status = "**Failed**"
            log_content = ctx.author.mention

        await self.mod_log.send_log_message(
            icon_url=Icons.user_mute,
            colour=Colour(Colours.soft_red),
            title="Member temporarily muted",
            thumbnail=user.avatar_url_as(static_format="png"),
            text=textwrap.dedent(f"""
                Member: {user.mention} (`{user.id}`)
                Actor: {ctx.message.author}
                DM: {dm_status}
                Reason: {reason}
                Duration: {duration}
                Expires: {infraction_expiration}
            """),
            content=log_content,
            footer=f"ID {response_object['infraction']['id']}"
        )

    @with_role(*MODERATION_ROLES)
    @command()
    async def tempban(
        self, ctx: Context, user: UserTypes, duration: str, *, reason: str = None
    ):
        """
        Create a temporary ban infraction in the database for a user.

        **`user`:** Accepts user mention, ID, etc.
        **`duration`:** The duration for the temporary ban infraction
        **`reason`:** The reason for the temporary ban.
        """

        if not await self.respect_role_hierarchy(ctx, user, 'tempban'):
            # Ensure ctx author has a higher top role than the target user
            # Warning is sent to ctx by the helper method
            return

        response_object = await post_infraction(
            ctx, user, type="ban", reason=reason, duration=duration
        )
        if response_object is None:
            return

        notified = await self.notify_infraction(
            user=user,
            infr_type="Ban",
            duration=duration,
            reason=reason
        )

        self.mod_log.ignore(Event.member_ban, user.id)
        self.mod_log.ignore(Event.member_remove, user.id)

        try:
            await ctx.guild.ban(user, reason=reason, delete_message_days=0)
            action_result = True
        except Forbidden:
            action_result = False

        infraction_object = response_object["infraction"]
        infraction_expiration = infraction_object["expires_at"]

        self.schedule_task(ctx.bot.loop, infraction_object["id"], infraction_object)

        dm_result = ":incoming_envelope: " if notified else ""
        action = f"{dm_result}:ok_hand: banned {user.mention} until {infraction_expiration}"

        if reason is None:
            await ctx.send(f"{action}.")
        else:
            await ctx.send(f"{action} ({reason}).")

        dm_status = "Sent" if notified else "**Failed**"
        log_content = None if all((notified, action_result)) else ctx.author.mention
        title = "Member temporarily banned"
        if not action_result:
            title += " (Failed)"

        await self.mod_log.send_log_message(
            icon_url=Icons.user_ban,
            colour=Colour(Colours.soft_red),
            thumbnail=user.avatar_url_as(static_format="png"),
            title=title,
            text=textwrap.dedent(f"""
                Member: {user.mention} (`{user.id}`)
                Actor: {ctx.message.author}
                DM: {dm_status}
                Reason: {reason}
                Duration: {duration}
                Expires: {infraction_expiration}
            """),
            content=log_content,
            footer=f"ID {response_object['infraction']['id']}"
        )

    # endregion
    # region: Permanent shadow infractions

    @with_role(*MODERATION_ROLES)
    @command(hidden=True, aliases=['shadowwarn', 'swarn', 'shadow_warn'])
    async def note(self, ctx: Context, user: UserTypes, *, reason: str = None):
        """
        Create a private infraction note in the database for a user.

        **`user`:** accepts user mention, ID, etc.
        **`reason`:** The reason for the warning.
        """

        response_object = await post_infraction(
            ctx, user, type="warning", reason=reason, hidden=True
        )
        if response_object is None:
            return

        if reason is None:
            await ctx.send(f":ok_hand: note added for {user.mention}.")
        else:
            await ctx.send(f":ok_hand: note added for {user.mention} ({reason}).")

        await self.mod_log.send_log_message(
            icon_url=Icons.user_warn,
            colour=Colour(Colours.soft_red),
            title="Member note added",
            thumbnail=user.avatar_url_as(static_format="png"),
            text=textwrap.dedent(f"""
                Member: {user.mention} (`{user.id}`)
                Actor: {ctx.message.author}
                Reason: {reason}
            """),
            footer=f"ID {response_object['infraction']['id']}"
        )

    @with_role(*MODERATION_ROLES)
    @command(hidden=True, aliases=['shadowkick', 'skick'])
    async def shadow_kick(self, ctx: Context, user: Member, *, reason: str = None):
        """
        Kicks a user.

        **`user`:** accepts user mention, ID, etc.
        **`reason`:** The reason for the kick.
        """

        if not await self.respect_role_hierarchy(ctx, user, 'shadowkick'):
            # Ensure ctx author has a higher top role than the target user
            # Warning is sent to ctx by the helper method
            return

        response_object = await post_infraction(ctx, user, type="kick", reason=reason, hidden=True)
        if response_object is None:
            return

        self.mod_log.ignore(Event.member_remove, user.id)

        try:
            await user.kick(reason=reason)
            action_result = True
        except Forbidden:
            action_result = False

        if reason is None:
            await ctx.send(f":ok_hand: kicked {user.mention}.")
        else:
            await ctx.send(f":ok_hand: kicked {user.mention} ({reason}).")

        title = "Member shadow kicked"
        if action_result:
            log_content = None
        else:
            log_content = ctx.author.mention
            title += " (Failed)"

        await self.mod_log.send_log_message(
            icon_url=Icons.sign_out,
            colour=Colour(Colours.soft_red),
            title=title,
            thumbnail=user.avatar_url_as(static_format="png"),
            text=textwrap.dedent(f"""
                Member: {user.mention} (`{user.id}`)
                Actor: {ctx.message.author}
                Reason: {reason}
            """),
            content=log_content,
            footer=f"ID {response_object['infraction']['id']}"
        )

    @with_role(*MODERATION_ROLES)
    @command(hidden=True, aliases=['shadowban', 'sban'])
    async def shadow_ban(self, ctx: Context, user: UserTypes, *, reason: str = None):
        """
        Create a permanent ban infraction in the database for a user.

        **`user`:** Accepts user mention, ID, etc.
        **`reason`:** The reason for the ban.
        """

        if not await self.respect_role_hierarchy(ctx, user, 'shadowban'):
            # Ensure ctx author has a higher top role than the target user
            # Warning is sent to ctx by the helper method
            return

        response_object = await post_infraction(ctx, user, type="ban", reason=reason, hidden=True)
        if response_object is None:
            return

        self.mod_log.ignore(Event.member_ban, user.id)
        self.mod_log.ignore(Event.member_remove, user.id)

        try:
            await ctx.guild.ban(user, reason=reason, delete_message_days=0)
            action_result = True
        except Forbidden:
            action_result = False

        if reason is None:
            await ctx.send(f":ok_hand: permanently banned {user.mention}.")
        else:
            await ctx.send(f":ok_hand: permanently banned {user.mention} ({reason}).")

        title = "Member permanently banned"
        if action_result:
            log_content = None
        else:
            log_content = ctx.author.mention
            title += " (Failed)"

        await self.mod_log.send_log_message(
            icon_url=Icons.user_ban,
            colour=Colour(Colours.soft_red),
            title=title,
            thumbnail=user.avatar_url_as(static_format="png"),
            text=textwrap.dedent(f"""
                Member: {user.mention} (`{user.id}`)
                Actor: {ctx.message.author}
                Reason: {reason}
            """),
            content=log_content,
            footer=f"ID {response_object['infraction']['id']}"
        )

    @with_role(*MODERATION_ROLES)
    @command(hidden=True, aliases=['shadowmute', 'smute'])
    async def shadow_mute(self, ctx: Context, user: Member, *, reason: str = None):
        """
        Create a permanent mute infraction in the database for a user.

        **`user`:** Accepts user mention, ID, etc.
        **`reason`:** The reason for the mute.
        """

        response_object = await post_infraction(ctx, user, type="mute", reason=reason, hidden=True)
        if response_object is None:
            return

        self.mod_log.ignore(Event.member_update, user.id)
        await user.add_roles(self._muted_role, reason=reason)

        if reason is None:
            await ctx.send(f":ok_hand: permanently muted {user.mention}.")
        else:
            await ctx.send(f":ok_hand: permanently muted {user.mention} ({reason}).")

        await self.mod_log.send_log_message(
            icon_url=Icons.user_mute,
            colour=Colour(Colours.soft_red),
            title="Member permanently muted",
            thumbnail=user.avatar_url_as(static_format="png"),
            text=textwrap.dedent(f"""
                Member: {user.mention} (`{user.id}`)
                Actor: {ctx.message.author}
                Reason: {reason}
            """),
            footer=f"ID {response_object['infraction']['id']}"
        )

    # endregion
    # region: Temporary shadow infractions

    @with_role(*MODERATION_ROLES)
    @command(hidden=True, aliases=["shadowtempmute, stempmute"])
    async def shadow_tempmute(
        self, ctx: Context, user: Member, duration: str, *, reason: str = None
    ):
        """
        Create a temporary mute infraction in the database for a user.

        **`user`:** Accepts user mention, ID, etc.
        **`duration`:** The duration for the temporary mute infraction
        **`reason`:** The reason for the temporary mute.
        """

        response_object = await post_infraction(
            ctx, user, type="mute", reason=reason, duration=duration, hidden=True
        )
        if response_object is None:
            return

        self.mod_log.ignore(Event.member_update, user.id)
        await user.add_roles(self._muted_role, reason=reason)

        infraction_object = response_object["infraction"]
        infraction_expiration = infraction_object["expires_at"]

        self.schedule_expiration(ctx.bot.loop, infraction_object)

        if reason is None:
            await ctx.send(f":ok_hand: muted {user.mention} until {infraction_expiration}.")
        else:
            await ctx.send(
                f":ok_hand: muted {user.mention} until {infraction_expiration} ({reason})."
            )

        await self.mod_log.send_log_message(
            icon_url=Icons.user_mute,
            colour=Colour(Colours.soft_red),
            title="Member temporarily muted",
            thumbnail=user.avatar_url_as(static_format="png"),
            text=textwrap.dedent(f"""
                Member: {user.mention} (`{user.id}`)
                Actor: {ctx.message.author}
                Reason: {reason}
                Duration: {duration}
                Expires: {infraction_expiration}
            """),
            footer=f"ID {response_object['infraction']['id']}"
        )

    @with_role(*MODERATION_ROLES)
    @command(hidden=True, aliases=["shadowtempban, stempban"])
    async def shadow_tempban(
            self, ctx: Context, user: UserTypes, duration: str, *, reason: str = None
    ):
        """
        Create a temporary ban infraction in the database for a user.

        **`user`:** Accepts user mention, ID, etc.
        **`duration`:** The duration for the temporary ban infraction
        **`reason`:** The reason for the temporary ban.
        """

        if not await self.respect_role_hierarchy(ctx, user, 'shadowtempban'):
            # Ensure ctx author has a higher top role than the target user
            # Warning is sent to ctx by the helper method
            return

        response_object = await post_infraction(
            ctx, user, type="ban", reason=reason, duration=duration, hidden=True
        )
        if response_object is None:
            return

        self.mod_log.ignore(Event.member_ban, user.id)
        self.mod_log.ignore(Event.member_remove, user.id)

        try:
            await ctx.guild.ban(user, reason=reason, delete_message_days=0)
            action_result = True
        except Forbidden:
            action_result = False

        infraction_object = response_object["infraction"]
        infraction_expiration = infraction_object["expires_at"]

        self.schedule_expiration(ctx.bot.loop, infraction_object)

        if reason is None:
            await ctx.send(f":ok_hand: banned {user.mention} until {infraction_expiration}.")
        else:
            await ctx.send(
                f":ok_hand: banned {user.mention} until {infraction_expiration} ({reason})."
            )

        title = "Member temporarily banned"
        if action_result:
            log_content = None
        else:
            log_content = ctx.author.mention
            title += " (Failed)"

        # Send a log message to the mod log
        await self.mod_log.send_log_message(
            icon_url=Icons.user_ban,
            colour=Colour(Colours.soft_red),
            thumbnail=user.avatar_url_as(static_format="png"),
            title=title,
            text=textwrap.dedent(f"""
                Member: {user.mention} (`{user.id}`)
                Actor: {ctx.message.author}
                Reason: {reason}
                Duration: {duration}
                Expires: {infraction_expiration}
            """),
            content=log_content,
            footer=f"ID {response_object['infraction']['id']}"
        )

    # endregion
    # region: Remove infractions (un- commands)

    @with_role(*MODERATION_ROLES)
    @command()
    async def unmute(self, ctx: Context, user: Member):
        """
        Deactivates the active mute infraction for a user.

        **`user`:** Accepts user mention, ID, etc.
        """

        try:
            # check the current active infraction
            response = await self.bot.http_session.get(
                URLs.site_infractions_user_type_current.format(
                    user_id=user.id,
                    infraction_type="mute"
                ),
                headers=self.headers
            )

            response_object = await response.json()
            if "error_code" in response_object:
                return await ctx.send(
                    ":x: There was an error removing the infraction: "
                    f"{response_object['error_message']}"
                )

            infraction_object = response_object["infraction"]
            if infraction_object is None:
                # no active infraction
                return await ctx.send(
                    f":x: There is no active mute infraction for user {user.mention}."
                )

            await self._deactivate_infraction(infraction_object)
            if infraction_object["expires_at"] is not None:
                self.cancel_expiration(infraction_object["id"])

            notified = await self.notify_pardon(
                user=user,
                title="You have been unmuted.",
                content="You may now send messages in the server.",
                icon_url=Icons.user_unmute
            )

            if notified:
                dm_status = "Sent"
                dm_emoji = ":incoming_envelope: "
                log_content = None
            else:
                dm_status = "**Failed**"
                dm_emoji = ""
                log_content = ctx.author.mention

            await ctx.send(f"{dm_emoji}:ok_hand: Un-muted {user.mention}.")

            # Send a log message to the mod log
            await self.mod_log.send_log_message(
                icon_url=Icons.user_unmute,
                colour=Colour(Colours.soft_green),
                title="Member unmuted",
                thumbnail=user.avatar_url_as(static_format="png"),
                text=textwrap.dedent(f"""
                    Member: {user.mention} (`{user.id}`)
                    Actor: {ctx.message.author}
                    Intended expiry: {infraction_object['expires_at']}
                    DM: {dm_status}
                """),
                footer=infraction_object["id"],
                content=log_content
            )

        except Exception as e:
            log.exception("There was an error removing an infraction.", exc_info=e)
            await ctx.send(":x: There was an error removing the infraction.")

    @with_role(*MODERATION_ROLES)
    @command()
    async def unban(self, ctx: Context, user: UserTypes):
        """
        Deactivates the active ban infraction for a user.

        **`user`:** Accepts user mention, ID, etc.
        """

        try:
            # check the current active infraction
            response = await self.bot.http_session.get(
                URLs.site_infractions_user_type_current.format(
                    user_id=user.id,
                    infraction_type="ban"
                ),
                headers=self.headers
            )
            response_object = await response.json()
            if "error_code" in response_object:
                return await ctx.send(
                    ":x: There was an error removing the infraction: "
                    f"{response_object['error_message']}"
                )

            infraction_object = response_object["infraction"]
            if infraction_object is None:
                # no active infraction
                return await ctx.send(
                    f":x: There is no active ban infraction for user {user.mention}."
                )

            await self._deactivate_infraction(infraction_object)
            if infraction_object["expires_at"] is not None:
                self.cancel_expiration(infraction_object["id"])

            await ctx.send(f":ok_hand: Un-banned {user.mention}.")

            # Send a log message to the mod log
            await self.mod_log.send_log_message(
                icon_url=Icons.user_unban,
                colour=Colour(Colours.soft_green),
                title="Member unbanned",
                thumbnail=user.avatar_url_as(static_format="png"),
                text=textwrap.dedent(f"""
                    Member: {user.mention} (`{user.id}`)
                    Actor: {ctx.message.author}
                    Intended expiry: {infraction_object['expires_at']}
                """)
            )
        except Exception:
            log.exception("There was an error removing an infraction.")
            await ctx.send(":x: There was an error removing the infraction.")

    # endregion
    # region: Edit infraction commands

    @with_role(*MODERATION_ROLES)
    @group(name='infraction', aliases=('infr', 'infractions', 'inf'), invoke_without_command=True)
    async def infraction_group(self, ctx: Context):
        """Infraction manipulation commands."""

        await ctx.invoke(self.bot.get_command("help"), "infraction")

    @with_role(*MODERATION_ROLES)
    @infraction_group.group(name='edit', invoke_without_command=True)
    async def infraction_edit_group(self, ctx: Context):
        """Infraction editing commands."""

        await ctx.invoke(self.bot.get_command("help"), "infraction", "edit")

    @with_role(*MODERATION_ROLES)
    @infraction_edit_group.command(name="duration")
    async def edit_duration(self, ctx: Context, infraction_id: str, duration: str):
        """
        Sets the duration of the given infraction, relative to the time of
        updating.

        **`infraction_id`:** The ID (UUID) of the infraction.
        **`duration`:** The new duration of the infraction, relative to the
          time of updating. Use "permanent" to the infraction as permanent.
        """

        try:
            previous = await self.bot.http_session.get(
                URLs.site_infractions_by_id.format(
                    infraction_id=infraction_id
                ),
                headers=self.headers
            )

            previous_object = await previous.json()

            if duration == "permanent":
                duration = None
            # check the current active infraction
            response = await self.bot.http_session.patch(
                URLs.site_infractions,
                json={
                    "id": infraction_id,
                    "duration": duration
                },
                headers=self.headers
            )
            response_object = await response.json()
            if "error_code" in response_object or response_object.get("success") is False:
                return await ctx.send(
                    ":x: There was an error updating the infraction: "
                    f"{response_object['error_message']}"
                )

            infraction_object = response_object["infraction"]
            # Re-schedule
            self.cancel_task(infraction_id)
            loop = asyncio.get_event_loop()
            self.schedule_task(loop, infraction_object["id"], infraction_object)

            if duration is None:
                await ctx.send(f":ok_hand: Updated infraction: marked as permanent.")
            else:
                await ctx.send(
                    ":ok_hand: Updated infraction: set to expire on "
                    f"{infraction_object['expires_at']}."
                )

        except Exception:
            log.exception("There was an error updating an infraction.")
            await ctx.send(":x: There was an error updating the infraction.")
            return

        prev_infraction = previous_object["infraction"]

        # Get information about the infraction's user
        user_id = int(infraction_object["user"]["user_id"])
        user = ctx.guild.get_member(user_id)

        if user:
            member_text = f"{user.mention} (`{user.id}`)"
            thumbnail = user.avatar_url_as(static_format="png")
        else:
            member_text = f"`{user_id}`"
            thumbnail = None

        # The infraction's actor
        actor_id = int(infraction_object["actor"]["user_id"])
        actor = ctx.guild.get_member(actor_id) or f"`{actor_id}`"

        await self.mod_log.send_log_message(
            icon_url=Icons.pencil,
            colour=Colour.blurple(),
            title="Infraction edited",
            thumbnail=thumbnail,
            text=textwrap.dedent(f"""
                Member: {member_text}
                Actor: {actor}
                Edited by: {ctx.message.author}
                Previous expiry: {prev_infraction['expires_at']}
                New expiry: {infraction_object['expires_at']}
            """)
        )

    @with_role(*MODERATION_ROLES)
    @infraction_edit_group.command(name="reason")
    async def edit_reason(self, ctx: Context, infraction_id: str, *, reason: str):
        """
        Sets the reason of the given infraction.
        **`infraction_id`:** The ID (UUID) of the infraction.
        **`reason`:** The new reason of the infraction.
        """

        try:
            previous = await self.bot.http_session.get(
                URLs.site_infractions_by_id.format(
                    infraction_id=infraction_id
                ),
                headers=self.headers
            )

            previous_object = await previous.json()

            response = await self.bot.http_session.patch(
                URLs.site_infractions,
                json={
                    "id": infraction_id,
                    "reason": reason
                },
                headers=self.headers
            )
            response_object = await response.json()
            if "error_code" in response_object or response_object.get("success") is False:
                return await ctx.send(
                    ":x: There was an error updating the infraction: "
                    f"{response_object['error_message']}"
                )

            await ctx.send(f":ok_hand: Updated infraction: set reason to \"{reason}\".")
        except Exception:
            log.exception("There was an error updating an infraction.")
            return await ctx.send(":x: There was an error updating the infraction.")

        new_infraction = response_object["infraction"]
        prev_infraction = previous_object["infraction"]

        # Get information about the infraction's user
        user_id = int(new_infraction["user"]["user_id"])
        user = ctx.guild.get_member(user_id)

        if user:
            user_text = f"{user.mention} (`{user.id}`)"
            thumbnail = user.avatar_url_as(static_format="png")
        else:
            user_text = f"`{user_id}`"
            thumbnail = None

        # The infraction's actor
        actor_id = int(new_infraction["actor"]["user_id"])
        actor = ctx.guild.get_member(actor_id) or f"`{actor_id}`"

        await self.mod_log.send_log_message(
            icon_url=Icons.pencil,
            colour=Colour.blurple(),
            title="Infraction edited",
            thumbnail=thumbnail,
            text=textwrap.dedent(f"""
                Member: {user_text}
                Actor: {actor}
                Edited by: {ctx.message.author}
                Previous reason: {prev_infraction['reason']}
                New reason: {new_infraction['reason']}
            """)
        )

    # endregion
    # region: Search infractions

    @with_role(*MODERATION_ROLES)
    @infraction_group.group(name="search", invoke_without_command=True)
    async def infraction_search_group(self, ctx: Context, query: InfractionSearchQuery):
        """
        Searches for infractions in the database.
        """

        if isinstance(query, User):
            await ctx.invoke(self.search_user, query)

        else:
            await ctx.invoke(self.search_reason, query)

    @with_role(*MODERATION_ROLES)
    @infraction_search_group.command(name="user", aliases=("member", "id"))
    async def search_user(self, ctx: Context, user: Union[User, proxy_user]):
        """
        Search for infractions by member.
        """

        try:
            response = await self.bot.http_session.get(
                URLs.site_infractions_user.format(
                    user_id=user.id
                ),
                params={"hidden": "True"},
                headers=self.headers
            )
            infraction_list = await response.json()
        except ClientError:
            log.exception(f"Failed to fetch infractions for user {user} ({user.id}).")
            await ctx.send(":x: An error occurred while fetching infractions.")
            return

        embed = Embed(
            title=f"Infractions for {user} ({len(infraction_list)} total)",
            colour=Colour.orange()
        )

        await self.send_infraction_list(ctx, embed, infraction_list)

    @with_role(*MODERATION_ROLES)
    @infraction_search_group.command(name="reason", aliases=("match", "regex", "re"))
    async def search_reason(self, ctx: Context, reason: str):
        """
        Search for infractions by their reason. Use Re2 for matching.
        """

        try:
            response = await self.bot.http_session.get(
                URLs.site_infractions,
                params={"search": reason, "hidden": "True"},
                headers=self.headers
            )
            infraction_list = await response.json()
        except ClientError:
            log.exception(f"Failed to fetch infractions matching reason `{reason}`.")
            await ctx.send(":x: An error occurred while fetching infractions.")
            return

        embed = Embed(
            title=f"Infractions matching `{reason}` ({len(infraction_list)} total)",
            colour=Colour.orange()
        )

        await self.send_infraction_list(ctx, embed, infraction_list)

    # endregion
    # region: Utility functions

    async def send_infraction_list(self, ctx: Context, embed: Embed, infractions: list):

        if not infractions:
            await ctx.send(f":warning: No infractions could be found for that query.")
            return

        lines = []
        for infraction in infractions:
            lines.append(
                self._infraction_to_string(infraction)
            )

        await LinePaginator.paginate(
            lines,
            ctx=ctx,
            embed=embed,
            empty=True,
            max_lines=3,
            max_size=1000
        )

    # endregion
    # region: Utility functions

    def schedule_expiration(self, loop: asyncio.AbstractEventLoop, infraction_object: dict):
        """
        Schedules a task to expire a temporary infraction.

        :param loop: the asyncio event loop
        :param infraction_object: the infraction object to expire at the end of the task
        """

        infraction_id = infraction_object["id"]
        if infraction_id in self.scheduled_tasks:
            return

        task: asyncio.Task = create_task(loop, self._scheduled_expiration(infraction_object))

        self.scheduled_tasks[infraction_id] = task

    def cancel_expiration(self, infraction_id: str):
        """
        Un-schedules a task set to expire a temporary infraction.
        :param infraction_id: the ID of the infraction in question
        """

        task = self.scheduled_tasks.get(infraction_id)
        if task is None:
            log.warning(f"Failed to unschedule {infraction_id}: no task found.")
            return
        task.cancel()
        log.debug(f"Unscheduled {infraction_id}.")
        del self.scheduled_tasks[infraction_id]

    async def _scheduled_task(self, infraction_object: dict):
        """
        A co-routine which marks an infraction as expired after the delay from the time of
        scheduling to the time of expiration. At the time of expiration, the infraction is
        marked as inactive on the website, and the expiration task is cancelled.

        :param infraction_object: the infraction in question
        """

        infraction_id = infraction_object["id"]

        # transform expiration to delay in seconds
        expiration_datetime = parse_rfc1123(infraction_object["expires_at"])
        await wait_until(expiration_datetime)

        log.debug(f"Marking infraction {infraction_id} as inactive (expired).")
        await self._deactivate_infraction(infraction_object)

        self.cancel_task(infraction_object["id"])

        # Notify the user that they've been unmuted.
        user_id = int(infraction_object["user"]["user_id"])
        guild = self.bot.get_guild(constants.Guild.id)
        await self.notify_pardon(
            user=guild.get_member(user_id),
            title="You have been unmuted.",
            content="You may now send messages in the server.",
            icon_url=Icons.user_unmute
        )

    async def _deactivate_infraction(self, infraction_object):
        """
        A co-routine which marks an infraction as inactive on the website. This co-routine does
        not cancel or un-schedule an expiration task.

        :param infraction_object: the infraction in question
        """

        guild: Guild = self.bot.get_guild(constants.Guild.id)
        user_id = int(infraction_object["user"]["user_id"])
        infraction_type = infraction_object["type"]

        if infraction_type == "mute":
            member: Member = guild.get_member(user_id)
            if member:
                # remove the mute role
                self.mod_log.ignore(Event.member_update, member.id)
                await member.remove_roles(self._muted_role)
            else:
                log.warning(f"Failed to un-mute user: {user_id} (not found)")
        elif infraction_type == "ban":
            user: Object = Object(user_id)
            await guild.unban(user)

        await self.bot.http_session.patch(
            URLs.site_infractions,
            headers=self.headers,
            json={
                "id": infraction_object["id"],
                "active": False
            }
        )

    def _infraction_to_string(self, infraction_object):
        actor_id = int(infraction_object["actor"]["user_id"])
        guild: Guild = self.bot.get_guild(constants.Guild.id)
        actor = guild.get_member(actor_id)
        active = infraction_object["active"] is True
        user_id = int(infraction_object["user"]["user_id"])
        hidden = infraction_object.get("hidden", False) is True

        lines = textwrap.dedent(f"""
            {"**===============**" if active else "==============="}
            Status: {"__**Active**__" if active else "Inactive"}
            User: {self.bot.get_user(user_id)} (`{user_id}`)
            Type: **{infraction_object["type"]}**
            Shadow: {hidden}
            Reason: {infraction_object["reason"] or "*None*"}
            Created: {infraction_object["inserted_at"]}
            Expires: {infraction_object["expires_at"] or "*Permanent*"}
            Actor: {actor.mention if actor else actor_id}
            ID: `{infraction_object["id"]}`
            {"**===============**" if active else "==============="}
        """)

        return lines.strip()

    async def notify_infraction(
            self, user: Union[User, Member], infr_type: str, duration: str = None,
            reason: str = None
    ):
        """
        Notify a user of their fresh infraction :)

        :param user: The user to send the message to.
        :param infr_type: The type of infraction, as a string.
        :param duration: The duration of the infraction.
        :param reason: The reason for the infraction.
        """

        if duration is None:
            duration = "N/A"

        if reason is None:
            reason = "No reason provided."

        embed = Embed(
            description=textwrap.dedent(f"""
                **Type:** {infr_type}
                **Duration:** {duration}
                **Reason:** {reason}
                """),
            colour=Colour(Colours.soft_red)
        )

        icon_url = INFRACTION_ICONS.get(infr_type, Icons.token_removed)
        embed.set_author(name="Infraction Information", icon_url=icon_url, url=RULES_URL)
        embed.title = f"Please review our rules over at {RULES_URL}"
        embed.url = RULES_URL

        return await self.send_private_embed(user, embed)

    async def notify_pardon(
            self, user: Union[User, Member], title: str, content: str,
            icon_url: str = Icons.user_verified
    ):
        """
        Notify a user that an infraction has been lifted.

        :param user: The user to send the message to.
        :param title: The title of the embed.
        :param content: The content of the embed.
        :param icon_url: URL for the title icon.
        """

        embed = Embed(
            description=content,
            colour=Colour(Colours.soft_green)
        )

        embed.set_author(name=title, icon_url=icon_url)

        return await self.send_private_embed(user, embed)

    async def send_private_embed(self, user: Union[User, Member], embed: Embed):
        """
        A helper method for sending an embed to a user's DMs.

        :param user: The user to send the embed to.
        :param embed: The embed to send.
        """

        # sometimes `user` is a `discord.Object`, so let's make it a proper user.
        user = await self.bot.get_user_info(user.id)

        try:
            await user.send(embed=embed)
            return True
        except (HTTPException, Forbidden):
            log.debug(
                f"Infraction-related information could not be sent to user {user} ({user.id}). "
                "They've probably just disabled private messages."
            )
            return False

    async def log_notify_failure(self, target: str, actor: Member, infraction_type: str):
        await self.mod_log.send_log_message(
            icon_url=Icons.token_removed,
            content=actor.mention,
            colour=Colour(Colours.soft_red),
            title="Notification Failed",
            text=(
                f"Direct message was unable to be sent.\nUser: {target.mention}\n"
                f"Type: {infraction_type}"
            )
        )

    # endregion

    async def __error(self, ctx, error):
        if isinstance(error, BadUnionArgument):
            if User in error.converters:
                await ctx.send(str(error.errors[0]))

    async def respect_role_hierarchy(self, ctx: Context, target: UserTypes, infr_type: str) -> bool:
        """
        Check if the highest role of the invoking member is greater than that of the target member.
        If this check fails, a warning is sent to the invoking ctx.

        Returns True always if target is not a discord.Member instance.

        :param ctx: The command context when invoked.
        :param target: The target of the infraction.
        :param infr_type: The type of infraction.
        """

        if not isinstance(target, Member):
            return True

        actor = ctx.author
        target_is_lower = target.top_role < actor.top_role
        if not target_is_lower:
            log.info(
                f"{actor} ({actor.id}) attempted to {infr_type} "
                f"{target} ({target.id}), who has an equal or higher top role."
            )
            await ctx.send(
                f":x: {actor.mention}, you may not {infr_type} "
                "someone with an equal or higher top role."
            )

        return target_is_lower


def setup(bot):
    bot.add_cog(Moderation(bot))
    log.info("Cog loaded: Moderation")

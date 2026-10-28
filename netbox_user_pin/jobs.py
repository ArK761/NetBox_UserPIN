from netbox.jobs import JobRunner, system_job

__all__ = ('RoleHousekeepingJob',)


@system_job(interval=5)
class RoleHousekeepingJob(JobRunner):
    """Every 5 minutes: expire invitations and moves, send reminders and return rights after temporary hand-overs."""

    class Meta:
        name = 'User PIN role housekeeping'

    def run(self, *args, **kwargs):
        from . import guests, roles
        roles.process_due()
        guests.announce_expiry()
        guests.report_changes()

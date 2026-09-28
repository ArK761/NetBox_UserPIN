from netbox.jobs import JobRunner, system_job

__all__ = ('RoleHousekeepingJob',)


@system_job(interval=60)
class RoleHousekeepingJob(JobRunner):
    """Hourly: expire invitations and moves, send reminders and return rights after temporary hand-overs."""

    class Meta:
        name = 'User PIN role housekeeping'

    def run(self, *args, **kwargs):
        from . import roles
        roles.process_due()

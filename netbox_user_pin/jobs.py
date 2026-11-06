from netbox.jobs import JobRunner, system_job

__all__ = ('RoleHousekeepingJob',)


@system_job(interval=5)
class RoleHousekeepingJob(JobRunner):
    """Every 5 minutes: expire invitations, moves and exceptions, send reminders and return rights after temporary hand-overs."""

    class Meta:
        name = 'User PIN role housekeeping'

    def run(self, *args, **kwargs):
        from . import areachanges, areas, guests, roles
        roles.process_due()
        areas.expire_exceptions()
        areachanges.report()
        guests.announce_expiry()
        guests.report_changes()
        areachanges.report_rule_mails()  # the summaries of the e-mail rules of the groups

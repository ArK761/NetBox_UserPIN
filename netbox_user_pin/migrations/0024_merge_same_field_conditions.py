from django.db import migrations


def merge(apps, schema_editor):
    """
    "Group is A" and "Group is B" saved as two conditions can never hold together (all conditions must), so the group
    saw nothing. Several "is" conditions of one field become one "is one of", several "is not" become "is none of".
    """
    AreaProfile = apps.get_model('netbox_user_pin', 'AreaProfile')
    merge = {'eq': 'in', 'ne': 'nin'}

    def key(condition):
        return condition.get('field'), condition.get('path'), condition.get('op')

    for profile in AreaProfile.objects.all():
        filters = dict(profile.filters or {})
        changed = False
        for target, spec in list(filters.items()):
            if not isinstance(spec, list):
                continue
            counts = {}
            for condition in spec:
                if condition.get('op') in merge and not isinstance(condition.get('value'), list):
                    counts[key(condition)] = counts.get(key(condition), 0) + 1
            result, merged = [], {}
            for condition in spec:
                if key(condition) in counts and counts[key(condition)] > 1 and \
                        not isinstance(condition.get('value'), list):
                    if key(condition) in merged:
                        merged[key(condition)]['value'].append(condition['value'])
                        changed = True
                        continue
                    condition = dict(condition, op=merge[condition['op']], value=[condition['value']])
                    if condition.get('lookup') == 'iexact':  # a name compared as text, whatever the case
                        condition.pop('lookup')
                        condition['ci'] = True
                    merged[key(dict(condition, op=[o for o, n in merge.items() if n == condition['op']][0]))] = condition
                result.append(condition)
            filters[target] = result
        if changed:
            profile.filters = filters
            profile.save(update_fields=['filters'])


class Migration(migrations.Migration):

    dependencies = [
        ('netbox_user_pin', '0023_userpin_failed_2fa'),
    ]

    operations = [
        migrations.RunPython(merge, migrations.RunPython.noop),
    ]

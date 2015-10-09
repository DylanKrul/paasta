#!/usr/bin/env python
import datetime
import logging

import humanize
import isodate
import requests_cache

import chronos_tools
from paasta_tools.mesos_tools import get_running_tasks_from_active_frameworks
from paasta_tools.mesos_tools import status_mesos_tasks_verbose
from paasta_tools.utils import datetime_from_utc_to_local
from paasta_tools.utils import decompose_job_id
from paasta_tools.utils import _log
from paasta_tools.utils import PaastaColors


log = logging.getLogger('__main__')
logging.basicConfig()


# Calls the 'manual start' endpoint in Chronos (https://mesos.github.io/chronos/docs/api.html#manually-starting-a-job),
# running the job now regardless of its 'schedule' and 'disabled' settings. The job's 'schedule' is left unmodified.
def start_chronos_job(service, instance, job_id, client, cluster, job_config, emergency=False):
    name = PaastaColors.cyan(job_id)
    log_reason = PaastaColors.red("EmergencyStart") if emergency else "Brutal bounce"
    log_immediate_run = " and running it immediately" if not job_config["disabled"] else ""
    _log(
        service_name=service,
        line="%s: Sending job %s to Chronos%s" % (log_reason, name, log_immediate_run),
        component="deploy",
        level="event",
        cluster=cluster,
        instance=instance
    )
    client.update(job_config)
    # TODO fail or give some output/feedback to user that the job won't run immediately if disabled (PAASTA-1244)
    if not job_config["disabled"]:
        client.run(job_id)


def stop_chronos_job(service, instance, client, cluster, existing_jobs, emergency=False):
    log_reason = PaastaColors.red("EmergencyStop") if emergency else "Brutal bounce"
    for job in existing_jobs:
        name = PaastaColors.cyan(job["name"])
        _log(
            service_name=service,
            line="%s: Killing all tasks for job %s" % (log_reason, name),
            component="deploy",
            level="event",
            cluster=cluster,
            instance=instance
        )
        job["disabled"] = True
        client.update(job)
        client.delete_tasks(job["name"])


def restart_chronos_job(service, instance, job_id, client, cluster, matching_jobs, job_config, emergency=False):
    stop_chronos_job(service, instance, client, cluster, matching_jobs, emergency)
    start_chronos_job(service, instance, job_id, client, cluster, job_config, emergency)


def get_matching_jobs(client, job_id, all_tags):
    """Use Chronos client `client` to get a list of configured Chronos jobs
    related to `job_id`, the full name of the job as calculated by
    create_complete_config().

    If all_tags is False, fetch only the exact job specified by job_id.

    If all_tags is True, fetch all jobs including those with different git and
    config hashes (i.e. older versions of jobs associated with a given service
    + instance).

    Returns a list of dicts, each representing the configuration of a Chronos
    job.
    """
    matching_jobs_pattern = r"^UNINITIALIZED PATTERN$"
    if all_tags:
        (service, instance, _) = decompose_job_id(job_id, spacer=chronos_tools.SPACER)
        # We add SPACER to the end as an anchor to prevent catching
        # "my_service my_job_extra" when looking for "my_service my_job".
        matching_jobs_pattern = r"^%s%s" % (chronos_tools.compose_job_id(service, instance), chronos_tools.SPACER)
    else:
        matching_jobs_pattern = r"^%s" % job_id
    matching_jobs = chronos_tools.lookup_chronos_jobs(matching_jobs_pattern, client, include_disabled=True)
    return matching_jobs


def get_short_task_id(task_id):
    """Return just the Chronos-generated timestamp section of a Mesos task id."""
    return task_id.split(chronos_tools.MESOS_TASK_SPACER)[1]


def _format_job_tag(job):
    job_tag = PaastaColors.red("UNKNOWN")
    job_id = job.get("name", None)
    if job_id:
        (_, _, job_tag) = decompose_job_id(job_id, spacer=chronos_tools.SPACER)
    return job_tag


def _format_disabled_status(job):
    status = PaastaColors.red("UNKNOWN")
    if job.get("disabled", False):
        status = PaastaColors.red("Disabled")
    else:
        status = PaastaColors.green("Enabled")
    return status


def _prettify_datetime(dt):
    """Prettify datetime objects further. Ignore hardcoded values like "never"."""
    pretty_dt = dt
    if isinstance(pretty_dt, datetime.datetime):
        dt_localtime = datetime_from_utc_to_local(dt)
        pretty_dt = "%s, %s" % (
            dt_localtime.strftime("%Y-%m-%dT%H:%M"),
            humanize.naturaltime(dt_localtime),
        )
    return pretty_dt


def _format_last_result(job):
    last_result = PaastaColors.red("UNKNOWN")
    last_result_when = PaastaColors.red("UNKNOWN")
    fail_result = PaastaColors.red("Fail")
    ok_result = PaastaColors.green("OK")
    last_error = job.get("lastError")
    last_success = job.get("lastSuccess")

    if not last_error and not last_success:
        last_result = PaastaColors.yellow("New")
        last_result_when = "never"
    elif not last_error:
        last_result = ok_result
        last_result_when = isodate.parse_datetime(last_success)
    elif not last_success:
        last_result = fail_result
        last_result_when = isodate.parse_datetime(last_error)
    else:
        fail_dt = isodate.parse_datetime(last_error)
        ok_dt = isodate.parse_datetime(last_success)
        if ok_dt > fail_dt:
            last_result = ok_result
            last_result_when = ok_dt
        else:
            last_result = fail_result
            last_result_when = fail_dt

    pretty_last_result_when = _prettify_datetime(last_result_when)
    return (last_result, pretty_last_result_when)


def _format_mesos_status(job, running_tasks):
    mesos_status = PaastaColors.red("UNKNOWN")
    num_tasks = len(running_tasks)
    if num_tasks == 0:
        mesos_status = PaastaColors.grey("Not running")
    elif num_tasks == 1:
        mesos_status = PaastaColors.yellow("Running")
    else:
        mesos_status = PaastaColors.red("Critical - %d tasks running (expected 1)" % num_tasks)
    return mesos_status


def format_chronos_job_status(job, desired_state, running_tasks, verbose):
    """Given a job, returns a pretty-printed human readable output regarding
    the status of the job.

    :param job: dictionary of the job status
    :param desired_state: a pretty-formatted string representing the
    job's started/stopped state as set with paasta emergency-[stop|start], e.g.
    the result of get_desired_state_human()
    :param running_tasks: a list of Mesos tasks associated with `job`, e.g. the
    result of mesos_tools.get_running_tasks_from_active_frameworks().
    """
    job_tag = _format_job_tag(job)
    disabled_state = _format_disabled_status(job)
    (last_result, last_result_when) = _format_last_result(job)
    mesos_status = _format_mesos_status(job, running_tasks)
    if verbose:
        mesos_status_verbose = status_mesos_tasks_verbose(job["name"], get_short_task_id)
        mesos_status = "%s\n%s" % (mesos_status, mesos_status_verbose)
    return (
        "Tag:        %(job_tag)s\n"
        "  Status:   %(disabled_state)s, %(desired_state)s\n"
        "  Last:     %(last_result)s (%(last_result_when)s)\n"
        "  Mesos:    %(mesos_status)s" % {
            "job_tag": job_tag,
            "disabled_state": disabled_state,
            "desired_state": desired_state,
            "last_result": last_result,
            "last_result_when": last_result_when,
            "mesos_status": mesos_status,
        }
    )


def status_chronos_jobs(jobs, job_config, verbose):
    """Returns a formatted string of the status of a list of chronos jobs

    :param jobs: list of dicts of chronos job info as returned by the chronos
        client
    :param job_config: dict containing configuration about these jobs as
        provided by chronos_tools.load_chronos_job_config().
    """
    if jobs == []:
        return "%s: chronos job is not set up yet" % PaastaColors.yellow("Warning")
    else:
        output = []
        desired_state = job_config.get_desired_state_human()
        for job in jobs:
            running_tasks = get_running_tasks_from_active_frameworks(job["name"])
            output.append(format_chronos_job_status(job, desired_state, running_tasks, verbose))
        return "\n".join(output)


def perform_command(command, service, instance, cluster, verbose, soa_dir):
    chronos_config = chronos_tools.load_chronos_config()
    client = chronos_tools.get_chronos_client(chronos_config)
    complete_job_config = chronos_tools.create_complete_config(service, instance, soa_dir=soa_dir)
    job_id = complete_job_config["name"]

    if command == "start":
        start_chronos_job(service, instance, job_id, client, cluster, complete_job_config, emergency=True)
    elif command == "stop":
        matching_jobs = get_matching_jobs(client, job_id, all_tags=True)
        stop_chronos_job(service, instance, client, cluster, matching_jobs, emergency=True)
    elif command == "restart":
        matching_jobs = get_matching_jobs(client, job_id, all_tags=True)
        restart_chronos_job(
            service,
            instance,
            job_id,
            client,
            cluster,
            matching_jobs,
            complete_job_config,
            emergency=True,
        )
    elif command == "status":
        # Setting up transparent cache for http API calls
        requests_cache.install_cache("paasta_serviceinit", backend="memory")
        # Verbose mode may want to display information about previous versions and configurations
        all_tags = False
        if verbose:
            all_tags = True
        matching_jobs = get_matching_jobs(client, job_id, all_tags)
        job_config = chronos_tools.load_chronos_job_config(service, instance, cluster, soa_dir=soa_dir)
        job_config = chronos_tools.load_chronos_job_config(
            service=service,
            instance=instance,
            cluster=cluster,
            soa_dir=soa_dir,
        )
        print status_chronos_jobs(matching_jobs, job_config, verbose)
    else:
        # The command parser shouldn't have let us get this far...
        raise NotImplementedError("Command %s is not implemented!" % command)
    return 0

# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4
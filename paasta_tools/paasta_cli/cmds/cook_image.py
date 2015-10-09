#!/usr/bin/env python
"""Contains methods used by the paasta client to build a docker image."""

import os
import sys

from paasta_tools.paasta_cli.cmds.check import makefile_responds_to
from paasta_tools.paasta_cli.utils import validate_service_name
from paasta_tools.utils import _log
from paasta_tools.utils import _run
from paasta_tools.utils import get_username


def add_subparser(subparsers):
    list_parser = subparsers.add_parser(
        'cook-image',
        description='Builds a docker image',
        help='Builds a docker image')

    list_parser.add_argument('-s', '--service',
                             help='Build docker image for this service. Leading '
                                  '"services-", as included in a Jenkins job name, '
                                  'will be stripped.',
                             required=True,
                             )
    list_parser.set_defaults(command=paasta_cook_image)


def paasta_cook_image(args, service=None, soa_dir=None):
    """Build a docker image"""
    if service:
        service_name = service
    else:
        service_name = args.service
    if service_name and service_name.startswith('services-'):
        service_name = service_name.split('services-', 1)[1]
    validate_service_name(service_name, soa_dir)

    run_env = os.environ.copy()
    default_tag = 'paasta-cook-image-%s-%s' % (service_name, get_username())
    tag = run_env.get('DOCKER_TAG', default_tag)
    run_env['DOCKER_TAG'] = tag

    if not makefile_responds_to('cook-image'):
        sys.stderr.write('ERROR: local-run now requires a cook-image target to be present in the Makefile. See '
                         'http://y/paasta-contract and PAASTA-601 for more details.\n')
        sys.exit(1)

    cmd = 'make cook-image'
    returncode, output = _run(
        cmd,
        env=run_env,
        log=True,
        component='build',
        service_name=service_name,
        loglevel='debug'
    )
    if returncode != 0:
        _log(
            service_name=service_name,
            line='ERROR: make cook-image failed for %s.' % service_name,
            component='build',
            level='event',
        )
        sys.exit(returncode)
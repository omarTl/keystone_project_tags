# Copyright 2013 Metacloud, Inc.
# Copyright 2012 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""Workflow Logic the Resource service."""

import uuid

from six.moves import http_client

from keystone.common import controller
from keystone.common import dependency
from keystone.common import utils
from keystone.common import validation
from keystone.common import wsgi
import keystone.conf
from keystone import exception
from keystone.i18n import _
from keystone.resource import schema


CONF = keystone.conf.CONF


@dependency.requires('resource_api')
class Tenant(controller.V2Controller):

    @controller.v2_deprecated
    def get_all_projects(self, request, **kw):
        """Get a list of all tenants for an admin user."""
        self.assert_admin(request)

        name = request.params.get('name')
        if name:
            return self._get_project_by_name(name)

        try:
            tenant_refs = self.resource_api.list_projects_in_domain(
                CONF.identity.default_domain_id)
        except exception.DomainNotFound:
            # If the default domain doesn't exist then there are no V2
            # projects.
            tenant_refs = []
        tenant_refs = [self.v3_to_v2_project(tenant_ref)
                       for tenant_ref in tenant_refs
                       if not tenant_ref.get('is_domain')]
        params = {
            'limit': request.params.get('limit'),
            'marker': request.params.get('marker'),
        }
        return self.format_project_list(tenant_refs, **params)

    def _assert_not_is_domain_project(self, project_id, project_ref=None):
        # Projects acting as a domain should not be visible via v2
        if not project_ref:
            project_ref = self.resource_api.get_project(project_id)
        if project_ref.get('is_domain'):
            raise exception.ProjectNotFound(project_id)

    @controller.v2_deprecated
    def get_project(self, request, tenant_id):
        # TODO(termie): this stuff should probably be moved to middleware
        self.assert_admin(request)
        ref = self.resource_api.get_project(tenant_id)
        self._assert_not_is_domain_project(tenant_id, ref)
        return {'tenant': self.v3_to_v2_project(ref)}

    def _get_project_by_name(self, tenant_name):
        # Projects acting as a domain should not be visible via v2
        ref = self.resource_api.get_project_by_name(
            tenant_name, CONF.identity.default_domain_id)
        self._assert_not_is_domain_project(ref['id'], ref)
        return {'tenant': self.v3_to_v2_project(ref)}

    # CRUD Extension
    @controller.v2_deprecated
    def create_project(self, request, tenant):
        tenant_ref = self._normalize_dict(tenant)

        validation.lazy_validate(schema.tenant_create, tenant)
        self.assert_admin(request)

        self.resource_api.ensure_default_domain_exists()

        tenant_ref['id'] = tenant_ref.get('id', uuid.uuid4().hex)
        tenant = self.resource_api.create_project(
            tenant_ref['id'],
            self._normalize_domain_id(request, tenant_ref),
            initiator=request.audit_initiator)
        return {'tenant': self.v3_to_v2_project(tenant)}

    @controller.v2_deprecated
    def update_project(self, request, tenant_id, tenant):
        validation.lazy_validate(schema.tenant_update, tenant)
        self.assert_admin(request)
        self._assert_not_is_domain_project(tenant_id)

        tenant_ref = self.resource_api.update_project(
            tenant_id, tenant, initiator=request.audit_initiator)
        return {'tenant': self.v3_to_v2_project(tenant_ref)}

    @controller.v2_deprecated
    def delete_project(self, request, tenant_id):
        self.assert_admin(request)
        self._assert_not_is_domain_project(tenant_id)
        self.resource_api.delete_project(
            tenant_id,
            initiator=request.audit_initiator
        )


@dependency.requires('resource_api')
class DomainV3(controller.V3Controller):
    collection_name = 'domains'
    member_name = 'domain'

    def __init__(self):
        super(DomainV3, self).__init__()
        self.get_member_from_driver = self.resource_api.get_domain

    @controller.protected()
    def create_domain(self, request, domain):
        validation.lazy_validate(schema.domain_create, domain)
        ref = self._assign_unique_id(self._normalize_dict(domain))
        ref = self.resource_api.create_domain(
            ref['id'], ref, initiator=request.audit_initiator
        )
        return DomainV3.wrap_member(request.context_dict, ref)

    @controller.filterprotected('enabled', 'name')
    def list_domains(self, request, filters):
        hints = DomainV3.build_driver_hints(request, filters)
        refs = self.resource_api.list_domains(hints=hints)
        return DomainV3.wrap_collection(request.context_dict,
                                        refs, hints=hints)

    @controller.protected()
    def get_domain(self, request, domain_id):
        ref = self.resource_api.get_domain(domain_id)
        return DomainV3.wrap_member(request.context_dict, ref)

    @controller.protected()
    def update_domain(self, request, domain_id, domain):
        validation.lazy_validate(schema.domain_update, domain)
        self._require_matching_id(domain_id, domain)
        ref = self.resource_api.update_domain(
            domain_id, domain, initiator=request.audit_initiator
        )
        return DomainV3.wrap_member(request.context_dict, ref)

    @controller.protected()
    def delete_domain(self, request, domain_id):
        return self.resource_api.delete_domain(
            domain_id, initiator=request.audit_initiator
        )


@dependency.requires('domain_config_api')
@dependency.requires('resource_api')
class DomainConfigV3(controller.V3Controller):
    member_name = 'config'

    @controller.protected()
    def create_domain_config(self, request, domain_id, config):
        self.resource_api.get_domain(domain_id)
        original_config = (
            self.domain_config_api.get_config_with_sensitive_info(domain_id))
        ref = self.domain_config_api.create_config(domain_id, config)
        if original_config:
            # Return status code 200, since config already existed
            return wsgi.render_response(body={self.member_name: ref})
        else:
            return wsgi.render_response(
                body={self.member_name: ref},
                status=(http_client.CREATED,
                        http_client.responses[http_client.CREATED]))

    def get_domain_config_wrapper(self, request, domain_id, group=None,
                                  option=None):
        if group and group == 'security_compliance':
            return self.get_security_compliance_domain_config(
                request, domain_id, group=group, option=option
            )
        else:
            return self.get_domain_config(
                request, domain_id, group=group, option=option
            )

    @controller.protected()
    def get_security_compliance_domain_config(self, request, domain_id,
                                              group=None, option=None):
        ref = self.domain_config_api.get_security_compliance_config(
            domain_id, group, option=option
        )
        return {self.member_name: ref}

    @controller.protected()
    def get_domain_config(self, request, domain_id, group=None, option=None):
        self.resource_api.get_domain(domain_id)
        ref = self.domain_config_api.get_config(domain_id, group, option)
        return {self.member_name: ref}

    @controller.protected()
    def update_domain_config(
            self, request, domain_id, config, group, option):
        self.resource_api.get_domain(domain_id)
        ref = self.domain_config_api.update_config(
            domain_id, config, group, option)
        return wsgi.render_response(body={self.member_name: ref})

    def update_domain_config_group(self, context, domain_id, group, config):
        self.resource_api.get_domain(domain_id)
        return self.update_domain_config(
            context, domain_id, config, group, option=None)

    def update_domain_config_only(self, context, domain_id, config):
        self.resource_api.get_domain(domain_id)
        return self.update_domain_config(
            context, domain_id, config, group=None, option=None)

    @controller.protected()
    def delete_domain_config(
            self, request, domain_id, group=None, option=None):
        self.resource_api.get_domain(domain_id)
        self.domain_config_api.delete_config(domain_id, group, option)

    @controller.protected()
    def get_domain_config_default(self, request, group=None, option=None):
        ref = self.domain_config_api.get_config_default(group, option)
        return {self.member_name: ref}


@dependency.requires('resource_api')
class ProjectV3(controller.V3Controller):
    collection_name = 'projects'
    member_name = 'project'

    def __init__(self):
        super(ProjectV3, self).__init__()
        self.get_member_from_driver = self.resource_api.get_project
 
    @classmethod
    def filter_by_attributes(cls, refs, hints):
        """Filter a list of references by filter values."""
        def _attr_match(ref_attr, val_attr):
            """Matche attributes allowing for booleans as strings.

            We test explicitly for a value that defines it as 'False',
            which also means that the existence of the attribute with
            no value implies 'True'

            """
            if type(ref_attr) is bool:
                return ref_attr == utils.attr_as_boolean(val_attr)
            else:
                return ref_attr == val_attr

        def _attr_partial_match(ref_attr, val_attr):
            """
            """
            return  val_attr in ref_attr or ref_attr == val_attr

        def _tags_any(matches, target_value):
            return any(matches)

        def _not_tags(matches, target_value):
            return not _tags(matches, target_value)

        def _not_tags_any(matches, target_value):
            return True if not target_value else not any(matches)

        def _tags(matches, target_value):
            return False if not target_value else all(matches)

        def _inexact_attr_match(filter, ref):
            """Apply an inexact filter to a result dict.

            :param filter: the filter in question
            :param ref: the dict to check

            :returns: True if there is a match

            """
            comparator = filter['comparator']
            filter_value = filter['value']
            key = filter['name'].replace("_", "-")
            
            if key in ref and 'tag' not in key:
                target_value = ref[key]
                if not filter['case_sensitive']:
                    # We only support inexact filters on strings so
                    # it's OK to use lower()
                    filter_value = filter_value.lower()
                    target_value = target_value.lower()

                if comparator == 'contains':
                    return (filter_value in target_value)
                elif comparator == 'startswith':
                    return target_value.startswith(filter_value)
                elif comparator == 'endswith':
                    return target_value.endswith(filter_value)
                else:
                    # We silently ignore unsupported filters
                    return True
            
            # NOTE(otleimat): Function pointers to helper functions
            # simplify tag filtering greatly because this is
            # essentially a large switch statement
            inexact_checker = {'tags-any': _tags_any, 'not-tags': _not_tags,
                               'not-tags-any': _not_tags_any, 'tags': _tags}
            # Only do a tag filter search if the request matches any of the
            # supported searches
            if key in inexact_checker.keys():
                target_value = ref['tags']
                if comparator == 'startswith' or comparator == 'endswith':
                    # If a 'startswith' or 'endswith' request is made, search
                    # any edge matches in the target_value and record an array
                    # of true/false values
                    edge_matches = [getattr(tag, comparator)(
                        filter_value) for tag in target_value]
                    # This is will route the matched occurences to whichever
                    # helper function needs to be hit
                    return inexact_checker[key](edge_matches, target_value)
                elif comparator == 'contains':
                    # a 'contains' search requires a different target array
                    contains_matches = [(filter_value in tag)
                                        for tag in target_value]
                    return inexact_checker[key](contains_matches, target_value)
                else:
                    return True
            return False
           
        for filter in hints.filters:
            if filter['comparator'] == 'equals':
                attr = filter['name']
                value = filter['value']
                if attr == 'tags':
                    refs = [r for r in refs if _attr_match(
                        utils.flatten_dict(r).get('tags'), sorted(value.split(',')))]
                elif attr == 'tags-any':
                    refs = [r for r in refs if _attr_partial_match(
                        utils.flatten_dict(r).get('tags'), sorted(value.split(',')))]
                elif attr == 'not-tags':
                    refs = [r for r in refs if not _attr_match(
                        utils.flatten_dict(r).get('tags'), sorted(value.split(',')))]
                elif attr == 'not-tags-any':
                    refs = [r for r in refs if not _attr_partial_match(
                        utils.flatten_dict(r).get('tags'), sorted(value.split(',')))]
                else:
                    refs = [r for r in refs if _attr_match(
                        utils.flatten_dict(r).get(attr), value)]
            else:
                # It might be an inexact filter
                refs = [r for r in refs if _inexact_attr_match(
                    filter, r)]

        return refs

    @controller.protected()
    def create_project(self, request, project):
        validation.lazy_validate(schema.project_create, project)
        ref = self._assign_unique_id(self._normalize_dict(project))

        if not ref.get('is_domain'):
            ref = self._normalize_domain_id(request, ref)
        # Our API requires that you specify the location in the hierarchy
        # unambiguously. This could be by parent_id or, if it is a top level
        # project, just by providing a domain_id.
        if not ref.get('parent_id'):
            ref['parent_id'] = ref.get('domain_id')

        try:
            ref = self.resource_api.create_project(
                ref['id'],
                ref,
                initiator=request.audit_initiator)
        except (exception.DomainNotFound, exception.ProjectNotFound) as e:
            raise exception.ValidationError(e)
        return ProjectV3.wrap_member(request.context_dict, ref)

    @controller.filterprotected('domain_id', 'enabled', 'name',
                                'parent_id', 'is_domain', 'tags',
                                'tags_any', 'not_tags', 'not_tags_any',
                                'tags-any', 'not-tags', 'not-tags-any')
    def list_projects(self, request, filters):
        hints = ProjectV3.build_driver_hints(request, filters)
        # If 'is_domain' has not been included as a query, we default it to
        # False (which in query terms means '0')
        if 'is_domain' not in request.params:
            hints.add_filter('is_domain', '0')
        # If filter with tags parameters below are passed in when listing
        # projects, proceed with querying projects with project names
        tag_params = ['tags', 'tags-any', 'not-tags', 'not-tags-any']
        is_in = lambda a, b: any(i in b for i in a)
        if is_in(request.params.keys(), tag_params):
            refs = self._project_list_tag_filter(request)
        else:
            refs = self.resource_api.list_projects(hints=hints)

        return ProjectV3.wrap_collection(request.context_dict,
                                         refs, hints=hints)

    def _project_list_tag_filter(self, request):
        # If one of the filter with tags parameters are found, point to
        # respective logic to proceed with querying
        params = request.params
        tag_map = {
            'tags': 'list_projects_with_tags',
            'tags-any': 'list_projects_with_tags_any',
            'not-tags': 'list_projects_not_tags',
            'not-tags-any': 'list_projects_not_tags_any'
        }
        for k, v in tag_map.items():
            if k in params:
                tag_set = params[k]
                if self.query_filter_is_true(tag_set):
                    tagged_projects = (getattr(self.resource_api, v)(tag_set))
        return tagged_projects

    def _expand_project_ref(self, request, ref):
        params = request.params
        context = request.context_dict

        parents_as_list = 'parents_as_list' in params and (
            self.query_filter_is_true(params['parents_as_list']))
        parents_as_ids = 'parents_as_ids' in params and (
            self.query_filter_is_true(params['parents_as_ids']))

        subtree_as_list = 'subtree_as_list' in params and (
            self.query_filter_is_true(params['subtree_as_list']))
        subtree_as_ids = 'subtree_as_ids' in params and (
            self.query_filter_is_true(params['subtree_as_ids']))

        # parents_as_list and parents_as_ids are mutually exclusive
        if parents_as_list and parents_as_ids:
            msg = _('Cannot use parents_as_list and parents_as_ids query '
                    'params at the same time.')
            raise exception.ValidationError(msg)

        # subtree_as_list and subtree_as_ids are mutually exclusive
        if subtree_as_list and subtree_as_ids:
            msg = _('Cannot use subtree_as_list and subtree_as_ids query '
                    'params at the same time.')
            raise exception.ValidationError(msg)

        if parents_as_list:
            parents = self.resource_api.list_project_parents(
                ref['id'], request.context.user_id)
            ref['parents'] = [ProjectV3.wrap_member(context, p)
                              for p in parents]
        elif parents_as_ids:
            ref['parents'] = self.resource_api.get_project_parents_as_ids(ref)

        if subtree_as_list:
            subtree = self.resource_api.list_projects_in_subtree(
                ref['id'], request.context.user_id)
            ref['subtree'] = [ProjectV3.wrap_member(context, p)
                              for p in subtree]
        elif subtree_as_ids:
            ref['subtree'] = self.resource_api.get_projects_in_subtree_as_ids(
                ref['id'])

    @controller.protected()
    def get_project(self, request, project_id):
        ref = self.resource_api.get_project(project_id)
        self._expand_project_ref(request, ref)
        return ProjectV3.wrap_member(request.context_dict, ref)

    @controller.protected()
    def update_project(self, request, project_id, project):
        validation.lazy_validate(schema.project_update, project)
        self._require_matching_id(project_id, project)
        ref = self.resource_api.update_project(
            project_id,
            project,
            initiator=request.audit_initiator)
        return ProjectV3.wrap_member(request.context_dict, ref)

    @controller.protected()
    def delete_project(self, request, project_id):
        return self.resource_api.delete_project(
            project_id,
            initiator=request.audit_initiator)


@dependency.requires('resource_api')
class ProjectTagV3(controller.V3Controller):
    collection_name = 'tags'
    member_name = 'tag'

    def __init__(self):
        super(ProjectTagV3, self).__init__()
        self.get_member_from_driver = self.resource_api.get_project_tag

    @classmethod
    def _add_self_referential_link(cls, context):
        return {'links': {'self': context.get('path')}}

    @classmethod
    def wrap_collection(cls, context, ref):
        new_ref = cls._add_self_referential_link(context)
        if not ref:
            ref = []
        new_ref[cls.collection_name] = ref
        return new_ref

    @classmethod
    def wrap_header(cls, context):
        try:
            url = context['host_url'] + context['environment']['REQUEST_URI']
        except Exception:
            url = context['path']
        headers = [('location', url)]
        return wsgi.render_response(headers=headers)

    @controller.protected()
    def create_project_tag(self, request, project_id, value):
        validation.lazy_validate(schema.project_tag_create, value)
        self.resource_api.create_project_tag(
            project_id, value, initiator=request.audit_initiator)
        return ProjectTagV3.wrap_header(request.context_dict)

    @controller.protected()
    def get_project_tag(self, request, project_id, value):
        self.resource_api.get_project_tag(project_id, value)

    @controller.protected()
    def delete_project_tag(self, request, project_id, value):
        self.resource_api.delete_project_tag(project_id, value)

    @controller.protected()
    def list_project_tags(self, request, project_id):
        ref = self.resource_api.list_project_tags(project_id)
        return ProjectTagV3.wrap_collection(request.context_dict, ref)

    @controller.protected()
    def update_project_tags(self, request, project_id, tags):
        validation.lazy_validate(schema.project_tags_update, tags)
        ref = self.resource_api.update_project_tags(
            project_id, tags, initiator=request.audit_initiator)
        return ProjectTagV3.wrap_collection(request.context_dict, ref)

    @controller.protected()
    def delete_project_tags(self, request, project_id):
        self.resource_api.update_project_tags(project_id, [])

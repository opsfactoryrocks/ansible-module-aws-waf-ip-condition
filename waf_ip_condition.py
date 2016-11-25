#!/usr/bin/python
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
DOCUMENTATION = '''
module: waf
short_description: create and delete WAF ACLs, Rules, Conditions, and Filters.
description:
  - Read the AWS documentation for WAF
    U(https://aws.amazon.com/documentation/waf/)
version_added: "2.1"

author:
    - "Mike Mochan(@mmochan)"
    - "Michael Crilly(@mrmcrilly)"
extends_documentation_fragment: aws
'''

EXAMPLES = '''
'''

RETURN = '''
task:
  description: The result of the create, or delete action.
  returned: success
  type: dictionary
'''

try:
    import botocore
    import boto3
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False

from ansible.module_utils.basic import *
from ansible.module_utils.ec2 import *

# import q
import hashlib
import json

def get_change_token():
  try:
    token = client.get_change_token()
    return token['ChangeToken']
  except botocore.exceptions.ClientError as e:
    module.fail_json(msg=str(e))

def condition_exists_by_name(name):
  for s in client.list_ip_sets()['IPSets']:
    if s['Name'] == name:
      return s['IPSetId']

  return False  

def format_update_list(raw, action):
  return [
    {
      'Action': action, 
      'IPSetDescriptor': {
        'Type': 'IPV4',
        'Value': ip['Value']
      }
    } for ip in raw
  ]

def format_ansible_ip_list(raw):
  return [
    {
      'Type': 'IPV4',
      'Value': v
    } for v in raw
  ]

def delete_ip_set(sid, ips):
  client.update_ip_set(
    IPSetId=sid,
    ChangeToken=get_change_token(),
    Updates=format_update_list(
      ips,
      'DELETE'
    )
  )

def create_ip_set(sid, ips):
  client.update_ip_set(
    IPSetId=sid,
    ChangeToken=get_change_token(),
    Updates=format_update_list(
      ips,
      'INSERT'
    )
  )

def equal_ip_sets(existing_ips, new_ips):
  for ip in existing_ips:
    if not ip in new_ips:
      return False

    if new_ips[new_ips.index(ip)] != ip:
      return False

  return True

def create_ip_condition():
  changed, result = False, None
  condition_id = condition_exists_by_name(module.params.get('name'))
  if condition_id:
    current_ip_set = client.get_ip_set(IPSetId=condition_id)
    if current_ip_set:
      current_ips = current_ip_set['IPSet']['IPSetDescriptors']
      new_ips = format_ansible_ip_list(module.params.get('ip_addresses'))

      current_ip_addresses = [ip['Value'] for ip in current_ips]
      new_ip_addresses = [ip['Value'] for ip in new_ips]

      if len(current_ip_addresses) != len(new_ip_addresses):
        changed = True

      if not equal_ip_sets(current_ip_addresses, new_ip_addresses) and \
         not changed:
        changed = True

      if changed and len(current_ips):
        delete_ip_set(condition_id, current_ips)

      try:
        create_ip_set(condition_id, new_ips)
      except Exception as e:
        if changed:
          create_ip_set(condition_id, current_ips)

        raise(e)

  else:
    new_ip_set = client.create_ip_set(
      Name=module.params.get('name'),
      ChangeToken=get_change_token()
    )

    if new_ip_set:
      create_ip_set(
        new_ip_set['IPSet']['IPSetId'],
        module.params.get('ip_addresses') 
      )
      changed, result = True, None

  return changed, result

def delete_ip_condition():
  pass

def main():
  global client
  global module

  argument_spec = ec2_argument_spec()
  argument_spec.update(dict(
      name=dict(required=True),
      ip_addresses=dict(type='list', required=False),
      state=dict(default='present', choices=['present', 'absent']),
      ),
  )
  module = AnsibleModule(argument_spec=argument_spec)
  state = module.params.get('state').lower()

  if not HAS_BOTO3:
      module.fail_json(msg='json and boto3 are required.')

  try:
      region, ec2_url, aws_connect_kwargs = get_aws_connection_info(
          module,
          boto3=True
      )

      client = boto3_conn(module,
          conn_type='client',
          resource='waf',
          region=region,
          endpoint=ec2_url,
          **aws_connect_kwargs
      )
  except botocore.exceptions.NoCredentialsError, e:
      module.fail_json(msg="Can't authorize connection - "+str(e))

  invocations = {
    "present": create_ip_condition,
    "absent": delete_ip_condition
  }

  (changed, result) = invocations[state]()
  module.exit_json(changed=changed, waf_ip_condition=result)

if __name__ == '__main__':
  main()

# Copyright 2024-2025 NetCracker Technology Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from datetime import datetime
import json
import os
import jq
import re
import subprocess
import tarfile
import logging


log = logging.getLogger(__name__)


def str_to_bool(s) -> bool:
    if isinstance(s, bool):
        return s
    if s.lower() == "true":
        return True
    elif s.lower() == "false":
        return False
    else:
        raise ValueError


def execute_command(command):
    log.info(f"Executing: {command}")
    p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    process_output, _ = p.communicate()
    for line in process_output.splitlines():
        decoded_line = line.decode("utf-8")
        if decoded_line != "":
            log.info(decoded_line)
    if p.returncode != 0:
        raise ChildProcessError(f"command {command} has failed with err code: {p.returncode}, err: {p.stderr.decode() if p.stderr is not None else ''}")


def extract_tarfile(path, extract_dir):
    os.makedirs(extract_dir, exist_ok=True)
    with tarfile.open(path, 'r:gz') as tar:
        tar.extractall(extract_dir)


def find_file_in_directory(directory, filename):
    for dp, dn, filenames in os.walk(directory):
        for f in filenames:
            if f == filename:
                return os.path.join(dp, f)
    return None


def check_schema_in_tar(tar_filename, schema_filename="schema.cql"):
    with tarfile.open(tar_filename, "r") as tar:
        members = tar.getmembers()
        for member in members:
            if member.name.endswith(schema_filename):
                return True
    return False


def replace_in_file(file_path, old_text, new_text):
    with open(file_path, 'r') as file:
        file_content = file.read()
    updated_content = re.sub(old_text, new_text, file_content)
    with open(file_path, 'w') as file:
        file.write(updated_content)


# returns a dict containing structure of host dirs with archives
# path: cassandra0-0.cassandra.cassandra.svc.cluster.local
# archives: ["cycling1-20240229_091301.tar.gz"]
def find_host_archives(vault: str) -> dict:
    backups = []
    files = os.listdir(vault)
    cassandra_dirs = [os.path.join(vault, x)
                      for x in files if os.path.isdir(os.path.join(vault, x)) and x.startswith("cassandra")]
    for cassandra_dir in cassandra_dirs:
        files = os.listdir(cassandra_dir)
        for file in files:
            if os.path.isfile(os.path.join(cassandra_dir, file)) and re.match(r".*-[0-9]{8}_[0-9]{6}.tar.gz", file):
                keyspace_name = re.match(
                    r"(.*)-[0-9]{8}_[0-9]{6}.tar.gz", file).group(1)
                backups.append(
                    {"path": cassandra_dir, "archive": file, "keyspace": keyspace_name})

    return backups


def extract_to_tmp_dir(path, archive_name) -> bool:
    archive_path = os.path.join(path, archive_name)
    if not check_schema_in_tar(archive_path):
        return ""
    tempDir = os.path.join(path, datetime.now().strftime("%Y%m%d_%H%M%S"))
    log.info(f"Extracting the archive {archive_path}")
    extract_tarfile(archive_path, tempDir)
    log.info("Extraction completed successfully.")
    return tempDir


def add_custom_vars(vault):
    metadata_file = None
    for root, dirs, files in os.walk(vault):
        for file in files:
            if file == "metadata.json":
                metadata_file = os.path.join(root, file)
                break
    if metadata_file:
        try:
            with open(metadata_file, 'r') as file:
                json_data = json.load(file)

            filter_expression = jq.compile('.')
            backup_info = filter_expression.input(json_data).first()

            logging.info(f"Backup info: {backup_info}")
        except Exception as e:
            logging.error(f"An unexpected error occurred: {e}")
        # Load existing custom vars
        custom_vars_file = os.path.join(vault, ".custom_vars")
        with open(custom_vars_file, 'r') as f:
            existing_custom_vars = json.load(f)

        existing_custom_vars['backup_info'] = backup_info

        temp_json_file = os.path.join(vault, "tmp.json")
        with open(temp_json_file, 'w') as f:
            json.dump(existing_custom_vars, f)
        os.replace(temp_json_file, custom_vars_file)
    else:
        logging.error(
            "metadata.json not found in the specified vault directory.")


def create_hosts_inventory(hosts_file_path, hosts_template_path):
    if not os.path.exists(hosts_file_path):
        cassandra_hosts = os.getenv('CASSANDRA_HOSTS')
        logging.debug(f"Cassndra_host: {cassandra_hosts}")
        with open(hosts_template_path, 'r') as template_file:
            template_contents = template_file.read()

        with open(hosts_file_path, 'w') as hosts_file:
            hosts_file.write(template_contents)

        with open(hosts_file_path, 'a') as hosts_file:
            for host in cassandra_hosts.split():
                hosts_file.write(host + '\n')


def get_new_table_path(table_path, generated_uuid):
    temp_path = os.path.realpath(os.path.join(table_path, ".."))
    temp_table = os.path.basename(table_path).split("-")[0]
    return os.path.join(temp_path, f"{temp_table}-{generated_uuid}")


def reformat_hostnames(cassandra_hosts):
    logging.info(f"cassandra Host: {cassandra_hosts}")
    hostnames = cassandra_hosts.split()
    result = [f"{hostname}" for hostname in hostnames]
    return result


def replace_uuid(schema_cql, keyspace_name, new_keyspace_name, generated_uuid):
    replace_in_file(schema_cql, keyspace_name, new_keyspace_name)
    replace_in_file(schema_cql, r'WITH ID =.*',
                    f"WITH ID = {generated_uuid}")

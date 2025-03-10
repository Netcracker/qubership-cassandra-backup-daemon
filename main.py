#!/usr/bin/env python3
import json
import os
import traceback
import argparse
import src.aws_restore
import logging
import src.backup_and_restore
import src.os_utils

TLS_ENABLED = src.os_utils.str_to_bool(os.getenv("TLS_ENABLED", False))
CASSANDRA_USERNAME = os.getenv('CASSANDRA_USERNAME')
CASSANDRA_PASSWORD = os.getenv('CASSANDRA_PASSWORD')

aws_access_key = os.getenv('AWS_ACCESS_KEY')
aws_secret_key = os.getenv('AWS_SECRET_KEY')
aws_region = os.getenv('AWS_REGION')


def parse_args():
    parser = argparse.ArgumentParser(description="Backup and Restore")

    parser.add_argument('action', choices=['backup', 'restore', 'list-dbs'],
                        help='Action to perform')
    parser.add_argument('-f', dest='vault', help='Vault option')
    parser.add_argument('-d', dest='databases', help='Databases option')
    parser.add_argument('-m', dest='dbmap', help='Dbmap option')
    parser.add_argument('-restore_roles', dest='restore_roles', help='Do we need to replace roles from backup', default=True)
    parser.add_argument('-restore_timestamp', dest='restore_timestamp',
                        help='Restore timestamp option')
    parser.add_argument('-ks_name', dest='ks_name',
                        help='KeySpace name option')
    parser.add_argument('-table', dest='table', help='Table option')
    parser.add_argument('-restored_table_name', dest='restored_table_name',
                        help='Restored table name option')

    return parser.parse_args()


def main():
    logging.basicConfig(level=logging.INFO,
                        format="[%(asctime)s][%(levelname)s][class=%(name)s][thread=%(thread)d] %(message)s",
                        datefmt="%Y-%m-%dT%H:%M:%S%z")

    hosts_file_path = '/opt/backup/hosts'
    hosts_template_path = '/opt/backup/hosts_template'
    src.os_utils.create_hosts_inventory(hosts_file_path, hosts_template_path)

    args = parse_args()

    if args.action == 'backup':
        try:
            src.backup_and_restore.cluster_backup(args.databases, args.vault,
                                                  TLS_ENABLED, CASSANDRA_USERNAME, CASSANDRA_PASSWORD)
        except Exception as e:
            logging.error(f"Backup has failed: {e}")
            exit(1)
    elif args.action == 'restore':
        restore = src.backup_and_restore.Restore(
            args.vault, args.dbmap, json.loads(args.databases), args.restore_roles)
        try:
            restore.restore()
        except Exception as e:
            logging.error(f"Restore has failed: {e}")
            logging.error(traceback.format_exc())
            exit(1)
    elif args.action == 'aws-restore':
        src.aws_restore.run_restore_aws(
            args.ks_name, args.table, args.restored_table_name, aws_access_key, aws_secret_key, aws_region)
    elif args.action == 'list-dbs':
        try:
            print("\n".join(src.backup_and_restore.list_databases(args.vault)))
        except Exception as e:
            logging.error(f"ListDB has failed: {e}")
            exit(1)
    else:
        logging.error("Invalid action:", args.action)
        exit(1)


if __name__ == "__main__":
    main()

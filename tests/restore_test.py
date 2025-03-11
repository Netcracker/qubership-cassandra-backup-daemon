import json
import random
import string

import pytest
from src.cassandra_client import CassandraClient
from src.backup_and_restore import Restore
from . import mocks, backups_generator
import os


def mock_sstable_loader(s, table_path):
    pass


@pytest.fixture(scope='function', autouse=True)
def mock(mocker):
    mocker.patch('src.os_utils.reformat_hostnames', return_value=None)

    clientMock = mocks.MockCassandraClient()
    mocker.patch.object(CassandraClient,
                        "__new__", return_value=clientMock)


def test_restore(mocker):

    temp_dir = os.path.abspath("./tests/generated")
    generator = backups_generator.BackupGenerator(
        1, 3, temp_dir)

    keyspaces = generator.generate_archives()
    restore = Restore(temp_dir, None, keyspaces)
    mocker.patch.object(Restore,
                        'sstable_loader', new=mock_sstable_loader)
    restore.restore()
    generator.clear()


def test_restore_clone(mocker):
    temp_dir = os.path.abspath("./tests/generated")
    generator = backups_generator.BackupGenerator(
        1, 3, temp_dir)

    keyspaces = generator.generate_archives()
    clone_names = {x: ''.join(random.choice(
        string.ascii_lowercase + string.digits) for _ in range(47)) for x in keyspaces}
    restore = Restore(
        temp_dir, json.dumps(clone_names), keyspaces)
    mocker.patch.object(Restore,
                        'sstable_loader', new=mock_sstable_loader)
    restore.restore()
    generator.clear()

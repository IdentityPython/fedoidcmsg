import os
import shutil
from time import sleep

from fedoidcmsg.file_system import FileSystem

ROOT = 'test_dir'


def test_create():
    if os.path.isdir(ROOT):
        shutil.rmtree(ROOT)

    fs = FileSystem(ROOT)
    fs['1'] = 'on'

    # should be a directory there now with one file

    assert os.path.isdir(ROOT)
    assert len(os.listdir(ROOT)) == 1

    # and that file should be name '1' and should contain 'on'

    fname = os.path.join(ROOT, '1')
    _dat = open(fname, 'r').read()
    assert _dat == 'on'


def test_keys_items():
    if os.path.isdir(ROOT):
        shutil.rmtree(ROOT)

    fs = FileSystem(ROOT)
    fs['1'] = 'on'

    assert list(fs.keys()) == ['1']
    assert dict([(k, v) for k, v in fs.items()]) == {'1': 'on'}


def test_create_reconnect():
    if os.path.isdir(ROOT):
        shutil.rmtree(ROOT)

    fs = FileSystem(ROOT)
    fs['1'] = 'on'

    fs2 = FileSystem(ROOT)

    assert list(fs2.keys()) == ['1']
    assert dict([(k, v) for k, v in fs2.items()]) == {'1': 'on'}


def test_detect_change():
    if os.path.isdir(ROOT):
        shutil.rmtree(ROOT)

    fs = FileSystem(ROOT)
    fs['1'] = 'one'
    fs['2'] = 'two'

    fname = os.path.join(ROOT, '3')
    fp = open(fname, 'w')
    fp.write('Three')
    fp.close()

    sleep(1)  # can't detect changes within 1 second

    fname = os.path.join(ROOT, '2')
    fp = open(fname, 'w')
    fp.write('twee')
    fp.close()

    assert set(fs.keys()) == {'1', '2', '3'}
    assert dict([(k, v) for k, v in fs.items()]) == {'1': 'one', '2': 'twee',
                                                     '3': 'Three'}

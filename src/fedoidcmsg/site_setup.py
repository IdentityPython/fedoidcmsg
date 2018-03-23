import datetime
import filecmp
import os
import shutil


def modification_date(filename):
    t = os.path.getmtime(filename)
    return datetime.datetime.fromtimestamp(t)


def copy_if_not_same(src, dst, overwrite=False):
    try:
        os.stat(dst)
    except OSError:
        shutil.copy(src, dst)
        return True

    if filecmp.cmp(src, dst):
        return False
    else:
        if overwrite:
            shutil.copy(src, dst)
            return True

    return False


def fedoidc_op_setup(distroot):
    for _dir in ['certs', 'keys', 'ms', 'jwks_dir', 'static', 'modules']:
        if os.path.isdir(_dir) is False:
            os.mkdir(_dir)

    _op_dir = os.path.join(distroot, 'fed_op')
    for _dir in ['static', 'htdocs', 'templates']:
        _src = os.path.join(_op_dir, _dir)
        if os.path.isdir(_dir):
            shutil.rmtree(_dir)
        shutil.copytree(_src, _dir)

    for _fname in ['fed_op_config.py', 'cpop.py', 'faop.py', 'setup.py']:
        _file = os.path.join(_op_dir, _fname)
        copy_if_not_same(_file, _fname, True)


def fedoidc_rp_setup(distroot):
    for _dir in ['certs', 'keys', 'ms', 'jwks_dir', 'static']:
        if os.path.isdir(_dir) is False:
            os.mkdir(_dir)

    _op_dir = os.path.join(distroot, 'fed_rp')
    for _dir in ['html']:
        _src = os.path.join(_op_dir, _dir)
        if os.path.isdir(_dir):
            shutil.rmtree(_dir)
        shutil.copytree(_src, _dir)

    for _fname in ['fed_rp_conf.py', 'farp.py', 'cprp.py']:
        _file = os.path.join(_op_dir, _fname)
        copy_if_not_same(_file, _fname, True)

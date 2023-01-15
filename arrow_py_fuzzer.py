#!/usr/bin/python3

# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
""" Harnass for fuzzing https://github.com/arrow-py/arrow.git """

import sys
import struct
import atheris
import arrow

def test_get_string(inp):
    """ Testing arrow get method for string """
    try:
        date = arrow.get(inp)
        date.timestamp()
    except arrow.ParserError:
        return
    except ValueError:
        return
    except OverflowError:
        return

def test_get_float(inp):
    """ Testing arrow get method for float """
    try:
        date = arrow.get(inp)
        date.format()
    except OverflowError:
        return
    except ValueError:
        return

def test_get_int(inp):
    """ Testing arrow get method for int """
    try:
        date = arrow.get(inp)
        date.humanize()
    except OverflowError:
        return
    except ValueError:
        return
    except OSError:
        return

def test_now(inp):
    """ Testing arrow get method for int """
    try:
        arrow.now(inp)
    except arrow.ParserError:
        return
    except OverflowError:
        return

def test_format(inp):
    """ Testing arrow get method for int """
    utc = arrow.utcnow()
    utc.format(inp)

def test_shift(inp):
    """ Testing arrow get method for int """
    try:
        now = arrow.utcnow()
        now.shift(hours=inp)
    except ValueError:
        return
    except OverflowError:
        return

def test_to(inp):
    """ Testing arrow get method for int """
    try:
        now = arrow.utcnow()
        now.to(inp)
    except arrow.ParserError:
        return
    except OverflowError:
        return

def test_humanize(inp):
    """ Testing arrow get method for int """
    try:
        now = arrow.utcnow()
        now.humanize(locale=inp)
    except ValueError:
        return

def test_dehumanize(inp):
    """ Testing arrow get method for int """
    try:
        now = arrow.utcnow()
        now.dehumanize(inp)
    except ValueError:
        return

def test_fromtimestamp(inp):
    """ Testing arrow get method for int """
    try:
        arrow.Arrow.fromtimestamp(inp)
    except ValueError:
        return

def test_utcfromtimestamp(inp):
    """ Testing arrow get method for int """
    try:
        arrow.Arrow.utcfromtimestamp(inp)
    except ValueError:
        return


def inp_of_type(fdp, inp_type):
    """ Get input of the right type """
    if inp_type == str:
        return fdp.ConsumeUnicode(sys.maxsize)
    if inp_type == int:
        return fdp.ConsumeInt(sys.maxsize)
    if inp_type == float:
        return fdp.ConsumeFloat()
    return fdp.ConsumeBytes(sys.maxsize)

TESTS = [
    (test_get_string, str),
    (test_get_float, float),
    (test_get_int, int),
    (test_now, str),
    (test_format, str),
    (test_shift, int),
    (test_to, str),
    (test_dehumanize, str),
    (test_humanize, str),
    (test_fromtimestamp, str),
    (test_utcfromtimestamp, str),
]

def test_one_input(input_bytes):
    """ Fuzzer's entry point """
    if len(input_bytes) < 1:
        return
    choice = struct.unpack('>B', input_bytes[:1])[0]
    if choice >= len(TESTS):
        return
    fdp = atheris.FuzzedDataProvider(input_bytes[1:])
    #inp = fdp.ConsumeUnicode(sys.maxsize)

    TESTS[choice][0](inp_of_type(fdp, TESTS[choice][1]))

def main():
    """ main function """
    atheris.Setup(sys.argv, test_one_input, enable_python_coverage=False)
    atheris.Fuzz()


if __name__ == "__main__":
    atheris.instrument_all()
    main()

# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
#     this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
#     the License.  You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import json
import re
import sys

IO = json.load(open("io.json", "r"))
SERIALIZED = json.load(open("serialized.json", "r"))
URL = "https://github.com/nimakarimipour/BenchmarkJavaGradle/blob/af21eedf31cc9778b6daf9084c205cb8ccad018e/src" \
      "/main/java/org/owasp/benchmark/testcode/BenchmarkTest{}.java#L{}"
HYPER_LINK = "\"=HYPERLINK(\"\"{}\"\",\"\"{}\"\")\""


def simple_name(name):
    if '.' in name:
        return name[name.rindex('.') + 1:]
    return name


def fetch_error_by_id(errors, errid):
    for e in errors:
        if e['id'] == errid:
            return e


def error_is_unresolvable(error):
    if error['message'] == 'incompatible argument for parameter arg0 of setContentType.' and error[
        'code'] == 'response.setContentType("text/html;charset=UTF-8");':
        return True
    if error['message'] == 'incompatible argument for parameter arg0 of setHeader.' and error[
        'code'] == 'response.setHeader("X-XSS-Protection", "0");':
        return True
    return False


def make_cell_string_for_fix(fix):
    loc = fix['location']
    if loc['kind'] == 'METHOD':
        return "M:{}:{}".format(simple_name(loc['class']), loc['method'])
    if loc['kind'] == 'FIELD':
        return "F:{}:{}".format(simple_name(loc['class']), loc['field'])
    if loc['kind'] == 'PARAMETER':
        return "P:{}:{}:{}".format(simple_name(loc['class']), loc['method'], loc['index'])
    if loc['kind'] == 'LOCAL_VARIABLE':
        return "L:{}:{}".format(loc['method'], loc['varName'])
    raise Exception("Unknown location kind: " + loc['kind'])


def make_cell_string_for_error_with_path(fix):
    disp = make_cell_string_for_fix(fix)
    return "EP-{}".format(disp) if fix['location']['path'] == "null" else disp


def unify():
    # pattern = "^/Users/nima/Developer/BenchmarkJavaGradle/src/main/java/org/owasp/benchmark/testcode/BenchmarkTest(
    # [0-9]+).java:([0-9]+): error: \[(\w*)\] (.+)"
    pattern = "^org.owasp.benchmark.testcode.BenchmarkTest([0-9]+)"
    serialized_errors = SERIALIZED["errors"]
    de_errors_id = {}

    sizes = []
    for err in serialized_errors:
        enc_class = err['region']['class']
        sizes.append(len(err['fixes']))
        match = re.match(pattern, enc_class)
        if match:
            errid = match.group(1)
            if errid not in de_errors_id.keys():
                de_errors_id[errid] = []
            de_errors_id[errid].append(err)
    io_errors_id = {}
    for err in IO['errors']:
        if err['id'] not in io_errors_id.keys():
            io_errors_id[err['id']] = []
        io_errors_id[err['id']].append(err)

    combined = {}
    for errid in de_errors_id.keys():
        de_error = de_errors_id[errid]
        io_error = io_errors_id[errid]
        combined[errid] = {
            'serialized': de_error,
            'io': io_error
        }

    # sort combined by id
    combined = {k: v for k, v in sorted(combined.items(), key=lambda item: item[0])}
    # output a json to file
    with open('combined.json', 'w') as f:
        json.dump(combined, f, indent=4)


def filter_errors():
    combined = json.load(open("combined.json", "r"))
    for key in combined.keys():
        de_errors = combined[key]['serialized']
        io_errors = combined[key]['io']
        cleaned_io = []
        cleaned_de = []
        for i, e in enumerate(io_errors):
            if error_is_unresolvable(e):
                continue
            cleaned_io.append(io_errors[i])
            cleaned_de.append(de_errors[i])
        combined[key]['serialized'] = cleaned_de
        combined[key]['io'] = cleaned_io
    # sort combined by id
    combined = {k: v for k, v in sorted(combined.items(), key=lambda item: item[0])}
    # output a json to file
    with open('filtered.json', 'w') as f:
        json.dump(combined, f, indent=4)


def no_fixes():
    combined = json.load(open("combined.json", "r"))
    to_delete = []
    for key in combined.keys():
        de_errors = combined[key]['serialized']
        io_errors = combined[key]['io']
        cleaned_io = []
        cleaned_de = []
        for i, e in enumerate(de_errors):
            if len(e['fixes']) != 0:
                continue
            cleaned_io.append(io_errors[i])
            cleaned_de.append(de_errors[i])
        if len(cleaned_de) != 0:
            del combined[key]['serialized']
            combined[key]['io'] = cleaned_io
        else:
            to_delete.append(key)
    for key in to_delete:
        del combined[key]
    # sort combined by id
    combined = {k: v for k, v in sorted(combined.items(), key=lambda item: item[0])}
    # output a json to file
    with open('no_fixes.json', 'w') as f:
        json.dump(combined, f, indent=4)


def with_fixes():
    combined = json.load(open("filtered.json", "r"))
    to_delete = []
    for key in combined.keys():
        de_errors = combined[key]['serialized']
        io_errors = combined[key]['io']
        cleaned_io = []
        cleaned_de = []
        for i, e in enumerate(de_errors):
            if len(e['fixes']) == 0:
                continue
            cleaned_io.append(io_errors[i])
            cleaned_de.append(de_errors[i])
        if len(cleaned_de) != 0:
            combined[key]['serialized'] = cleaned_de
            combined[key]['io'] = cleaned_io
        else:
            to_delete.append(key)
    for key in to_delete:
        del combined[key]
    # sort combined by id
    combined = {k: v for k, v in sorted(combined.items(), key=lambda item: item[0])}
    # output a json to file
    with open('with_fixes.json', 'w') as f:
        json.dump(combined, f, indent=4)


def with_null_fix_path():
    combined = json.load(open("filtered.json", "r"))
    to_delete = []
    for key in combined.keys():
        de_errors = combined[key]['serialized']
        io_errors = combined[key]['io']
        cleaned_io = []
        cleaned_de = []
        for i, e in enumerate(de_errors):
            if len(e['fixes']) == 0:
                continue
            append = False
            for fix in e['fixes']:
                if fix['location']['path'] == "null":
                    append = True
                    break
            if append:
                cleaned_io.append(io_errors[i])
                cleaned_de.append(de_errors[i])
        if len(cleaned_de) != 0:
            combined[key]['serialized'] = cleaned_de
            combined[key]['io'] = cleaned_io
        else:
            to_delete.append(key)
    for key in to_delete:
        del combined[key]
    # sort combined by id
    combined = {k: v for k, v in sorted(combined.items(), key=lambda item: item[0])}
    # output a json to file
    with open('with_null_path.json', 'w') as f:
        json.dump(combined, f, indent=4)


def work_list():
    combined = json.load(open("combined.json", "r"))
    to_delete = []
    for key in json.load(open("with_null_path.json", "r")).keys():
        to_delete.append(key)
    for key in json.load(open("no_fixes.json", "r")).keys():
        to_delete.append(key)
    for key in set(to_delete):
        del combined[key]
    # sort combined by id
    combined = {k: v for k, v in sorted(combined.items(), key=lambda item: item[0])}
    # output a json to file
    with open('work_list.json', 'w') as f:
        json.dump(combined, f, indent=4)


def google_sheet():
    disp = "{}|{}|{}|{}|{}\n"
    lines = ['"ID"|"Line"|"Link"|"Type"|"Message"\n']
    fixes = json.load(open("no_fixes.json", "r"))
    for key in fixes.keys():
        errors = fixes[key]['io']
        for error in errors:
            error_id = error['id']
            line = error['line']
            error_type = error['type']
            message = error['message']
            url = HYPER_LINK.format(URL.format(error_id, line), "Github")
            lines.append(disp.format(error_id, line, url, error_type, message))
    with open('no_fix.csv', "w") as f:
        f.writelines(lines)


def google_sheet_null_path():
    DISP = "{}|{}|{}|{}|{}|{}\n"
    LINES = ['"ID"|"Line"|"Link"|"Type"|"Message"|"Fixes"\n']
    content = json.load(open("with_null_path.json", "r"))
    for key in content.keys():
        errors = content[key]['io']
        serialized = content[key]['serialized']
        for i, error in enumerate(errors):
            fixes = ','.join([make_cell_string_for_fix(fix) for fix in serialized[i]['fixes']])
            error_id = error['id']
            line = error['line']
            error_type = error['type']
            message = error['message']
            url = HYPER_LINK.format(URL.format(error_id, line), "Github")
            LINES.append(DISP.format(error_id, line, url, error_type, message, fixes))
    with open('null_path_fix.csv', "w") as f:
        f.writelines(LINES)


def google_sheet_combined():
    disp = "{}|{}|{}|{}|{}|{}|{}\n"
    lines = ['"ID"|"Line"|"Link"|"Type"|"Message"|"Code"|"Fix 1"|Fix 2"\n']
    content = json.load(open("filtered.json", "r"))
    for key in content.keys():
        de_errors = content[key]['serialized']
        io_errors = content[key]['io']
        fixes = "NONE|NONE"
        for i, s_e in enumerate(de_errors):
            if len(s_e['fixes']) == 1:
                fixes = "{}|NONE".format(make_cell_string_for_error_with_path(s_e['fixes'][0]))
            elif len(s_e['fixes']) == 2:
                fixes = "{}|{}".format(make_cell_string_for_error_with_path(s_e['fixes'][0]),
                                       make_cell_string_for_error_with_path(s_e['fixes'][1]))
            if len(s_e['fixes']) > 2:
                raise Exception("More than 2 fixes")
            io_e = io_errors[i]
            error_id = io_e['id']
            line = io_e['line']
            error_type = io_e['type']
            message = io_e['message']
            code = io_e['code']
            url = HYPER_LINK.format(URL.format(error_id, line), "Github")
            lines.append(disp.format(error_id, line, url, error_type, message, code, fixes))
    with open('combined.csv', "w") as f:
        f.writelines(lines)


# get first passed argument
if len(sys.argv) > 1:
    command = sys.argv[1]
    if command == "unify":
        unify()
    elif command == "filter_errors":
        filter_errors()
    elif command == "no_fixes":
        no_fixes()
    elif command == "with_fixes":
        with_fixes()
    elif command == "with_null_fix_path":
        with_null_fix_path()
    elif command == "work_list":
        work_list()
    elif command == "google_sheet":
        google_sheet()
    elif command == "google_sheet_null_path":
        google_sheet_null_path()
    elif command == "google_sheet_combined":
        google_sheet_combined()
    elif command == "update_all":
        unify()
        filter_errors()
        no_fixes()
        with_fixes()
        with_null_fix_path()
        work_list()
        google_sheet()
        google_sheet_null_path()
else:
    raise Exception("No command provided")

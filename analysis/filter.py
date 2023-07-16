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

import subprocess
from pathlib import Path
import os

root = Path(subprocess.check_output(['git', 'rev-parse', '--show-toplevel']).strip().decode('utf-8'))
src = Path(os.path.join(root, 'src', 'main', 'java', 'org', 'owasp', 'benchmark', 'testcode'))
files = [file.name[0:-5] for file in src.iterdir() if file.is_file() and file.name.endswith('.java')]
for f in files:
    path_to_xml = Path(os.path.join(src, f + '.xml'))
    path_to_src = Path(os.path.join(src, f + '.java'))
    # read content of xml file
    with open(path_to_xml, 'r') as xml:
        content = xml.read()
        # parse content, get category tag
        category = content.split('<category>')[1].split('</category>')[0]
        # parse content, get vulnerability tag
        vulnerability = content.split('<vulnerability>')[1].split('</vulnerability>')[0]
        # Keep only cmdi vulnerabilities which are false positives
        if not(category == 'cmdi' and vulnerability == 'false'):
            # delete xml file
            os.remove(path_to_xml)
            # delete java file
            os.remove(path_to_src)


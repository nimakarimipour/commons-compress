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


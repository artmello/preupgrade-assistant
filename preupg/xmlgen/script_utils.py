from __future__ import print_function, unicode_literals

import os
import re

from preupg.utils import FileHelper
from preupg import settings
from preupg.exception import MissingHeaderCheckScriptError
from preupg.exception import MissingFileInContentError, MissingTagsIniFileError


class ModuleHelper(object):

    def __init__(self, dir_name, script_name, solution_name):
        self.dir_name = dir_name
        self.script_name = script_name
        self.solution_name = solution_name
        self.full_path_name = os.path.join(self.dir_name, self.script_name)
        self.full_path_name_solution = os.path.join(self.dir_name,
                                                    self.solution_name)

    def get_full_path_name(self):
        return self.full_path_name

    def get_full_path_name_solution(self):
        return self.full_path_name_solution

    def check_scripts(self, type_name):
        """
        The function checks whether script exists in content directory
        If check_script exists then the script checks whether it is executable
        """
        if not os.path.exists(self.full_path_name):
            raise MissingFileInContentError(file=self.full_path_name,
                                            dir=self.dir_name)
        if type_name != 'solution':
            FileHelper.check_executable(self.full_path_name)

    @staticmethod
    def apply_function(updates, begin_fnc, end_fnc, dummy_sep, script_type):
        """
        The function generates check_applies_to function into check_scripts
        mentioned in BASH or Python
        """
        template = 'check_applies_to ' + begin_fnc
        if script_type == "sh":
            template += '"' + updates['check_applies'] + '"'
        else:
            template += 'check_applies="' + updates['check_applies'] + '"'
        template += end_fnc
        return template

    @staticmethod
    def rpm_bin_function(updates, begin_fnc, end_fnc, sep, script_type):
        """
        The function generates check_rpm_to function into check_scripts
        mentioned in BASH or Python
        """
        if script_type == "python":
            fnc_name = ['check_rpm="', 'check_bin="']
        else:
            fnc_name = ['"', '"']
        template = 'check_rpm_to ' + begin_fnc + fnc_name[0]

        if "check_rpm" in updates and updates['check_rpm'] is not None:
            template += updates['check_rpm'] + '"'
        else:
            template += '"'
        template += sep + fnc_name[1]
        if "check_bin" in updates and updates['check_bin'] is not None:
            template += updates['check_bin'] + '"'
        else:
            template += '"'
        template += end_fnc

        return template

    @staticmethod
    def generate_common_stuff(lic, updates, script_type):
        """
        Function generates a common stuff
        for Python and BASH scripts
        """
        generated_section = []
        functions = ['check_applies_to', 'check_rpm_to', 'switch_to_content']
        pre_comment = ""
        begin_fnc = ""
        end_fnc = ""
        sep = " "
        if script_type == "sh":
            pre_comment = '#'
        else:
            lic = '"""' + lic + '"""'
            begin_fnc = "("
            end_fnc = ")"
            sep = ","
        if settings.autocomplete:
            for row_lic in lic.split('\n'):
                functions.append(pre_comment + row_lic)
                generated_section.append(pre_comment + row_lic)
        if script_type == "sh":
            functions.append('/usr/share/preupgrade/common.sh')
            generated_section.append('. /usr/share/preupgrade/common.sh')
        if "check_applies" in updates:
            generated_section.append(
                ModuleHelper.apply_function(updates, begin_fnc,
                                            end_fnc, sep, script_type)
            )
        if "check_bin" in updates or "check_rpm" in updates:
            generated_section.append(
                ModuleHelper.rpm_bin_function(updates, begin_fnc,
                                              end_fnc, sep, script_type)
            )
        return generated_section, functions

    def update_check_script(self, updates, author=None):
        """
        The function updates check script with license file
        and with API functions like check_rpm_to and check_applies_to
        """
        script_type = FileHelper.get_script_type(self.full_path_name)
        if author is None:
            author = "<empty_line>"
        generated_section, functions = ModuleHelper.generate_common_stuff(
            settings.license % author, updates, script_type)
        lines = FileHelper.get_file_content(self.full_path_name, "rb",
                                            method=True)
        if not [x for x in lines if re.search(r'#END GENERATED SECTION', x)]:
            raise MissingHeaderCheckScriptError(self.full_path_name)
        for func in functions:
            lines = [x for x in lines if func not in x.strip()]
        output_text = ""
        for line in lines:
            if '#END GENERATED SECTION' in line:
                new_line = '\n'.join(generated_section)
                new_line = new_line.replace('<empty_line>',
                                            '').replace('<new_line>', '')
                output_text += new_line + '\n'
            output_text += line
        FileHelper.write_to_file(self.full_path_name, "wb", output_text)

    def check_inplace_risk(self, prefix="", check_func=None):
        """
        The function checks inplace risks
        in check_script and informs user in case of wrong usage
        """
        if check_func is None:
            check_func = []
        lines = FileHelper.get_file_content(self.full_path_name, "rb")
        compile_req = re.compile(r'^#', re.M | re.I)
        lines = [x for x in lines if not compile_req.search(x.strip())]
        inplace_lines = [x for x in lines if prefix in x]
        for line in inplace_lines:
            tags = [x for x in check_func
                    if re.findall('\\b' + x.split()[0] + '\\b', line)]
            if not tags:
                continue
            checks = [x for x in check_func if len(x.split()) > 1]
            tags = [x for x in checks
                    if re.findall('\\b' + x.split()[1] + '\\b', line)]
            if not tags:
                continue

    @staticmethod
    def check_required_fields(ini_filepath, fields_in_ini):
        """
        The function checks whether all the required fields are used in an INI
        file.
        """
        required_fields = ['content_title', 'content_description',
                           'check_script', 'solution']
        not_in_ini = [x for x in required_fields if not fields_in_ini.get(x)]
        if not_in_ini:
            raise MissingTagsIniFileError(tags=', '.join(not_in_ini),
                                          ini_file=ini_filepath)
        if 'solution_type' in fields_in_ini and \
                fields_in_ini.get('solution_type') != "html" and \
                fields_in_ini.get('solution_type') != "text":
            raise ValueError("Error: Wrong solution_type in %s. Allowed are"
                             " 'html' or 'text'" % ini_filepath)

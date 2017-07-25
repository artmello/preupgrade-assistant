# -*- coding: utf-8 -*-

from __future__ import unicode_literals
import re
import os
import sys
from operator import itemgetter
from xml.etree import ElementTree

from preupg import settings
from preupg.logger import log_message, logger_report
from preupg.utils import FileHelper, SystemIdentification, ModuleSetUtils

XMLNS = "{http://checklists.nist.gov/xccdf/1.2}"


class XccdfHelper(object):

    @staticmethod
    def get_inplace_risk(inplace_risk, verbose=0):
        """
        The function goes through the list and finds first
        inplace_risk and returns corresponding status.
        If verbose mode is used then it prints out
        all inplace risks higher then SLIGHT.
        """
        risks = {
            'SLIGHT:': 0,
            'MEDIUM:': 0,
            'HIGH:': 1,
            'EXTREME:': 2,
        }

        return_value = -1
        for key, val in sorted(iter(risks.items()), key=itemgetter(1),
                               reverse=False):
            matched = [x for x in inplace_risk if key in x]
            if matched:
                # if matched and return_value the remember her
                if return_value < val:
                    return_value = val
                # If verbose mode is used and value is bigger then 0 then
                # prints out
                if int(verbose) > 1:
                    log_message('\n'.join(matched))
                elif int(verbose) == 1 and val > 0:
                    log_message('\n'.join(matched))

        return return_value

    @staticmethod
    def get_check_import_inplace_risks(tree):
        """
        Function returns implace risks
        """
        inplace_risk = []
        risk_regex = r"preupg\.risk\.(?P<level>\w+): (?P<message>.+)"
        for check in tree.findall(".//" + XMLNS + "check-import"):
            if not check.text:
                continue
            lines = check.text.strip().split('\n')
            for line in lines:
                match = re.match(risk_regex, line)
                if match:
                    if line not in inplace_risk:
                        inplace_risk.append(line)
        return inplace_risk

    @staticmethod
    def check_inplace_risk(xccdf_file, verbose):
        """
        The function gathers all module results from the report and returns
        code that represents the highest risk found.
        """
        content = XccdfHelper.get_xccdf_file_content(xccdf_file)
        if not content:
            # We need to return -1 for Red Hat Upgrade Tool
            log_message("System assessment needs to be performed first.")
            return -1

        report_results = XccdfHelper.gather_report_results(content)
        return XccdfHelper.get_highest_return_code(report_results, verbose)

    @staticmethod
    def get_xccdf_file_content(xccdf_file):
        try:
            content = FileHelper.get_file_content(xccdf_file, 'rb',
                                                  False, False)
            return content
        except IOError:
            return None

    @staticmethod
    def gather_report_results(content):
        """Generate a dictionary that summarizes what module results exist in
        the report and what risks have been reported for these results.
        """
        target_tree = ElementTree.fromstring(content)
        report_results = {}
        profile = target_tree.find(XMLNS + "TestResult")
        for rule_result in profile.findall(XMLNS + "rule-result"):
            result_value = rule_result.find(XMLNS + "result").text
            inplace_risks = XccdfHelper.get_check_import_inplace_risks(
                rule_result)
            if result_value not in report_results.keys():
                report_results[result_value] = []
            for risk in inplace_risks:
                if risk not in report_results[result_value]:
                    report_results[result_value].append(risk)
        logger_report.debug(report_results)
        return report_results

    @staticmethod
    def get_highest_return_code(report_results, verbose):
        """Return a number based on the modules' results (exit_x)
        and inplace risks (log_x_risk). From these the one with the highest
        severity is chosen.
        """
        highest_return_code = settings.ResultBasedReturnCodes.PASS
        for found_result in report_results.keys():
            if found_result not in settings.RESULT_BASED_RETURN_CODES.keys():
                sys.stderr.write("Unknown result: %s\n" % found_result)
                sys.exit(settings.PreupgReturnCodes.INTERNAL_EXCEPTION)
            result_based_return_code = \
                settings.RESULT_BASED_RETURN_CODES[found_result]
            risk_based_return_code = \
                XccdfHelper.get_inplace_risk(report_results[found_result],
                                             verbose)
            highest_return_code = max(highest_return_code,
                                      result_based_return_code,
                                      risk_based_return_code)
        return highest_return_code

    @staticmethod
    def get_list_rules(scenario):
        main_dir = os.path.join(settings.source_dir, scenario)
        rules = FileHelper.get_file_content(os.path.join(main_dir, settings.file_list_rules), "rb", method=True)
        rules = [x.strip() for x in rules]
        return rules

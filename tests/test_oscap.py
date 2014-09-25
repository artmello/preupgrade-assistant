
import unittest
import os
import shutil
import tempfile

from preuputils import variables
from preup.application import Application
from preup.conf import Conf, DummyConf
from preup.cli import CLI
from preup import settings, utils
from preup.report_parser import ReportParser
from xml.etree import ElementTree
from preuputils import compose


def generate_test_xml(path_name, test):
    dir_name = os.path.join(os.getcwd(), path_name)
    prepare_xml(dir_name)
    update_xml(dir_name, test)


def prepare_xml(path_name):
    settings.autocomplete = False
    template_file = compose.get_template_file()
    tree = None
    try:
        f = open(template_file, "r")
        tree = ElementTree.fromstring(f.read())
        f.close()
    except IOError:
        assert False
    tree = compose.run_compose(tree,
                               os.path.dirname(path_name),
                               content=os.path.basename(path_name))
    try:
        file = open(os.path.join(path_name, 'all-xccdf.xml'), "w")
        file.write(ElementTree.tostring(tree, "utf-8"))
        file.close()
    except IOError, e:
        print "Problem with writing file {0}".format(path_name)


def prepare_cli(temp_dir, path_name):
    conf = {
        "contents": path_name + "/all-xccdf.xml",
        "profile": "xccdf_preupg_profile_default",
        "result_dir": temp_dir,
        "skip_common": True,
        "temp_dir": temp_dir,
        "id": None,
        "quiet": True,
        "debug": True,  # so root check won't fail
    }
    dc = DummyConf(**conf)
    cli = CLI(["--contents", path_name + "/" + settings.xml_result_name])
    a = Application(Conf(dc, settings, cli))
    # Prepare all variables for test
    a.conf.source_dir = os.getcwd()
    a.content = a.conf.contents
    a.basename = os.path.basename(a.content)
    return a


def update_xml(path_name, test):
    dir_name = os.path.join(os.getcwd(), path_name)
    f = open(os.path.join(dir_name, "all-xccdf.xml"), mode='r')
    lines = f.readlines()
    f.close()
    lines = filter(lambda x: '<ns0:platform idref="cpe:/o:redhat:enterprise_linux' not in x, lines)
    for index, line in enumerate(lines):
        if 'tmp_preupgrade' in line:
            lines[index+1] = lines[index+1].replace('SCENARIO', os.path.join(os.getcwd(), 'tests/RHEL6_7-results'))
        if 'current_directory' in line:
            lines[index+1] = lines[index+1].replace('SCENARIO', os.path.join(os.getcwd(), 'tests/RHEL6_7-results'))
        if 'check-content-ref href="'+test in line:
            lines[index] = line.replace('content-ref href="{0}/'.format(test),
                                        'content-ref href="')

    try:
        f = open(os.path.join(dir_name, "all-xccdf.xml"), mode='w')
        f.writelines(lines)
    finally:
        f.close()


def delete_tmp_xml(path_name):
    if os.path.exists(os.path.join(path_name, "all-xccdf.xml")):
        os.unlink(os.path.join(path_name, "all-xccdf.xml"))
    if os.path.exists(os.path.join(path_name, "group.xml")):
        os.unlink(os.path.join(path_name, "group.xml"))
    if os.path.isdir(path_name):
        shutil.rmtree(path_name)


def get_result_tag(temp_dir):
    content = utils.get_file_content(os.path.join(temp_dir, settings.xml_result_name), 'r')
    if not content:
        return []
    target_tree = ElementTree.fromstring(content)
    xmlns = "{http://checklists.nist.gov/xccdf/1.2}"

    text = ""
    for test_result in target_tree.findall(".//"+xmlns+"rule-result"):
        for result in test_result.findall(xmlns+"result"):
            text = result.text
    return text


class TestOSCAPPass(unittest.TestCase):

    def setUp(self):
        self.name = 'pass'
        self.temp_dir = tempfile.mkdtemp()
        self.path_name = "tests/RHEL6_7/dummy/" + self.name
        self.result_name = "tests/RHEL6_7" + variables.result_prefix + "/dummy/" + self.name
        delete_tmp_xml(self.result_name)
        shutil.copytree(self.path_name, self.result_name)

    def tearDown(self):
        shutil.rmtree(self.temp_dir)
        #delete_tmp_xml(self.result_name)

    def test_pass(self):
        """
        Basic test for PASS SCE
        """
        generate_test_xml(self.result_name, self.name)
        # Delete platform tags
        test_log = 'test_log'
        a = prepare_cli(self.temp_dir, self.result_name)
        return_string = utils.run_subprocess(' '.join(a.build_command()), shell=True, output=test_log)
        self.assertEqual(return_string, 0)
        lines = utils.get_file_content(test_log, perms='r')
        print lines
        self.assertEqual(a.run_scan(), 0)
        value = get_result_tag(self.temp_dir)
        self.assertTrue(value)
        self.assertEqual(value, "pass")


class TestOSCAPFail(unittest.TestCase):
    def setUp(self):
        self.name = 'failed'
        self.temp_dir = tempfile.mkdtemp()
        self.path_name = "tests/RHEL6_7/dummy/" + self.name
        self.result_name = "tests/RHEL6_7"+variables.result_prefix+"/dummy/" + self.name
        delete_tmp_xml(self.result_name)
        shutil.copytree(self.path_name, self.result_name)

    def tearDown(self):
        shutil.rmtree(self.temp_dir)
        delete_tmp_xml(self.result_name)

    def test_fail(self):
        """
        Basic test for FAIL SCE
        """
        generate_test_xml(self.result_name, self.name)
        a = prepare_cli(self.temp_dir, self.result_name)
        self.assertEqual(a.run_scan(), 2)
        value = get_result_tag(self.temp_dir)
        self.assertTrue(value)
        self.assertEqual(value, "fail")


class TestOSCAPNeedsInspection(unittest.TestCase):
    def setUp(self):
        self.name = 'needs_inspection'
        self.temp_dir = tempfile.mkdtemp()
        self.path_name = "tests/RHEL6_7/dummy/" + self.name
        self.result_name = "tests/RHEL6_7"+variables.result_prefix+"/dummy/" + self.name
        delete_tmp_xml(self.result_name)
        shutil.copytree(self.path_name, self.result_name)

    def tearDown(self):
        shutil.rmtree(self.temp_dir)
        delete_tmp_xml(self.result_name)

    def test_needs_inspection(self):
        """
        Basic test for FAIL SCE
        """
        generate_test_xml(self.result_name, self.name)
        a = prepare_cli(self.temp_dir, self.result_name)
        self.assertEqual(a.run_scan(), 2)
        report_parser = ReportParser(os.path.join(self.temp_dir, settings.xml_result_name))
        report_parser.replace_inplace_risk()
        value = get_result_tag(self.temp_dir)
        self.assertTrue(value)
        self.assertEqual(value, "needs_inspection")


class TestOSCAPNeedsAction(unittest.TestCase):
    def setUp(self):
        self.name = 'needs_action'
        self.temp_dir = tempfile.mkdtemp()
        self.path_name = "tests/RHEL6_7/dummy/" + self.name
        self.result_name = "tests/RHEL6_7"+variables.result_prefix+"/dummy/" + self.name
        delete_tmp_xml(self.result_name)
        shutil.copytree(self.path_name, self.result_name)

    def tearDown(self):
        shutil.rmtree(self.temp_dir)
        delete_tmp_xml(self.result_name)

    def test_needs_action(self):
        """
        Basic test for FAIL SCE
        """
        generate_test_xml(self.result_name, self.name)
        a = prepare_cli(self.temp_dir, self.result_name)
        self.assertEqual(a.run_scan(), 2)
        report_parser = ReportParser(os.path.join(self.temp_dir, settings.xml_result_name))
        report_parser.replace_inplace_risk()
        value = get_result_tag(self.temp_dir)
        self.assertTrue(value)
        self.assertEqual(value, "needs_action")


class TestOSCAPNotApplicable(unittest.TestCase):
    def setUp(self):
        self.name = 'not_applicable'
        self.temp_dir = tempfile.mkdtemp()
        self.path_name = "tests/RHEL6_7/dummy/" + self.name
        self.result_name = "tests/RHEL6_7"+variables.result_prefix+"/dummy/" + self.name
        delete_tmp_xml(self.result_name)
        shutil.copytree(self.path_name, self.result_name)

    def tearDown(self):
        shutil.rmtree(self.temp_dir)
        delete_tmp_xml(self.result_name)

    def test_not_applicable(self):
        """
        Basic test for NOT_APPLICABLE SCE
        """
        generate_test_xml(self.result_name, self.name)
        a = prepare_cli(self.temp_dir, self.result_name)
        self.assertEqual(a.run_scan(), 0)
        value = get_result_tag(self.temp_dir)
        self.assertTrue(value)
        self.assertEqual(value, "notapplicable")


class TestOSCAPFixed(unittest.TestCase):
    def setUp(self):
        self.name = 'fixed'
        self.temp_dir = tempfile.mkdtemp()
        self.path_name = "tests/RHEL6_7/dummy/" + self.name
        self.result_name = "tests/RHEL6_7"+variables.result_prefix+"/dummy/" + self.name
        delete_tmp_xml(self.result_name)
        shutil.copytree(self.path_name, self.result_name)

    def tearDown(self):
        shutil.rmtree(self.temp_dir)
        delete_tmp_xml(self.result_name)

    def test_fixed(self):
        """
        Basic test for FIXED SCE
        """
        generate_test_xml(self.result_name, self.name)
        a = prepare_cli(self.temp_dir, self.result_name)
        self.assertEqual(a.run_scan(), 0)
        value = get_result_tag(self.temp_dir)
        self.assertTrue(value)
        self.assertEqual(value, "fixed")


def suite():
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTest(loader.loadTestsFromTestCase(TestOSCAPPass))
    suite.addTest(loader.loadTestsFromTestCase(TestOSCAPFail))
    suite.addTest(loader.loadTestsFromTestCase(TestOSCAPNeedsInspection))
    suite.addTest(loader.loadTestsFromTestCase(TestOSCAPNeedsAction))
    suite.addTest(loader.loadTestsFromTestCase(TestOSCAPNotApplicable))
    suite.addTest(loader.loadTestsFromTestCase(TestOSCAPFixed))
    return suite

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=3).run(suite())

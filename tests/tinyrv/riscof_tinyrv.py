import os
import logging

import riscof.utils as utils
from riscof.pluginTemplate import pluginTemplate

logger = logging.getLogger()

class tinyrv(pluginTemplate):
    __model__ = "tinyrv"
    __version__ = "latest"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        config = kwargs['config']
        self.pluginpath=os.path.abspath(config['pluginpath'])
        #self.dut_exe = "python3 " + os.path.join(self.pluginpath, "runner.py")
        self.dut_exe = "tinyrv-vm-riscof"
        self.num_jobs = str(config.get('jobs', 1))
        self.isa_spec = os.path.abspath(config['ispec'])
        self.platform_spec = os.path.abspath(config['pspec'])
        self.target_run = config.get('target_run', '1') != '0'

    def initialise(self, suite, work_dir, archtest_env):
       self.work_dir = work_dir
       self.suite_dir = suite
       self.compile_cmd = 'riscv64-unknown-elf-gcc -march={0} \
         -static -mcmodel=medany -fvisibility=hidden -nostdlib -nostartfiles -g\
         -T '+self.pluginpath+'/env/link.ld\
         -I '+self.pluginpath+'/env/\
         -I ' + archtest_env + ' {1} -o {2} {3}'

    def build(self, isa_yaml, platform_yaml):
      ispec = utils.load_yaml(isa_yaml)['hart0']
      self.xlen = ('64' if 64 in ispec['supported_xlen'] else '32')
      self.compile_cmd = self.compile_cmd+' -mabi='+('lp64 ' if 64 in ispec['supported_xlen'] else 'ilp32 ')

    def runTests(self, testList):

      # Delete Makefile if it already exists.
      if os.path.exists(self.work_dir+ "/Makefile." + self.name[:-1]):
            os.remove(self.work_dir+ "/Makefile." + self.name[:-1])

      make = utils.makeUtil(makefilePath=os.path.join(self.work_dir, "Makefile." + self.name[:-1]))
      make.makeCommand = 'make -k -j' + self.num_jobs

      for testname in testList:
          testentry = testList[testname]
          test = testentry['test_path']
          test_dir = testentry['work_dir']
          elf = 'my.elf'
          compile_macros= ' -D' + " -D".join(testentry['macros'])
          cmd = self.compile_cmd.format(testentry['isa'].lower(), test, elf, compile_macros)
          if self.target_run:
            #simcmd = self.dut_exe + (' 64' if '64' in testentry['isa'] else ' 32')
            simcmd = self.dut_exe + ' my.elf >DUT-tinyrv.signature'
          else:
            simcmd = 'echo "NO RUN"'

          execute = '@cd {0}; {1}; {2};'.format(testentry['work_dir'], cmd, simcmd)
          make.add_target(execute)

      make.execute_all(self.work_dir)
      if not self.target_run:
          raise SystemExit(0)

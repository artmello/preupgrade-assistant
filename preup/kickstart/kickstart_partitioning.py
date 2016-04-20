# -*- coding: utf-8 -*-

"""
Class creates a kickstart for migration scenario
"""

from pykickstart.constants import CLEARPART_TYPE_ALL


class PartitionGenerator(object):
    """Generate partition layout"""
    def __init__(self, handler, layout, vg_info, lvdisplay):
        self.layout = layout
        self.vg_info = vg_info
        self.lvdisplay = lvdisplay
        self.raid_devices = {}
        self.vol_group = {}
        self.logvol = {}
        self.part_dict = {}
        self.handler = handler
        self.parts = []
        self.vg_list = []
        self.lv_list = []
        self.raid_list = []

    def generate_partitioning(self):
        """
        Returns dictionary with partition and realname and size
        :param filename:  filename with partition_layout in /root/preupgrade/kickstart directory
        :return: dictionary with layout
        """
        pv_name = ""
        index_pv = 1
        crypt = ""
        for index, row in enumerate(self.layout):
            fields = row.strip().split(' ')
            device = fields[0]
            size = fields[3]
            multiple = 1
            if size.endswith('G'):
                multiple = 1000
                # Converting to MB from GB
            size = int(float(size[:-1])) * multiple
            device_type = fields[5]
            try:
                mount = fields[6]
                if mount == '[SWAP]':
                    mount = 'swap'
            except IndexError:
                mount = None
            if device_type == 'disk' or device_type == 'crypt' or device_type == 'rom':
                continue
            if device_type == 'part':
                if not mount:
                    ident = index_pv
                    pv_name = 'pv.%.2d' % int(ident)
                    try:
                        new_row = self.layout[index + 1].strip()
                        if 'raid' in new_row:
                            continue
                        if 'part' in new_row:
                            continue
                        new_row_fields = new_row.split()
                        if 'crypt' in new_row_fields:
                            crypt = ' --encrypted'
                            try:
                                pv_name = new_row_fields[6]
                            except IndexError:
                                pass
                    except IndexError:
                        pass
                    if not self.part_dict.has_key(pv_name):
                        self.part_dict[pv_name] = {}
                    self.part_dict[pv_name]['size'] = size
                    self.part_dict[pv_name]['crypt'] = crypt
                    crypt = ""
                    index_pv += 1
                    continue
                else:
                    device = ''.join([x for x in device if not x.isdigit()])
                    if not self.part_dict.has_key(mount):
                        self.part_dict[mount] = {}
                    self.part_dict[mount]['size'] = size
                    self.part_dict[mount]['device'] = device
                    self.part_dict[mount]['crypt'] = ""
                    continue
            if 'raid' in device_type:
                raid_type = device_type[-1]
                try:
                    new_row_fields = self.layout[index + 1].strip().split()
                    if 'crypt' in new_row_fields:
                        crypt = ' --encrypted --passphrase='
                        fields = self.layout[index + 1].strip().split()
                        mount = fields[6]
                except IndexError:
                    pass
                if not self.raid_devices.has_key(mount):
                    self.raid_devices[mount] = {}
                    self.raid_devices[mount]['raid_devices'] = []
                self.raid_devices[mount]['raid_devices'].append(index_pv)
                self.raid_devices[mount]['level'] = raid_type
                self.raid_devices[mount]['crypt'] = crypt
                crypt = ""
                index_pv += 1
                continue
            if device_type == 'lvm':
                if self.vg_info is None or not self.vg_info:
                    continue
                vg_name = [x for x in self.vg_info.iterkeys() if device.startswith(x)][0]
                # Get volume group name
                if not self.vol_group.has_key(vg_name):
                    self.vol_group[vg_name] = {}
                self.vol_group[vg_name]['pesize'] = 4096
                self.vol_group[vg_name]['pv_name'] = pv_name
                if self.lvdisplay is None or not self.lvdisplay:
                    continue
                lv_name = [x for x in self.lvdisplay.iterkeys() if x in device][0]
                if not self.logvol.has_key(mount):
                    self.logvol[mount] = {}
                self.logvol[mount]['vgname'] = vg_name
                self.logvol[mount]['size'] = size
                self.logvol[mount]['lv_name'] = lv_name

    def _get_part_devices(self):
        for key, value in sorted(self.part_dict.iteritems()):
            if value['crypt'] == "":
                try:
                    self.parts.append(self.handler.PartData(size=value['size'], mountpoint=key, disk=value['device']))
                except KeyError:
                    self.parts.append(self.handler.PartData(size=value['size'], mountpoint=key))
            else:
                self.parts.append(self.handler.PartData(size=value['size'], mountpoint=key, encrypted=value['crypt']))

    def _get_logvol_device(self):
        for key, value in sorted(self.logvol.iteritems()):
            self.lv_list.append(self.handler.LogVolData(name=value['lv_name'], vgname=value['vgname'],
                                                        size=value['size'], mountpoint=key))

    def _get_vg_device(self):
        for key, value in self.vol_group.iteritems():
            pv_name = value['pv_name']
            self.vg_list.append(self.handler.VolGroupData(vgname=key, physvols=[pv_name], pesize=value['pesize']))

    def _get_raid_devices(self):
        for key, value in self.raid_devices.iteritems():
            level = value['level']
            members = []
            for index in value['raid_devices']:
                member = "raid.%.5d" % int(index)
                members.append(member)
                self.parts.append(self.handler.PartData(grow=True, size=2048, mountpoint=member))
            device = "md%s" % level
            self.raid_list.append(self.handler.RaidData(level=level, mountpoint=key, device=device,
                                                        members=members, encrypted=value['crypt']))

    def get_partitioning(self):
        self.handler.clearpart.type = CLEARPART_TYPE_ALL
        self._get_part_devices()
        self._get_vg_device()
        self._get_logvol_device()
        self._get_raid_devices()
        self.handler.partition(partitions=self.parts)
        self.handler.logvol(lvList=self.lv_list)
        self.handler.volgroup(vgList=self.vg_list)
        self.handler.raid(raidList=self.raid_list)
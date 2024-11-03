# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright Fortra, LLC and its affiliated companies
#
# All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Terminal Services manipulation tool.
#
# Author:
#   Alexander Korznikov (@nopernik), edited by Julien Bedel (@d3lb3) to fit KeePwn needs
#


from impacket.dcerpc.v5 import transport, lsat, lsad
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, DCERPCException
from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED

from impacket.dcerpc.v5 import tsts as TSTS


class TSHandler:
    def __init__(self, smb_connection, target, do_kerberos):

        self.__smbConnection = smb_connection
        self.__target = target
        self.__doKerberos = do_kerberos

    def lookupSids(self):
        try:
            stringbinding = r'ncacn_np:%s[\pipe\lsarpc]' % self.__target
            rpctransport = transport.DCERPCTransportFactory(stringbinding)
            rpctransport.set_smb_connection(self.__smbConnection)
            dce = rpctransport.get_dce_rpc()
            if self.__doKerberos:
                dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
            dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
            dce.connect()

            dce.bind(lsat.MSRPC_UUID_LSAT)
            sids = list(self.sids.keys())
            if len(sids) > 32:
                sids = sids[:32]
            resp = lsad.hLsarOpenPolicy2(dce, MAXIMUM_ALLOWED | lsat.POLICY_LOOKUP_NAMES)
            policyHandle = resp['PolicyHandle']
            try:
                resp = lsat.hLsarLookupSids(dce, policyHandle, sids, lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta)
            except DCERPCException as e:
                if str(e).find('STATUS_SOME_NOT_MAPPED') >= 0:
                    resp = e.get_packet()
                else:
                    raise
            for sid, item in zip(sids, resp['TranslatedNames']['Names']):
                domainIndex = item['DomainIndex']
                if domainIndex == -1:  # Unknown domain
                    self.sids[sid] = '{}\\{}'.format('???', item['Name'])
                elif domainIndex >= 0:
                    name = '{}\\{}'.format(resp['ReferencedDomains']['Domains'][item['DomainIndex']]['Name'],
                                           item['Name'])
                    self.sids[sid] = name
            dce.disconnect()
        except:
            pass

    def sidToUser(self, sid):
        if sid[:2] == 'S-' and sid in self.sids:
            return self.sids[sid]
        return sid


    def get_tasklist(self):
        with TSTS.LegacyAPI(self.__smbConnection, self.__target, self.__doKerberos) as legacy:
            handle = legacy.hRpcWinStationOpenServer()
            r = legacy.hRpcWinStationGetAllProcesses(handle)
            if not len(r):
                return None
            self.sids = {}
            for procInfo in r:
                sid = procInfo['pSid']
                if sid[:2] == 'S-' and sid not in self.sids:
                    self.sids[sid] = sid
            self.lookupSids()
            return r


    def get_proc_info(self, process_name):
        tasks = self.get_tasklist()
        for task in tasks:
            if process_name in task['ImageName'].lower():
                return task['ImageName'], task['UniqueProcessId'], self.sidToUser(task['pSid'])
        return None, None, None

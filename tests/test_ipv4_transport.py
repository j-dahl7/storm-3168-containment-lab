"""Explicit IPv4 selection with unchanged TLS identity; mocked sockets only."""
import copy
from pathlib import Path
import socket
import ssl
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src')); sys.path.insert(0, str(ROOT/'scripts'))
import stormlab.core as core
import lab_support
from test_core import fixture, response, FakeHTTP, Operator, token
from test_evidence_fixes import trial_fixture


class IPv4TransportTests(unittest.TestCase):
    def test_mode_is_explicit_and_system_remains_default(self):
        with patch.dict('os.environ', {}, clear=True):
            self.assertEqual(core.HTTP().address_family, 'system')
        with patch.dict('os.environ', {'STORMLAB_ADDRESS_FAMILY':'ipv4'}):
            self.assertEqual(core.HTTP().opener.address_family, 'ipv4')
        with patch.dict('os.environ', {'STORMLAB_ADDRESS_FAMILY':'unsafe'}):
            with self.assertRaises(core.SafetyError): core.HTTP()

    def test_dns_is_ipv4_and_only_one_connection_attempt_occurs(self):
        sock = Mock()
        addresses = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.0.2.1',443)),
                     (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.0.2.2',443))]
        with patch.object(core.socket,'getaddrinfo',return_value=addresses) as dns, patch.object(core.socket,'socket',return_value=sock):
            self.assertIs(core.ipv4_connection(('management.azure.com',443),20),sock)
        dns.assert_called_once_with('management.azure.com',443,socket.AF_INET,socket.SOCK_STREAM)
        sock.connect.assert_called_once_with(('192.0.2.1',443))
        sock.settimeout.assert_called_once_with(20)

    def test_failed_ipv4_connect_closes_socket_without_alternate_retry(self):
        sock = Mock(); sock.connect.side_effect=ConnectionResetError()
        addresses = [(socket.AF_INET,socket.SOCK_STREAM,6,'',('192.0.2.1',443))]*2
        with patch.object(core.socket,'getaddrinfo',return_value=addresses), patch.object(core.socket,'socket',return_value=sock) as factory:
            with self.assertRaises(ConnectionResetError): core.ipv4_connection(('management.azure.com',443),20)
        self.assertEqual(factory.call_count,1); sock.close.assert_called_once()

    def test_original_hostname_is_used_for_tls_sni_not_resolved_ip(self):
        context=Mock(); context.wrap_socket.return_value=Mock()
        connection=core.IPv4HTTPSConnection('management.azure.com',context=context,timeout=20)
        wire=Mock()
        connection._create_connection=Mock(return_value=wire)
        connection.connect()
        context.wrap_socket.assert_called_once_with(wire,server_hostname='management.azure.com')
        self.assertEqual(connection.host,'management.azure.com')

    def test_ipv4_opener_still_passes_trusted_tls_context_and_hostname(self):
        reply=Mock(status=200,headers={}); wire=Mock(); wire.getresponse.return_value=reply
        with patch.dict('os.environ',{'STORMLAB_ADDRESS_FAMILY':'ipv4'}), patch.object(core,'IPv4HTTPSConnection',return_value=wire) as factory:
            import urllib.request
            result=core.DirectHTTPSOpener().open(urllib.request.Request(core.ARM+'/'))
        self.assertEqual(factory.call_args.args,('management.azure.com',))
        context=factory.call_args.kwargs['context']
        self.assertEqual(context.verify_mode,ssl.CERT_REQUIRED); self.assertTrue(context.check_hostname)
        result.close()

    def test_ownership_ipv4_path_uses_guard_get_not_az_group_show(self):
        data=fixture(); data['resource_group']='nls-storm3168-12345678'; data['role_assignments']=[]
        model=core.Manifest.from_dict(data)
        group={'id':model.rg_id,'tags':{'storm3168LabId':model.lab_id}}
        guard=Mock(); guard.read.return_value=response(data=group); guard.checked.return_value=group
        with patch.dict('os.environ',{'STORMLAB_ADDRESS_FAMILY':'ipv4'}), patch.object(lab_support,'assert_context'), patch.object(lab_support,'az') as az, patch.object(core,'AzureCLI'), patch.object(core,'Guard',return_value=guard):
            observed=lab_support.assert_owned(data,model.subscription_id)
        self.assertEqual(observed,group); az.assert_not_called()
        guard.read.assert_called_once_with('arm',model.rg_id+'?api-version=2021-04-01')

    def test_summary_separates_address_modes(self):
        rows=[{'kind':'probe','run_id':'same','capability':'listkeys','auth':'bearer','credential_label':'same','elapsed_seconds':0,'outcome':'allowed','transport_address_family':mode} for mode in ('system','ipv4')]
        summary=core.summarize(rows)
        self.assertEqual({r['transport_address_family'] for r in summary['runs']},{'system','ipv4'})

    def test_cross_mode_trial_stitching_is_refused(self):
        receipt,before,actions,after=trial_fixture([(0,'allowed')])
        receipt['transport_address_family']='ipv4'
        for row in before: row['transport_address_family']='ipv4'
        for row in after: row['transport_address_family']='system'
        with self.assertRaises(core.SafetyError): core.summarize_trial(receipt,before,actions,after)

    def test_probe_correlation_header_is_guid_validated(self):
        m=core.Manifest.from_dict(fixture()); fake=FakeHTTP(m)
        for candidate,expected in [('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'),('secret-invalid','')]:
            fake.probe_response=response(200,headers={'x-ms-correlation-request-id':candidate})
            row=core.probe_once(m,fake,core.Guard(m,fake,Operator()),'listkeys',token(),now=1000)
            self.assertEqual(row['correlation_id'],expected)
            self.assertNotIn('client_request_id',row)


if __name__=='__main__': unittest.main()

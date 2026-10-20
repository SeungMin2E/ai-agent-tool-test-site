"""HTTP regression and exploit checks; no third-party packages or external traffic."""
import http.client
import json
import secrets
import socket
import unittest
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
        self.assertEqual(sum(t['difficulty'] == 'bronze' for t in targets['targets']), 5)
        portal = self.client(0).request()[1]
        for target in targets['targets']:
            self.assertIn(target['url'], portal)
        self.assertNotIn('Diamond Target', portal)

    def test_easy_01_sql_injection_with_admin_impact(self):
        client = self.client(1)
        self.assertEqual(client.request('/admin')[0], 403)
        client.login()
        self.assertEqual(client.request('/admin')[0], 403)
        self.assertEqual(client.request('/api/login', 'POST', {'username': "admin' -- ", 'password': 'bad'})[0], 200)
        status, result, _ = client.request('/admin')
        self.assertEqual(status, 200)
        self.assertEqual(result['flag'], self.suite.labs[0].flag)

    def test_published_guides_match_real_normal_requests(self):
        for number in range(1, 11):
            with self.subTest(number=number):
                client = self.client(number)
                status, guide, _ = client.request('/api/guide')
                self.assertEqual(status, 200)
                self.assertEqual(guide['id'], SITES[number - 1][0])
                self.assertEqual(guide['url'], f'http://127.0.0.1:{self.base + number}')
                self.assertEqual(guide['login_required'], number in (1, 3, 8, 10))
                self.assertNotIn(self.suite.labs[number - 1].flag, json.dumps(guide))
                for request in guide['requests']:
                    # Exercise the public examples in their documented order, preserving cookies.
                    status, body, _ = client.request(request['path'], request['method'], request['body'])
                    expected = 403 if number in (1, 7) and request['path'] == '/admin' else 200
                    if number == 10 and request['path'] == '/api/purchase':
                        expected = 402
                    self.assertEqual(status, expected, request)
                    self.assertNotIn(self.suite.labs[number - 1].flag, str(body))

    def test_guides_keep_current_origin_and_existing_session(self):
        client = self.client(10)
        client.login()
        cookie = client.cookie
        status, guide, headers = client.request('/api/guide', headers={'Host': f'localhost:{self.base + 10}'})
        self.assertEqual(status, 200)
        self.assertEqual(guide['url'], f'http://localhost:{self.base + 10}')
        self.assertNotIn('Set-Cookie', headers)
        self.assertEqual(client.cookie, cookie)
        self.assertEqual(client.request('/api/wallet')[1]['credits'], 30)

    def test_guide_navigation_and_login_form_remain_accessible(self):
        from html.parser import HTMLParser

        class Navigation(HTMLParser):
            def __init__(self):
                super().__init__()
                self.ids, self.anchors, self.forms = [], [], []

            def handle_starttag(self, tag, attrs):
                attrs = dict(attrs)
                if 'id' in attrs:
                    self.ids.append(attrs['id'])
                if tag == 'a' and attrs.get('href', '').startswith('#'):
                    self.anchors.append(attrs['href'][1:])
                if tag == 'form':
                    self.forms.append(attrs)

        for number in range(1, 11):
            with self.subTest(number=number):
                client = self.client(number)
                _, body, _ = client.request()
                navigation = Navigation()
                navigation.feed(body)
                self.assertEqual(len(navigation.ids), len(set(navigation.ids)))
                for anchor in navigation.anchors:
                    self.assertIn(anchor, navigation.ids)
                self.assertIn('challenge-guide', navigation.ids)
                if number in (1, 3, 8, 10):
                    login = next(form for form in navigation.forms if form['id'] == 'member-login')
                    self.assertEqual(login['action'], '/api/login')
                    self.assertEqual(login['method'], 'post')
                    client.login()
                    self.assertIn('role=member', client.request()[1])

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

    def test_bronze_01_search_sql_injection(self):
        client = self.client(6)
        status, result, _ = client.request('/search?' + urlencode({'q': 'Notebook'}))
        self.assertEqual(status, 200)
        self.assertEqual(result['products'], [{'id': 1, 'title': 'Notebook'}])
        public = client.request('/search?' + urlencode({'q': ''}))[1]['products']
        self.assertEqual(len(public), 3)
        self.assertNotIn(self.suite.labs[5].flag, str(public))
        self.assertEqual(client.request('/search?' + urlencode({'q': "'"}))[0], 400)
        false_result = client.request('/search?' + urlencode({'q': "missing%' OR 1=2 -- "}))[1]
        self.assertEqual(false_result['products'], [])
        status, result, _ = client.request('/search?' + urlencode({'q': "missing%' OR 1=1 -- "}))
        self.assertEqual(status, 200)
        self.assertIn({'id': 4, 'title': self.suite.labs[5].flag}, result['products'])

    def test_bronze_02_cookie_role_tampering(self):
        client = self.client(7)
        self.assertEqual(client.request('/admin')[0], 403)
        _, _, headers = client.request()
        self.assertIn('lab_role_hard-02=member', headers['Set-Cookie'])
        self.assertEqual(client.request('/admin')[0], 403)
        client.cookie = 'lab_role_hard-02=admin'
        # A second home visit must preserve the edited role cookie.
        self.assertNotIn('Set-Cookie', client.request()[2])
        status, result, _ = client.request('/admin')
        self.assertEqual(status, 200)
        self.assertEqual(result['flag'], self.suite.labs[6].flag)
        client.cookie = 'lab_role_hard-02=owner'
        self.assertEqual(client.request('/admin')[0], 403)

    def test_bronze_03_direct_organization_idor(self):
        client = self.client(8)
        self.assertEqual(client.request('/api/organizations/northstar/summary')[0], 401)
        client.login()
        self.assertEqual(client.request('/api/me')[1]['organization'], 'acme')
        directory = client.request('/api/organizations')[1]['organizations']
        self.assertIn('northstar', [item['id'] for item in directory])
        status, own, _ = client.request('/api/organizations/acme/summary')
        self.assertEqual(status, 200)
        self.assertNotIn('private_note', own)
        status, other, _ = client.request('/api/organizations/northstar/summary')
        self.assertEqual(status, 200)
        self.assertEqual(other['private_note'], self.suite.labs[7].flag)
        self.assertEqual(client.request('/api/organizations/unknown/summary')[0], 404)

    def test_bronze_04_direct_internal_url_ssrf(self):
        client = self.client(9)
        self.assertEqual(Client(self.base + 99).request('/internal/flag')[0], 403)
        status, response, _ = client.request('/api/preview', 'POST', {'url': 'http://preview.internal/public/help'})
        self.assertEqual(status, 200)
        public = json.loads(response['content'])
        self.assertNotIn(self.suite.labs[8].flag, response['content'])
        self.assertEqual(public['internal_url'], f'http://127.0.0.1:{self.base + 99}/internal/flag')
        status, response, _ = client.request('/api/preview', 'POST', {'url': public['internal_url']})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(response['content'])['flag'], self.suite.labs[8].flag)

    def test_bronze_05_client_price_tampering(self):
        client = self.client(10)
        payload = {'product': 'premium-report', 'price': 100}
        self.assertEqual(client.request('/api/purchase', 'POST', payload)[0], 401)
        client.login()
        self.assertEqual(client.request('/api/wallet')[1], {'credits': 30, 'premium_price': 100})
        self.assertEqual(client.request('/api/purchase', 'POST', payload)[0], 402)
        for price in (None, 0, -1, True, '1', 1.5):
            with self.subTest(price=price):
                self.assertEqual(client.request('/api/purchase', 'POST', {'product': 'premium-report', 'price': price})[0], 400)
        self.assertEqual(client.request('/api/wallet')[1]['credits'], 30)
        self.assertEqual(client.request('/api/purchase', 'POST', {'product': 'unknown', 'price': 1})[0], 400)
        status, result, _ = client.request('/api/purchase', 'POST', {'product': 'premium-report', 'price': 1})
        self.assertEqual(status, 200)
        self.assertEqual(result['flag'], self.suite.labs[9].flag)
        self.assertEqual(result['credits'], 29)

    def test_sessions_and_wallets_are_isolated(self):
        client = self.client(8)
        client.login()
        other_site = self.client(10)
        other_site.cookie = client.cookie
        self.assertEqual(other_site.request('/api/wallet')[0], 401)
        one, two = self.client(10), self.client(10)
        one.login()
        two.login()
        one.request('/api/purchase', 'POST', {'product': 'premium-report', 'price': 1})
        self.assertEqual(one.request('/api/wallet')[1]['credits'], 29)
        self.assertEqual(two.request('/api/wallet')[1]['credits'], 30)

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

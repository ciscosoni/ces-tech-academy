#!/usr/bin/env python3
"""CES Tech Academy · Cisco SD-WAN Design in Practice · lab helper

Reads the design of a running SD-WAN from its Manager (vManage) REST API. Read-only: it signs in, makes four
GET calls, prints what it finds as tables, suggests what the design is, and signs out.

    python3 sdwan_lab.py --manager <address[:port]> --user <username> --insecure
    python3 sdwan_lab.py --manager <address> --user <username> --insecure --edge <system-ip> --save out/

  --insecure   accept a self-signed certificate. Sandboxes and labs need it. Never use it against production.
  --edge       system IP of the WAN Edge router to inspect (default: the first reachable one)
  --save DIR   also save the raw JSON replies in DIR

The password is asked for when the script starts and is never stored. (For automation only, the script reads
the environment variable SDWAN_PASS if it is set.) Needs Python 3.8 or later and no extra packages.
"""
import argparse, getpass, http.cookiejar, json, os, ssl, sys, urllib.error, urllib.parse, urllib.request


def table(rows, cols):
    """Print a list of dicts as an aligned table. cols = [(key, heading), ...]."""
    if not rows:
        print('  (no rows)'); return
    data = [[str(r.get(k, '-')) for k, _ in cols] for r in rows]
    width = [max(len(h), *(len(d[i]) for d in data)) for i, (_, h) in enumerate(cols)]
    print('  ' + '   '.join(h.ljust(width[i]) for i, (_, h) in enumerate(cols)))
    for d in data:
        print('  ' + '   '.join(v.ljust(width[i]) for i, v in enumerate(d)))


class Manager:
    def __init__(self, host, insecure):
        self.base = 'https://' + host
        ctx = ssl.create_default_context()
        if insecure:
            ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        self.opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx),
                                                  urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def call(self, path, data=None, headers=None, method=None):
        req = urllib.request.Request(self.base + path, data=data, headers=headers or {}, method=method)
        with self.opener.open(req, timeout=30) as r:
            return r.read()

    def login(self, user, password):
        body = urllib.parse.urlencode({'j_username': user, 'j_password': password}).encode()
        reply = self.call('/j_security_check', data=body, headers={'Content-Type': 'application/x-www-form-urlencoded'})
        if b'<html' in reply.lower():          # a login page comes back when the credentials are wrong
            raise SystemExit('Sign-in failed: check the address, the user name and the password.')

    def get(self, path):
        reply = self.call(path)
        try:
            return json.loads(reply).get('data', [])
        except ValueError:
            raise SystemExit('The Manager did not return JSON for ' + path + '. Is the session still valid?')

    def logout(self):
        try:
            token = self.call('/dataservice/client/token').decode().strip()
            self.call('/logout', data=b'', headers={'X-XSRF-TOKEN': token}, method='POST')
        except Exception:
            pass                               # signing out is best effort


def main():
    ap = argparse.ArgumentParser(description='Read the design of a running Cisco SD-WAN (read-only).')
    ap.add_argument('--manager', required=True, help='Manager address, with :port if needed')
    ap.add_argument('--user', required=True)
    ap.add_argument('--edge', help='system IP of the WAN Edge router to inspect')
    ap.add_argument('--insecure', action='store_true', help='accept a self-signed certificate (labs and sandboxes only)')
    ap.add_argument('--save', metavar='DIR', help='save the raw JSON replies in this folder')
    a = ap.parse_args()
    password = os.environ.get('SDWAN_PASS') or getpass.getpass('Password for ' + a.user + ': ')

    def save(name, data):
        if a.save:
            os.makedirs(a.save, exist_ok=True)
            with open(os.path.join(a.save, name + '.json'), 'w') as f:
                json.dump(data, f, indent=1)

    m = Manager(a.manager, a.insecure)
    try:
        m.login(a.user, password)
    except urllib.error.URLError as e:
        raise SystemExit('Cannot reach the Manager: %s\n(For a sandbox with a self-signed certificate, add --insecure. For a reservable sandbox, connect the VPN first.)' % e.reason)
    try:
        # 1. inventory
        devices = m.get('/dataservice/device'); save('device', devices)
        print('\n1. Who is here?   GET /dataservice/device')
        table(devices, [('host-name', 'host-name'), ('device-type', 'device-type'), ('system-ip', 'system-ip'), ('site-id', 'site-id'), ('reachability', 'reachability')])
        count = {}
        for d in devices: count[d.get('device-type', '?')] = count.get(d.get('device-type', '?'), 0) + 1
        names = {'vmanage': 'Manager', 'vsmart': 'Controller', 'vbond': 'Validator', 'vedge': 'WAN Edge router'}
        print('  Roles: ' + ', '.join('%d x %s (%s)' % (n, names.get(t, t), t) for t, n in sorted(count.items())))
        edges = [d for d in devices if d.get('device-type') == 'vedge']
        edge = a.edge or next((d.get('system-ip') for d in edges if d.get('reachability') == 'reachable'), None)
        if not edge:
            raise SystemExit('No reachable WAN Edge router found. Use --edge <system-ip>.')
        q = '?deviceId=' + urllib.parse.quote(edge)
        me = next((d for d in devices if d.get('system-ip') == edge), {})
        print('\n  Inspecting %s (%s), site %s' % (me.get('host-name', '?'), edge, me.get('site-id', '?')))

        # 2. control connections
        ctl = m.get('/dataservice/device/control/connections' + q); save('control_connections', ctl)
        print('\n2. Is it connected to its controllers?   GET /dataservice/device/control/connections')
        table(ctl, [('peer-type', 'peer-type'), ('system-ip', 'system-ip'), ('local-color', 'local-color'), ('protocol', 'protocol'), ('state', 'state')])

        # 3. tunnels
        bfd = m.get('/dataservice/device/bfd/sessions' + q); save('bfd_sessions', bfd)
        print('\n3. Which tunnels does it have?   GET /dataservice/device/bfd/sessions')
        table(bfd, [('system-ip', 'remote system-ip'), ('site-id', 'site-id'), ('local-color', 'local-color'), ('color', 'remote-color'), ('state', 'state')])

        # 4. routes
        omp = m.get('/dataservice/device/omp/routes/received' + q); save('omp_routes_received', omp)
        seen, routes = set(), []
        for r in omp:
            k = (str(r.get('vpn-id', '-')), r.get('prefix', '-'))
            if k not in seen:
                seen.add(k); routes.append({'vpn-id': k[0], 'prefix': k[1], 'originator': r.get('originator', '-')})
        print('\n4. Which routes has it received?   GET /dataservice/device/omp/routes/received   (each prefix once per VPN)')
        table(routes[:40], [('vpn-id', 'vpn-id'), ('prefix', 'prefix'), ('originator', 'originator')])
        if len(routes) > 40: print('  … and %d more' % (len(routes) - 40))

        # what the output suggests
        print('\nWhat this suggests (check it against the tables above):')
        colours = sorted({s.get('local-color', '?') for s in bfd} | {c.get('local-color', '?') for c in ctl})
        print('  Colours on this router: ' + (', '.join(colours) or 'none seen'))
        cross = [s for s in bfd if s.get('local-color') != s.get('color')]
        down = sum(1 for s in cross if s.get('state') != 'up')
        if down: print('  (Cross-colour tunnels that stay down usually mean the transports do not meet and restrict is missing.)')
        print('  Tunnels between different colours: ' + ('%d (%d of them down)' % (len(cross), down) if cross else 'none, so the colours are restricted'))
        other_sites = {str(d.get('site-id')) for d in edges} - {str(me.get('site-id'))}
        tunnel_sites = {str(s.get('site-id')) for s in bfd if s.get('state') == 'up'}
        if other_sites:
            if other_sites <= tunnel_sites:
                print('  Topology: tunnels to every other WAN Edge site (%d of %d). This looks like a full mesh.' % (len(other_sites), len(other_sites)))
            else:
                print('  Topology: tunnels to %d of the %d other WAN Edge sites (sites %s). This looks like hub and spoke, or a partial mesh.' % (
                    len(tunnel_sites & other_sites), len(other_sites), ', '.join(sorted(tunnel_sites)) or 'none'))
        vpns = sorted({r['vpn-id'] for r in routes}, key=lambda v: (len(v), v))
        print('  Service VPNs in the received routes: ' + (', '.join(vpns) or 'none seen'))
        if a.save: print('\nRaw replies saved in ' + a.save)
    finally:
        m.logout()
    print('\nSigned out.')


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(1)

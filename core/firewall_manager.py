import subprocess
import json
import datetime
import os

# ─── Path to blocked IPs storage ─────────────────────────────
BLOCKED_IPS_FILE = '/home/lingkong/NAIDS_Project/api/blocked_ips.json'

# ─── Trusted IP Whitelist ─────────────────────────────────────
# These IP prefixes are NEVER blocked regardless of AI detection
WHITELISTED_PREFIXES = [
    # Local network
    '192.168.1.',        # Entire local network
    '127.0.0.',          # Localhost
    # Google services
    '8.8.8.',            # Google DNS
    '8.8.4.',            # Google DNS
    '142.250.',          # Google servers
    '172.217.',          # Google servers
    '216.58.',           # Google servers
    # Microsoft services
    '13.107.',           # Microsoft
    '52.96.',            # Microsoft Office 365
    '40.96.',            # Microsoft
    '20.190.',           # Microsoft Azure
    '52.184.',           # Microsoft
    # Cloudflare
    '104.16.',           # Cloudflare
    '104.17.',           # Cloudflare
    '104.18.',           # Cloudflare
    '1.1.1.',            # Cloudflare DNS
    '1.0.0.',            # Cloudflare DNS
    # Meta — WhatsApp and Facebook
    '157.240.',          # WhatsApp/Facebook
    '31.13.',            # Facebook
    '179.60.',           # Facebook
    # Telegram
    '149.154.',          # Telegram servers
    '91.108.',           # Telegram servers
    # Amazon AWS
    '52.94.',            # Amazon AWS
    '54.230.',           # Amazon CloudFront
    '13.224.',           # Amazon CloudFront
    # African ISPs
    '196.216.',          # MTN Cameroon
    '197.0.',            # Orange Cameroon
    '196.201.',          # Camtel
]

# ─── Load blocked IPs from file ──────────────────────────────
def load_blocked_ips():
    """Read all blocked IPs from JSON file"""
    try:
        with open(BLOCKED_IPS_FILE, 'r') as f:
            return json.load(f)
    except:
        return []

# ─── Save blocked IPs to file ────────────────────────────────
def save_blocked_ips(blocked_list):
    """Save blocked IPs list to JSON file"""
    with open(BLOCKED_IPS_FILE, 'w') as f:
        json.dump(blocked_list, f, indent=2)

# ─── Check if IP is already blocked ──────────────────────────
def is_ip_blocked(ip_address):
    """Returns True if IP is already in blocked list"""
    blocked = load_blocked_ips()
    return any(b['ip'] == ip_address for b in blocked)

# ─── Block an IP address ──────────────────────────────────────
def block_ip(ip_address, reason='Manual block', duration='permanent'):
    """
    Block an IP address using iptables
    duration: 'permanent', '1hour', '24hours'
    Returns: dict with success status and message
    """
    try:
        # Check if already blocked
        if is_ip_blocked(ip_address):
            return {
                'success': False,
                'message': f'{ip_address} is already blocked'
            }

        # Execute iptables block command
        cmd = [
            'sudo', 'iptables',
            '-A', 'INPUT',
            '-s', ip_address,
            '-j', 'DROP'
        ]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10
        )

        if result.returncode == 0:
            # Calculate expiry time
            now = datetime.datetime.now()
            if duration == '1hour':
                expires = (now + datetime.timedelta(hours=1)
                          ).strftime('%Y-%m-%d %H:%M:%S')
            elif duration == '24hours':
                expires = (now + datetime.timedelta(hours=24)
                          ).strftime('%Y-%m-%d %H:%M:%S')
            else:
                expires = 'Never'

            # Save to blocked IPs file
            blocked = load_blocked_ips()
            blocked.append({
                'ip': ip_address,
                'reason': reason,
                'blocked_at': now.strftime('%Y-%m-%d %H:%M:%S'),
                'expires': expires,
                'duration': duration,
                'status': 'active'
            })
            save_blocked_ips(blocked)

            return {
                'success': True,
                'message': f'{ip_address} blocked successfully',
                'expires': expires,
                'duration': duration
            }
        else:
            return {
                'success': False,
                'message': f'iptables error: {result.stderr}'
            }

    except subprocess.TimeoutExpired:
        return {
            'success': False,
            'message': 'Command timed out'
        }
    except Exception as e:
        return {
            'success': False,
            'message': f'Error: {str(e)}'
        }

# ─── Unblock an IP address ────────────────────────────────────
def unblock_ip(ip_address):
    """
    Remove iptables block for an IP address
    Returns: dict with success status and message
    """
    try:
        # Execute iptables unblock command
        cmd = [
            'sudo', 'iptables',
            '-D', 'INPUT',
            '-s', ip_address,
            '-j', 'DROP'
        ]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10
        )

        # Remove from blocked IPs file regardless
        blocked = load_blocked_ips()
        blocked = [b for b in blocked if b['ip'] != ip_address]
        save_blocked_ips(blocked)

        return {
            'success': True,
            'message': f'{ip_address} unblocked successfully'
        }

    except Exception as e:
        return {
            'success': False,
            'message': f'Error: {str(e)}'
        }

# ─── Auto-expire timed blocks ────────────────────────────────
def check_expired_blocks():
    """
    Check all blocked IPs and unblock any that have expired
    This runs automatically every minute via APScheduler
    """
    blocked = load_blocked_ips()
    now = datetime.datetime.now()
    expired_count = 0

    for entry in blocked:
        if entry['expires'] != 'Never':
            expiry_time = datetime.datetime.strptime(
                entry['expires'], '%Y-%m-%d %H:%M:%S'
            )
            if now >= expiry_time:
                result = unblock_ip(entry['ip'])
                if result['success']:
                    expired_count += 1
                    print(f"Auto-unblocked expired IP: {entry['ip']}")

    return expired_count

# ─── Get all blocked IPs ──────────────────────────────────────
def get_blocked_ips():
    """Returns list of all currently blocked IPs"""
    return load_blocked_ips()

# ─── Auto-block critical threats ─────────────────────────────
def auto_block_if_critical(analysis_result, src_ip):
    """
    Automatically block IP if threat is critical.
    Only fires when both engines agree (BLOCK_IMMEDIATELY).
    Never blocks whitelisted IPs.
    """
    # ── CHECK WHITELIST FIRST ─────────────────────────────────
    for prefix in WHITELISTED_PREFIXES:
        if src_ip.startswith(prefix):
            return False

    # ── CHECK IF THREAT ───────────────────────────────────────
    if not analysis_result.get('is_threat'):
        return False

    confidence   = analysis_result.get('confidence', 0)
    attack_type  = analysis_result.get('attack_type', '')
    recommendation = analysis_result.get('recommendation', {})
    action       = recommendation.get('action', '')

    # ── AUTO-BLOCK ONLY WHEN BOTH ENGINES AGREE ───────────────
    if action == 'BLOCK_IMMEDIATELY':
        result = block_ip(
            src_ip,
            reason=f'Auto-blocked: {attack_type} '
                   f'({confidence:.1f}% confidence)',
            duration='24hours'
        )
        if result['success']:
            print(f"🛡️ AUTO-BLOCKED: {src_ip} — {attack_type}")
            return True

    return False
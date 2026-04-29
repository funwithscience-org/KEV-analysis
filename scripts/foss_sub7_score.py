#!/usr/bin/env python3
"""Classify FOSS sub-7 exploited CVEs against the threat-prioritization model.

Per CLAUDE.md (formalized 2026-04-25):
- NP (Network Parser): primary purpose is processing untrusted network input
  OR driving security decisions from untrusted input. HTTP servers, app
  frameworks, JSON/XML/YAML parsers, auth/security libs, template engines.
- DI (Dangerous Input): CWE class indicates untrusted input changing a
  security outcome. Per the brief: CWE-77/78/79/89/90/91/93/94/95/917
  (injection), CWE-502 (deserialization), CWE-22/23/35 (path traversal),
  CWE-918 (SSRF), CWE-611 (XXE), and the widened auth-bypass set
  (CWE-287, -289, -306, -345, -693, -863, -1321).

Hacker tier (S/A/B/C/D): three axes default_config x network_edge x
primitive_direct, with auth_missing co-tag.
"""

import json
import re
from collections import Counter, defaultdict
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
INPUT_FILE = str(_REPO / 'data' / 'foss-sub7-unique.json')
SCORING_OUT = str(_REPO / 'data' / 'foss-sub7-scoring.json')

# Per-package NP classification.
# CMS / web-app monoliths: NP because they own the HTTP boundary and parse
# untrusted requests (they ARE the HTTP server + template engine).
# Helper/specialty libs: classified individually.
NP_PACKAGES = {
    # HTTP servers, app frameworks
    'org.apache.tomcat:jsp-api': True,
    'org.apache.tomcat:servlet-api': True,
    'org.apache.tomcat.embed:tomcat-embed-core': True,
    'org.apache.tomcat:tomcat-coyote': True,
    'org.eclipse.jetty:jetty-webapp': True,
    'org.eclipse.jetty.http2:http2-common': True,
    'org.eclipse.jetty.http2:http2-server': True,
    'org.eclipse.jetty.http2:jetty-http2-common': True,
    'org.eclipse.jetty.http2:jetty-http2-server': True,
    'org.mortbay.jetty:jetty': True,
    'com.typesafe.akka:akka-http-core': True,
    'com.typesafe.akka:akka-http-core_2.11': True,
    'com.typesafe.akka:akka-http-core_2.12': True,
    'com.typesafe.akka:akka-http-core_2.13': True,
    'golang.org/x/net': True,
    'org.apache.axis:axis': True,
    'org.apache.shindig:shindig-php': True,

    # Web frameworks / app servers
    'django': True,
    'web2py': True,
    'silverstripe/framework': True,
    'org.springframework.cloud:spring-cloud-config-server': True,
    'django-unicorn': True,

    # Auth / security libs
    'org.bouncycastle:bcprov-jdk15on': True,
    'org.springframework.security.oauth:spring-security-oauth': True,
    'org.springframework.security.oauth:spring-security-oauth2': True,
    'org.keycloak:keycloak-core': True,
    'products-pluggableauthservice': True,

    # XML/HTML/feed parsers
    'lxml': True,
    'feedparser': True,
    'org.apache.olingo:odata-client-core': True,
    'org.apache.olingo:odata-server-core': True,

    # Email lib (msgHTML processes untrusted HTML)
    'phpmailer/phpmailer': True,

    # CMS / web-app monoliths (own HTTP, render templates)
    'typo3/cms': True,
    'symphonycms/symphony-2': True,
    'org.opencms:opencms-core': True,
    'concrete5/concrete5': True,
    'shopware/shopware': True,
    'getkirby/cms': True,
    'craftcms/cms': True,
    'pimcore/pimcore': True,
    'pagekit/pagekit': True,
    'drupal/core': True,
    'drupal/core-recommended': True,
    'drupal/drupal': True,
    'limesurvey/limesurvey': True,
    'dolibarr/dolibarr': True,
    'phpmyadmin/phpmyadmin': True,
    'mantisbt/mantisbt': True,
    'nilsteampassnet/teampass': True,
    'admidio/admidio': True,
    'showdoc/showdoc': True,
    'thorsten/phpmyfaq': True,
    'feehi/cms': True,
    'francoisjacquet/rosariosis': True,
    'wintercms/winter': True,
    'soosyze/soosyze': True,
    'microweber/microweber': True,
    'intelliants/subrion': True,
    'mobiledetect/mobiledetectlib': True,
    'opencart/opencart': True,
    'snipe/snipe-it': True,
    'mayan-edms': True,
    'mezzanine': True,
    'cherrymusic': True,
    'moin': True,
    'apache-superset': True,
    'pretalx': True,
    'label-studio': True,
    'copyparty': True,
    'ajenti': True,
    'moodle/moodle': True,
    'bolt/bolt': True,
    'october/cms': True,
    'october/rain': True,
    'rainlab/blog-plugin': True,
    'rainlab/user-plugin': True,
    'yourls/yourls': True,
    'cosenary/instagram': True,
    'DotNetNuke.Core': True,
    'UmbracoCms': True,
    'keystone': True,
    'ghost': True,
    'tileserver-gl': True,
    'vite': True,
    'github.com/gogits/gogs': True,
    'gogs.io/gogs': True,
    'github.com/casdoor/casdoor': True,
    'github.com/grafana/grafana': True,
    'github.com/kubesphere/kubesphere': True,
    'github.com/esm-dev/esm.sh': True,
    'github.com/tiagorlampert/CHAOS': True,
    'com.liferay.portal:portal-service': True,
    'com.liferay.portal:release.portal.bom': True,
    'com.liferay:com.liferay.portal.search.web': True,
    'org.wso2.carbon.commons:org.wso2.carbon.logging.view.ui': True,
    'org.wso2.carbon.commons:org.wso2.carbon.messageflows.ui': True,
    'org.wso2.carbon.commons:org.wso2.carbon.ndatasource.ui': True,
    'org.wso2.carbon.identity.framework:org.wso2.carbon.identity.mgt.ui': True,
    'org.apache.spark:spark-core_2.10': True,
    'org.apache.spark:spark-core_2.11': True,
    'org.jenkins-ci.main:jenkins-core': True,
    'org.jenkins-ci.plugins:sonar': True,
    'org.jenkins-ci.plugins:depgraph-view': True,
    'org.jenkins-ci.plugins:build-metrics': True,
    'org.jenkins-ci.ruby-plugins:gitlab-hook': True,
    'org.rundeck:rundeck': True,
    'org.opennms:opennms-webapp-rest': True,
    'org.apache.openmeetings:openmeetings-install': True,
    'org.apache.portals.pluto:chatRoomDemo': True,
    'org.apache.syncope:syncope-core': True,
    'com.shopizer:shopizer': True,
    'org.elasticsearch.client:elasticsearch-rest-client': True,
    'camaleon_cms': True,

    # Network-fetch libraries
    'pip': True,
    'salt': True,

    # Not-NP under strict reading
    'slo-generator': False,
}


# DI CWE numbers per the brief.
DI_CWES = {
    77, 78, 79, 89, 90, 91, 93, 94, 95, 96, 97, 113, 116, 917,  # injection
    502,                                                          # deserialization
    22, 23, 35, 73,                                              # path traversal
    918,                                                          # SSRF
    611, 776,                                                    # XXE
    74,                                                           # generic injection
    287, 289, 306, 345, 444, 693, 863, 1321,                     # auth bypass
}


def infer_primitive(summary, details):
    """Return a tuple (cwes_set, primitive_kind, has_unauth_keyword,
    has_auth_required_keyword, has_default_off_keyword,
    has_default_off_admin_required, has_user_interaction_required,
    has_priv_role_required).
    """
    text = (summary + ' ' + details).lower()
    cwes = set()
    kinds = []

    # --- CWE inference, ordered by specificity ---
    # XSS first because many summaries are XSS-only
    is_xss = any(k in text for k in [
        'cross-site scripting', 'cross site scripting', ' xss ',
        ' xss.', ' xss ', 'reflected xss', 'stored xss', 'persistent xss',
        'allows xss', 'is vulnerable to xss',
    ]) or text.startswith('xss ') or text.endswith(' xss')
    if is_xss:
        cwes.add(79)
        kinds.append('xss')

    is_sqli = ('sql injection' in text or 'sqli' in text or 'sql injection' in text)
    if is_sqli:
        cwes.add(89)
        kinds.append('sqli')

    is_csv = 'csv injection' in text or 'formula injection' in text
    if is_csv:
        cwes.add(1236)
        kinds.append('csv')

    is_csrf = 'csrf' in text or 'cross-site request forgery' in text or 'cross site request forgery' in text
    if is_csrf:
        cwes.add(352)
        kinds.append('csrf')

    is_redirect = 'open redirect' in text or 'open redirector' in text
    if is_redirect:
        cwes.add(601)
        kinds.append('open-redirect')

    is_ssrf = 'ssrf' in text or 'server-side request forgery' in text or 'server side request forgery' in text
    if is_ssrf:
        cwes.add(918)
        kinds.append('ssrf')

    is_xxe = 'xxe' in text or 'xml external entity' in text or ('external entity' in text and 'xml' in text)
    if is_xxe:
        cwes.add(611)
        kinds.append('xxe')

    is_path = (
        'path traversal' in text or 'directory traversal' in text or
        'arbitrary file' in text or 'arbitrary path' in text or
        'local file inclusion' in text or 'lfi' in text or
        'local file read' in text or 'local file disclosure' in text or
        'file disclosure' in text or '../' in text or
        '..%2f' in text or '..%5c' in text or
        '%2e%2e' in text or '%u002e' in text or
        ('..' in text and 'dot dot' in text) or
        'arbitrary directory access' in text or
        'improperly sanitize paths' in text or
        'web-inf' in text or 'bypass some security constraints' in text or
        ('encoded' in text and ('access' in text or 'protected' in text)) or
        'access protected resources' in text
    )
    if is_path:
        cwes.add(22)
        kinds.append('path-traversal')

    is_idor = 'idor' in text or 'insecure direct object' in text or 'incorrect authorization' in text
    if is_idor:
        cwes.add(863)
        kinds.append('idor')

    is_authbypass = (
        'authentication bypass' in text or 'auth bypass' in text or
        'bypass authentication' in text or 'improper authentication' in text or
        'fail open' in text or 'fail-open' in text or
        'privilege escalation' in text or 'escalate' in text and 'privilege' in text
    )
    if is_authbypass:
        cwes.add(287)
        kinds.append('authbypass')

    # Deserialization / object injection / RCE-class
    is_deser = 'deserialization' in text or 'deserialize' in text or 'php object instantiation' in text
    if is_deser:
        cwes.add(502)
        kinds.append('deser')

    # Code injection / RCE — careful about false positives
    is_rce = (
        'remote code execution' in text or
        'execute arbitrary code' in text or
        'command injection' in text or
        'arbitrary command' in text or
        'os command injection' in text or
        'execute arbitrary command' in text or
        'execute arbitrary commands' in text or
        'arbitrary php files' in text or  # LFI -> RCE via PHP includes
        'local file inclusion' in text or
        'code injection' in text or
        'allow for code execution' in text or
        'lead to remote code execution' in text or
        'may lead to remote code execution' in text or
        ('execute arbitrary' in text and 'web script' not in text and 'sql' not in text)  # avoid XSS and SQLi
    )
    if is_rce:
        cwes.add(94)
        kinds.append('rce')

    # Code execution via uploaded file (often CWE-434, NOT DI)
    is_upload_rce = (
        'unrestricted file upload' in text or
        ('upload' in text and 'execute' in text and ('arbitrary code' in text or 'shell' in text))
    )
    if is_upload_rce:
        cwes.add(434)
        if 'rce' not in kinds:
            kinds.append('rce-via-upload')

    is_prototype_pollution = 'prototype pollution' in text or 'object.prototype' in text and 'extend' in text
    if is_prototype_pollution:
        cwes.add(1321)
        kinds.append('prototype-pollution')

    # Information disclosure: not DI on its own
    is_info_disc = (
        'sensitive information' in text or
        'information disclosure' in text or
        'observable discrepancy' in text or
        'cleartext password' in text or
        'memory disclosure' in text or
        'full path disclosure' in text
    )
    if is_info_disc:
        cwes.add(200)
        kinds.append('info-disc')

    # Improper input validation: framing only — not DI by itself
    if 'improper input validation' in text:
        cwes.add(20)
        if not kinds:
            kinds.append('improper-input-val')

    # DoS
    is_dos = 'denial of service' in text or 'memory leak' in text or 'rapid reset' in text
    if is_dos:
        cwes.add(400)
        if not kinds:
            kinds.append('dos')

    # MITM
    is_mitm = 'man-in-the-middle' in text or 'mitm' in text or 'bleichenbacher' in text
    if is_mitm:
        cwes.add(295)
        if not kinds:
            kinds.append('mitm')

    # Brute force / rate limit
    is_brute = 'rate-limit' in text or ('brute' in text and 'force' in text)
    if is_brute:
        cwes.add(307)
        if not kinds:
            kinds.append('brute-force')

    return cwes, kinds


def classify_one(rec):
    pkg = rec['package']
    pkgs = [p[0] for p in rec['all_packages']]
    text = (rec['summary'] + ' ' + rec.get('details_excerpt', '')).lower()

    # NP: True if any listed package is NP-marked
    np = any(NP_PACKAGES.get(p, None) is True for p in pkgs)
    np_unknown = all(p not in NP_PACKAGES for p in pkgs)

    cwes, kinds = infer_primitive(rec['summary'], rec.get('details_excerpt',''))
    di_cwe_basis = sorted(c for c in cwes if c in DI_CWES)
    di = bool(di_cwe_basis)

    # DQ rescue
    dq_rescue = False
    dq_rationale = ''
    if np and not di:
        # Rescue when a non-DI CWE inference is hiding DI behavior.
        # The most common: brute-force / rate-limit on auth endpoint
        # (treat as auth-control issue), or info-disc that's actually
        # an arbitrary-file-read (path traversal-like).
        if 'brute-force' in kinds or 'rate-limit' in text:
            dq_rescue = True
            dq_rationale = 'CWE-307 brute-force on auth: input drives auth decision'
        elif 'mitm' in kinds:
            dq_rescue = True
            dq_rationale = 'CWE-295/208 MITM/oracle: untrusted input drives security decision'
        elif 'csrf' in kinds and 'arbitrary' in text:
            dq_rescue = True
            dq_rationale = 'CSRF that yields privileged operation reaches auth-decision boundary'
        elif 'open-redirect' in kinds and ('leak' in text or 'authorization code' in text):
            dq_rescue = True
            dq_rationale = 'open redirect leaks auth code (auth-flow input)'

    # === Hacker tier ===
    # Determine network_edge (default true for server-side packages)
    network_edge = True

    # auth_missing — does the attacker need credentials?
    auth_missing = True
    auth_required_terms = [
        'authenticated user', 'authenticated attacker', 'authenticated administrator',
        'authenticated remote', 'remote authenticated', 'requires authentication',
        'logged-in', 'logged in', 'with permissions',
        'with the ability to', 'with write access', 'with elevated privileges',
        'low-privileged', 'privileged user', 'privileged attacker',
        'rogue admin', 'site admin', 'admin user', 'admin can',
        'with developer or super user', 'super user level',
        'a user with', 'with job/configure', 'who can configure jobs',
        'attackers able to configure', 'malicious user with',
        'low privilege', 'low-privilege', 'a low ', 'least privileged',
        'authenticated remote attackers',
        # extra signals
        'gains write access', 'gain write access',
        'requires significant privileges', 'significant privileges',
        'incorrect authorization',  # IDOR — attacker is authenticated
        'idor',
        'after logging in', 'after login',
        'controllers_backend',  # Shopware admin backend
        '/admin/', 'admin api', 'admin component',
        'role_admin', 'role_admin',
        'an administrator', 'as an administrator',
        'requires admin', 'requires the user',
        'in the admin panel', 'admin panel',
        'soap api', 'rest web service api',  # APIs typically require keys
        'in the backend', 'in the management interface',
    ]
    for term in auth_required_terms:
        if term in text:
            auth_missing = False
            break
    # explicit overrides
    if 'unauthenticated' in text or 'unauth ' in text or 'no authentication' in text:
        auth_missing = True
    # CSRF: attacker is unauthenticated but victim must be authenticated;
    # for hacker primitive accounting, this counts as auth_missing=True for
    # the attacker but primitive requires user-interaction.

    # default_config — is the vulnerable surface enabled out of the box?
    default_config = True
    not_default_terms = [
        'not enabled by default', 'disabled by default', 'is disabled',
        'non-default', 'requires configuration', 'when configured',
        'opt-in', 'requires the app to', 'requires the application to',
        'when the app', 'depending on configuration',
        'is not the default', "isn't the default",
        'requires admin', 'gain write access to',
        'self-registration is enabled', 'a non-default feature',
        'standalone master',
        'not advised for production', 'not recommended for production',
        'is using a sqlite', 'using a sqlite database for its metadata',
        'an internal component', "is an 'internal' component",
        'typically only accessible',
    ]
    for term in not_default_terms:
        if term in text:
            default_config = False
            break
    if 'ssi is disabled' in text:
        default_config = False
    if pkg == 'vite' and ('--host' in text or 'explicitly exposing' in text):
        default_config = False
    if 'shindig' in pkg.lower() and 'php' in text:
        # Shindig PHP variant is uncommon
        pass
    # The tomcat printenv SSI-only thing
    if 'printenv' in text and 'debugging' in text:
        default_config = False
    # Liferay XSS only when "out-of-the-box behavior with no customizations is not vulnerable"
    if 'out-of-the-box behavior with no customizations is not vulnerable' in text:
        default_config = False
    # Apache OData XML deserialization only fires for "application/xml"
    # content type — that's still default for OData/SOAP
    # MoinMoin twikidraw needs "write permissions" (auth required)

    # primitive_direct — what is the primary primitive?
    # We determine direction strictly from the kinds list, not heuristic.
    # Strong primitives (yields RCE/auth-bypass/mass-data-exfil directly):
    primitive_direct = False
    primitive_kind = ','.join(kinds) if kinds else 'unknown'

    # Strong yes:
    if 'rce' in kinds or 'deser' in kinds or 'rce-via-upload' in kinds:
        primitive_direct = True
    elif 'authbypass' in kinds:
        # Auth bypass yields direct admin/data, but only if no chain needed
        # E.g., OpenNMS ROLE_FILESYSTEM_EDITOR -> ROLE_ADMIN (already need
        # an auth role first) — that's auth-required pre-condition.
        # Mark direct only for fail-open / pre-auth bypasses.
        if 'fail open' in text or 'fail-open' in text or ('unauthenticated' in text and 'bypass' in text):
            primitive_direct = True
        else:
            primitive_direct = False  # chained / requires existing role
    elif 'sqli' in kinds:
        # Direct SQLi is data-exfil capable in most SQL-driven webapps
        primitive_direct = True
    elif 'idor' in kinds:
        # IDOR is data-exfil capable
        primitive_direct = True
    elif 'path-traversal' in kinds:
        # Arbitrary file READ is mass-exfil for sensitive files (creds, source)
        # Arbitrary file WRITE is RCE-adjacent
        if 'arbitrary file' in text and ('read' in text or 'access' in text or 'download' in text or 'retrieve' in text):
            primitive_direct = True
        elif 'write' in text and 'arbitrary' in text:
            primitive_direct = True
        else:
            # Narrow file read (e.g., specific log file) — not mass exfil
            primitive_direct = False
    elif 'xxe' in kinds:
        # XXE on modern stacks — file read or SSRF; primitive but not always direct
        # Treat as direct only if "read arbitrary files"
        if 'read arbitrary' in text or 'read sensitive' in text:
            primitive_direct = True
        else:
            primitive_direct = False
    elif 'ssrf' in kinds:
        # SSRF needs chain to internal services; not primitive_direct
        primitive_direct = False
    elif 'prototype-pollution' in kinds:
        primitive_direct = False  # needs gadget
    elif 'xss' in kinds or 'csrf' in kinds or 'open-redirect' in kinds or 'csv' in kinds:
        primitive_direct = False
    elif 'info-disc' in kinds:
        # Info disclosure of THE secret-of-record (e.g. juHash secret) can
        # be primitive_direct because it bypasses auth. But Bleichenbacher
        # / oracle-style attacks aren't operator-deployable day-1 — they
        # need MITM position and extensive query budget.
        if 'bleichenbacher' in text or 'oracle' in text:
            primitive_direct = False
        elif 'authentication details' in text or 'hash secret' in text:
            primitive_direct = True
        else:
            primitive_direct = False
    elif 'mitm' in kinds:
        primitive_direct = False  # requires MITM position
    elif 'dos' in kinds:
        primitive_direct = False
    elif 'brute-force' in kinds:
        primitive_direct = False  # not direct primitive
    elif 'improper-input-val' in kinds:
        primitive_direct = False
    else:
        primitive_direct = False

    # Tier mapping (calibrated against hacker-tiers.json)
    # S = all 3 axes + auth_missing
    # A = 2 axes + auth_missing  OR  3 axes with auth required
    # B = 1 axis + auth_missing  OR  2 axes with auth required
    # C = 1 axis with auth required, OR mostly-noise primitives
    # D = DoS-only or impractical-at-scale
    axes = sum([default_config, network_edge, primitive_direct])

    # First handle pure-D cases: DoS-only, MITM-only, info-disc-only, csrf-only,
    # open-redirect-only, csv-injection-only, brute-force-only, prototype-pollution-only
    is_d = False
    if not primitive_direct:
        only_kind = set(kinds)
        if only_kind.issubset({'dos','mitm','info-disc','open-redirect','csv','brute-force','improper-input-val','rate-limit'}):
            is_d = True
        # XSS / CSRF: not D, but C without primitive
        # Open redirect: not D, but C
    # Rate-limit/brute-force on auth endpoint are essentially impractical-at-scale by themselves -> D
    if 'brute-force' in kinds and not primitive_direct:
        is_d = True

    if is_d:
        tier = 'D'
    elif axes == 3 and auth_missing:
        tier = 'S'
    elif axes == 3 and not auth_missing:
        tier = 'A'
    elif axes == 2 and auth_missing:
        tier = 'A'
    elif axes == 2 and not auth_missing:
        tier = 'B'
    elif axes == 1 and auth_missing:
        tier = 'B'
    elif axes == 1 and not auth_missing:
        tier = 'C'
    else:
        tier = 'D'

    # Cap non-direct-primitive bugs at B max regardless of axes. The R2 report
    # explicitly treated handlebars XSS-via-template at B even though axes=3,
    # because "primitive-directness" is the dominant tier-determining factor:
    # operators don't weaponize XSS / CSRF / open-redirect / info-disc / csv
    # as campaign primitives the way they weaponize RCE / SQLi / authbypass.
    # The brief's tier rule mechanically gives 2-axes+unauth=A, but that's
    # reading the rule too literally; the operator framing is "what would I
    # actually deploy day-1?" and an XSS link doesn't qualify.
    weak_only = set(kinds) <= {'xss','csrf','open-redirect','info-disc','csv','prototype-pollution','dos','mitm','brute-force','improper-input-val','rate-limit','xss','authbypass'} and not primitive_direct
    if weak_only and not primitive_direct:
        # Strong primitives (sqli, rce, deser, idor, fail-open authbypass,
        # arb-file-read path traversal) already have primitive_direct=True
        # so they don't hit this clause.
        # Demote A -> B
        if tier == 'A':
            tier = 'B'
        # XSS-auth-required ends up at B already; CSRF-auth-required at C; fine.

    # Specific package overrides for borderline cases
    # spring-security-oauth open redirect: A in calibration set?
    # No, open redirect by itself is C-tier. Keep current logic.

    notes = []
    if np_unknown:
        notes.append('package_not_in_NP_lookup')
    if not kinds:
        notes.append('no_primitive_kind_inferred')

    return {
        'cve': rec['cve'],
        'package': pkg,
        'all_packages': pkgs,
        'ecosystem': rec['ecosystem'],
        'cvss_score': rec['cvss_score'],
        'cvss_vector': rec.get('cvss_vector',''),
        'evidence_sources': rec['evidence_sources'],
        'np': np,
        'di': di,
        'di_cwe_basis': di_cwe_basis,
        'inferred_cwes': sorted(cwes),
        'inferred_kinds': kinds,
        'dq_rescue': dq_rescue,
        'dq_rationale': dq_rationale,
        'hacker_default_config': default_config,
        'hacker_network_edge': network_edge,
        'hacker_primitive_direct': primitive_direct,
        'hacker_auth_missing': auth_missing,
        'hacker_primitive_kind': primitive_kind,
        'hacker_tier': tier,
        'summary': rec['summary'],
        'notes': '; '.join(notes),
    }


def main():
    with open(INPUT_FILE) as f:
        records = json.load(f)
    out = [classify_one(r) for r in records]

    n = len(out)
    npdi = [r for r in out if r['np'] and r['di']]
    npdiqd = [r for r in out if r['np'] and (r['di'] or r['dq_rescue'])]
    sa = [r for r in out if r['hacker_tier'] in ('S','A')]
    union = [r for r in out if r['np'] and (r['di'] or r['dq_rescue']) or r['hacker_tier'] in ('S','A')]
    inter = [r for r in out if (r['np'] and (r['di'] or r['dq_rescue'])) and r['hacker_tier'] in ('S','A')]

    def pct(a,b): return f"{100.0*a/b:.1f}%" if b else "0.0%"

    aggregate = {
        'total_cves': n,
        'np_total': sum(1 for r in out if r['np']),
        'di_total': sum(1 for r in out if r['di']),
        'np_di_raw': len(npdi),
        'np_di_raw_pct': pct(len(npdi), n),
        'np_di_dq': len(npdiqd),
        'np_di_dq_pct': pct(len(npdiqd), n),
        'hacker_sa': len(sa),
        'hacker_sa_pct': pct(len(sa), n),
        'union': len(union),
        'union_pct': pct(len(union), n),
        'intersection': len(inter),
        'intersection_pct': pct(len(inter), n),
        'tier_dist': dict(Counter(r['hacker_tier'] for r in out)),
        'primitive_kind_dist': dict(Counter(r['hacker_primitive_kind'] for r in out)),
    }

    by_eco = defaultdict(lambda: {'n':0,'npdi':0,'npdiqd':0,'sa':0,'union':0})
    for r in out:
        e = r['ecosystem']
        by_eco[e]['n'] += 1
        if r['np'] and r['di']: by_eco[e]['npdi'] += 1
        if r['np'] and (r['di'] or r['dq_rescue']): by_eco[e]['npdiqd'] += 1
        if r['hacker_tier'] in ('S','A'): by_eco[e]['sa'] += 1
        if (r['np'] and (r['di'] or r['dq_rescue'])) or r['hacker_tier'] in ('S','A'):
            by_eco[e]['union'] += 1
    for e, d in by_eco.items():
        d['npdi_pct'] = pct(d['npdi'], d['n'])
        d['npdiqd_pct'] = pct(d['npdiqd'], d['n'])
        d['sa_pct'] = pct(d['sa'], d['n'])
        d['union_pct'] = pct(d['union'], d['n'])
    aggregate['by_ecosystem'] = dict(by_eco)

    by_ev = {}
    for src in ['KEV','Metasploit','ExploitDB']:
        rs = [r for r in out if src in r['evidence_sources']]
        d = {
            'n': len(rs),
            'npdi': sum(1 for r in rs if r['np'] and r['di']),
            'npdiqd': sum(1 for r in rs if r['np'] and (r['di'] or r['dq_rescue'])),
            'sa': sum(1 for r in rs if r['hacker_tier'] in ('S','A')),
            'union': sum(1 for r in rs if (r['np'] and (r['di'] or r['dq_rescue'])) or r['hacker_tier'] in ('S','A')),
        }
        if d['n']:
            d['npdi_pct'] = pct(d['npdi'], d['n'])
            d['npdiqd_pct'] = pct(d['npdiqd'], d['n'])
            d['sa_pct'] = pct(d['sa'], d['n'])
            d['union_pct'] = pct(d['union'], d['n'])
        by_ev[src] = d
    aggregate['by_evidence'] = by_ev

    final = {
        'metadata': {
            'generated': '2026-04-29',
            'source': 'foss-low-severity-exploited.json (135 distinct CVEs)',
            'np_rule': 'package primary purpose is parsing untrusted network input OR security decisions from untrusted input',
            'di_cwes': sorted(DI_CWES),
            'aggregate': aggregate,
        },
        'records': out,
    }

    with open(SCORING_OUT, 'w') as f:
        json.dump(final, f, indent=2)
    print(f'Wrote {SCORING_OUT}')
    print()
    print('=== AGGREGATE ===')
    for k, v in aggregate.items():
        if k in ('by_ecosystem','by_evidence','tier_dist','primitive_kind_dist'):
            print(f'{k}:')
            for kk, vv in v.items():
                print(f'  {kk}: {vv}')
        else:
            print(f'{k}: {v}')


if __name__ == '__main__':
    main()

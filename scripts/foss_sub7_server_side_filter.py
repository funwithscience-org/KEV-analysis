"""Apply the server-side judgment filter to exploited_unfiltered.json.

Stage 3 of the foss_sub7 pipeline. Reads from data/_foss-sub7-cache/
and writes server_side_filtered.json into the same cache dir.
"""
import json
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
WORK = REPO / "data" / "_foss-sub7-cache"

# --- Package classifications ---
# These run in the user's browser/device — XSS in them is client-side. EXCLUDE.
CLIENT_SIDE_PACKAGES = {
    # Browser DOM / UI libs (any ecosystem)
    "jquery", "org.webjars.npm:jquery", "jquery-rails",
    "components/jquery", "athlon1600/youtube-downloader",  # latter pulls in jquery client
    "jQuery",  # NuGet capitalisation
    # Note: ".jquery"-bearing packages: maximebf/debugbar uses jquery for dev toolbar, that's
    # bundled into a SERVER-rendered page — but the CVE itself is jquery DOM XSS that fires in
    # the developer's browser. Still client-side execution. EXCLUDE.
    "maximebf/debugbar",
    # mobiledetectlib is a server-side detection library though — INCLUDE actually.
    # docsify is a static-site generator that runs IN the browser to fetch markdown — client-side. EXCLUDE.
    "docsify",
    # tileserver-gl is a node server *but* the XSS is delivered to the user's map browser.
    # Looking at the CVE: it's the server's web UI that's XSS. Server-rendered. INCLUDE.
    # Joplin: a desktop note-taking app (Electron). EXCLUDE.
    "joplin",
    # Puppeteer drives Chrome. The CVE is in Chrome/Chromium UAF; running puppeteer doesn't
    # expose a server. The "puppeteer" package is server-side automation but the CVE is
    # the underlying browser. EXCLUDE.
    "puppeteer",
    # CefSharp — embedded Chromium for desktop apps (.NET WPF/WinForms). EXCLUDE.
    "CefSharp.Common", "CefSharp.WinForms", "CefSharp.Wpf", "CefSharp.Wpf.HwndHost",
}

# Per-package server-side rationale (default if not in CLIENT_SIDE_PACKAGES)
SERVER_RATIONALE = {
    # Web servers / app frameworks
    "org.apache.tomcat:jsp-api": "Tomcat servlet/JSP server",
    "org.apache.tomcat:servlet-api": "Tomcat servlet/JSP server",
    "org.apache.tomcat.embed:tomcat-embed-core": "Embedded Tomcat HTTP server",
    "org.apache.tomcat:tomcat-coyote": "Tomcat HTTP connector (Coyote)",
    "org.mortbay.jetty:jetty": "Jetty HTTP server",
    "org.eclipse.jetty:jetty-webapp": "Jetty webapp server",
    "org.eclipse.jetty.http2:http2-common": "Jetty HTTP/2 server",
    "org.eclipse.jetty.http2:http2-server": "Jetty HTTP/2 server",
    "org.eclipse.jetty.http2:jetty-http2-common": "Jetty HTTP/2 server",
    "org.eclipse.jetty.http2:jetty-http2-server": "Jetty HTTP/2 server",
    "com.typesafe.akka:akka-http-core": "Akka HTTP server",
    "com.typesafe.akka:akka-http-core_2.11": "Akka HTTP server",
    "com.typesafe.akka:akka-http-core_2.12": "Akka HTTP server",
    "com.typesafe.akka:akka-http-core_2.13": "Akka HTTP server",
    "vite": "Vite dev server (Node) — runs server-side serving local files",
    # CMS / portal (server-rendered)
    "org.opencms:opencms-core": "OpenCMS Java CMS (server-rendered)",
    "typo3/cms": "TYPO3 CMS (PHP, server-rendered)",
    "phpmyadmin/phpmyadmin": "phpMyAdmin (PHP web admin)",
    "symphonycms/symphony-2": "Symphony PHP CMS",
    "moin": "MoinMoin Python wiki (server-rendered)",
    "mayan-edms": "Mayan EDMS Django document mgmt server",
    "feedparser": "Python RSS/Atom server-side parser",
    "lxml": "Python XML/HTML server-side parser",
    "pip": "Python package manager runs at install on dev/server hosts (server-side ops)",
    "github.com/gogits/gogs": "Gogs self-hosted Git server",
    "gogs.io/gogs": "Gogs self-hosted Git server",
    "nilsteampassnet/teampass": "TeamPass PHP password manager server",
    "cherrymusic": "CherryMusic Python music streaming server",
    "org.apache.openmeetings:openmeetings-install": "Apache OpenMeetings Java server",
    "com.liferay:com.liferay.portal.search.web": "Liferay portal (Java)",
    "com.liferay.portal:portal-service": "Liferay portal (Java)",
    "com.liferay.portal:release.portal.bom": "Liferay portal (Java)",
    "org.wso2.carbon.commons:org.wso2.carbon.logging.view.ui": "WSO2 Carbon admin UI (server)",
    "org.wso2.carbon.commons:org.wso2.carbon.messageflows.ui": "WSO2 Carbon admin UI (server)",
    "org.wso2.carbon.commons:org.wso2.carbon.ndatasource.ui": "WSO2 Carbon admin UI (server)",
    "org.wso2.carbon.identity.framework:org.wso2.carbon.identity.mgt.ui": "WSO2 Carbon admin UI (server)",
    "web2py": "web2py Python web framework",
    "django": "Django Python web framework",
    "october/rain": "OctoberCMS PHP",
    "october/cms": "OctoberCMS PHP",
    "shopware/shopware": "Shopware PHP commerce platform",
    "getkirby/cms": "Kirby PHP CMS",
    "phpmailer/phpmailer": "PHPMailer mail-sending library",
    "mantisbt/mantisbt": "MantisBT bug tracker (PHP)",
    "concrete5/concrete5": "Concrete CMS (PHP)",
    "admidio/admidio": "Admidio member management (PHP)",
    "craftcms/cms": "Craft CMS (PHP)",
    "rainlab/user-plugin": "OctoberCMS user plugin (PHP)",
    "moodle/moodle": "Moodle LMS (PHP)",
    "pagekit/pagekit": "Pagekit CMS (PHP)",
    "pimcore/pimcore": "Pimcore PHP DXP",
    "intelliants/subrion": "Subrion CMS (PHP)",
    "ajenti": "Ajenti server admin panel (Python)",
    "dolibarr/dolibarr": "Dolibarr ERP (PHP)",
    "bolt/bolt": "Bolt CMS (PHP)",
    "rainlab/blog-plugin": "OctoberCMS blog plugin",
    "org.apache.portals.pluto:chatRoomDemo": "Apache Pluto portal Java",
    "org.jenkins-ci.main:jenkins-core": "Jenkins CI server (Java)",
    "org.jenkins-ci.plugins:depgraph-view": "Jenkins plugin (server)",
    "org.jenkins-ci.plugins:build-metrics": "Jenkins plugin (server)",
    "org.jenkins-ci.plugins:sonar": "Jenkins plugin (server)",
    "org.jenkins-ci.ruby-plugins:gitlab-hook": "Jenkins plugin (server)",
    "org.springframework.security.oauth:spring-security-oauth": "Spring Security OAuth (Java)",
    "org.springframework.security.oauth:spring-security-oauth2": "Spring Security OAuth (Java)",
    "DotNetNuke.Core": "DNN .NET CMS server",
    "github.com/grafana/grafana": "Grafana dashboard server (Go)",
    "cosenary/instagram": "PHP server-side Instagram API client",
    "limesurvey/limesurvey": "LimeSurvey PHP server",
    "org.apache.olingo:odata-client-core": "Apache Olingo OData library (used server-side)",
    "org.apache.olingo:odata-server-core": "Apache Olingo OData server",
    "org.springframework.cloud:spring-cloud-config-server": "Spring Cloud Config server (Java)",
    "org.rundeck:rundeck": "Rundeck operations server (Java)",
    "tileserver-gl": "Node tile server",
    "opencart/opencart": "OpenCart PHP commerce",
    "org.keycloak:keycloak-core": "Keycloak IAM server (Java)",
    "salt": "SaltStack Salt master/minion server (Python)",
    "org.bouncycastle:bcprov-jdk15on": "BouncyCastle Java crypto (used server-side for TLS/cert)",
    "org.apache.shindig:shindig-php": "Apache Shindig OpenSocial server",
    "org.apache.spark:spark-core_2.10": "Apache Spark cluster compute (server)",
    "org.apache.spark:spark-core_2.11": "Apache Spark cluster compute (server)",
    "org.apache.syncope:syncope-core": "Apache Syncope identity server (Java)",
    "thorsten/phpmyfaq": "phpMyFAQ PHP server",
    "francoisjacquet/rosariosis": "RosarioSIS PHP school server",
    "github.com/casdoor/casdoor": "Casdoor Go IAM server",
    "wintercms/winter": "Winter CMS (PHP)",
    "apache-superset": "Apache Superset BI server (Python)",
    "copyparty": "Copyparty Python file server",
    "ghost": "Ghost Node CMS server",
    "org.opennms:opennms-webapp-rest": "OpenNMS network management server (Java)",
    "github.com/tiagorlampert/CHAOS": "CHAOS C2 server (Go) — server-side though malicious tool",
    "drupal/core": "Drupal CMS (PHP)",
    "drupal/core-recommended": "Drupal CMS (PHP)",
    "drupal/drupal": "Drupal CMS (PHP)",
    "github.com/kubesphere/kubesphere": "KubeSphere Go server",
    "camaleon_cms": "Camaleon Ruby CMS",
    "silverstripe/framework": "Silverstripe PHP framework",
    "showdoc/showdoc": "ShowDoc PHP documentation server",
    "feehi/cms": "Feehi PHP CMS",
    "label-studio": "Label Studio Python labeling server",
    "yourls/yourls": "YOURLS PHP URL shortener server",
    "products-pluggableauthservice": "Plone PluggableAuth (Python server)",
    "org.elasticsearch.client:elasticsearch-rest-client": "Elasticsearch Java REST client (server-side use)",
    "slo-generator": "Google SLO generator Python tool (server pipeline)",
    "django-unicorn": "django-unicorn server-side Django component framework",
    "pretalx": "pretalx Python conference server",
    "microweber/microweber": "Microweber PHP CMS",
    "org.opennms:opennms-webapp-rest": "OpenNMS network management server (Java)",
    "snipe/snipe-it": "Snipe-IT PHP asset management server",
    "mezzanine": "Mezzanine Django CMS",
    "soosyze/soosyze": "Soosyze PHP CMS",
    "github.com/esm-dev/esm.sh": "esm.sh Go module CDN server",
    "UmbracoCms": "Umbraco .NET CMS (server)",
    "mobiledetect/mobiledetectlib": "Mobile-Detect PHP library (server-side UA detection)",
    "rainlab/user-plugin": "OctoberCMS user plugin (PHP)",
    "rainlab/blog-plugin": "OctoberCMS blog plugin (PHP)",
    "com.shopizer:shopizer": "Shopizer Java commerce server",
    "keystone": "KeystoneJS Node.js CMS server (admin XSS is server-rendered)",
    "org.apache.axis:axis": "Apache Axis SOAP/WSDL server (Java)",
    "golang.org/x/net": "Go x/net HTTP/2 server library (HTTP/2 rapid-reset DoS)",
}

def classify(rec):
    pkgs = rec["packages"]
    # Default: server-side unless ALL packages are client-side
    client_side_pkgs = [p for p in pkgs if p in CLIENT_SIDE_PACKAGES]
    if pkgs and len(client_side_pkgs) == len(pkgs):
        # all packages are client-side
        return False, f"All packages are client-side: {client_side_pkgs}"
    # If a known server-side rationale exists for any pkg, use it.
    rationales = []
    for p in pkgs:
        if p in CLIENT_SIDE_PACKAGES:
            continue
        if p in SERVER_RATIONALE:
            rationales.append(f"{p}: {SERVER_RATIONALE[p]}")
        else:
            rationales.append(f"{p}: <UNREVIEWED>")
    return True, "; ".join(rationales)

# Apply
records = json.load(open(WORK / "exploited_unfiltered.json"))
out = []
excluded = []
unreviewed = []
for r in records:
    is_ss, rationale = classify(r)
    r["server_side"] = is_ss
    r["server_side_rationale"] = rationale
    if "<UNREVIEWED>" in rationale:
        unreviewed.append(r)
    if is_ss:
        out.append(r)
    else:
        excluded.append(r)

print(f"Server-side records: {len(out)} / {len(records)}")
print(f"Excluded (client-side): {len(excluded)}")
print(f"Unreviewed packages: {len(unreviewed)}")
for u in unreviewed:
    print(f"  UNREVIEWED: {u['cve']} | {u['ecosystem']} | {u['packages']}")

# Distinct CVEs in server-side
ss_cves = sorted({r["cve"] for r in out})
print(f"Distinct server-side sub-7 exploited CVEs: {len(ss_cves)}")

# Distinct CVEs excluded
ex_cves = sorted({r["cve"] for r in excluded})
print(f"Distinct excluded CVEs: {len(ex_cves)}")
print("Excluded CVEs:", ex_cves)

(WORK / "server_side_filtered.json").write_text(json.dumps(out, indent=2))
(WORK / "client_side_excluded.json").write_text(json.dumps(excluded, indent=2))

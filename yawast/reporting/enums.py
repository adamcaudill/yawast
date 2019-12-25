#  Copyright (c) 2013 - 2019 Adam Caudill and Contributors.
#  This file is part of YAWAST which is released under the MIT license.
#  See the LICENSE file or go to https://yawast.org/license/ for full license details.

from enum import Enum
from typing import NamedTuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    BEST_PRACTICE = "best_practice"
    INFO = "info"


class VulnerabilityInfo(NamedTuple):
    name: str
    severity: Severity
    description: str
    display_all: bool = False
    id: str = "(Invalid)"  # must be the last item

    @classmethod
    def create(
        cls, name: str, severity: Severity, description: str, display_all: bool = False
    ):
        digest = hashes.Hash(hashes.SHAKE128(5), backend=default_backend())
        digest.update(name.encode("utf_8"))
        d = digest.finalize().hex()
        id_val = f"Y{d}"

        return cls.__new__(cls, name, severity, description, display_all, id_val)


class VulnerabilityInfoEnum(VulnerabilityInfo, Enum):
    pass


class Vulnerabilities(VulnerabilityInfoEnum):
    APP_WORDPRESS_VERSION = VulnerabilityInfo.create(
        "App_WordPress_Version", Severity.LOW, ""
    )
    APP_WORDPRESS_OUTDATED = VulnerabilityInfo.create(
        "App_WordPress_Outdated", Severity.MEDIUM, ""
    )
    APP_WORDPRESS_USER_ENUM_API = VulnerabilityInfo.create(
        "App_WordPress_User_Enum_API", Severity.MEDIUM, ""
    )
    APP_WORDPRESS_USER_FOUND = VulnerabilityInfo.create(
        "App_WordPress_User_Found", Severity.LOW, "", True
    )
    APP_WORDPRESS_PATH_DISCLOSURE = VulnerabilityInfo.create(
        "App_WordPress_Path_Disclosure", Severity.LOW, "", True
    )
    APP_JIRA_FOUND = VulnerabilityInfo.create("App_Jira_Found", Severity.INFO, "")
    APP_JIRA_USER_REG_ENABLED = VulnerabilityInfo.create(
        "App_Jira_User_Reg_Enabled", Severity.LOW, ""
    )
    APP_TELERIK_UI_RAD_ASYNC_UPLOAD_ENABLED = VulnerabilityInfo(
        "App_Telerik_UI_Rad_Async_Upload_Enabled", Severity.LOW, ""
    )

    COOKIE_MISSING_SECURE_FLAG = VulnerabilityInfo.create(
        "Cookie_Missing_Secure_Flag", Severity.MEDIUM, "", True
    )
    COOKIE_MISSING_HTTPONLY_FLAG = VulnerabilityInfo.create(
        "Cookie_Missing_HttpOnly_Flag", Severity.LOW, "", True
    )
    COOKIE_MISSING_SAMESITE_FLAG = VulnerabilityInfo.create(
        "Cookie_Missing_SameSite_Flag", Severity.BEST_PRACTICE, "", True
    )
    COOKIE_WITH_SAMESITE_NONE_FLAG = VulnerabilityInfo.create(
        "Cookie_With_SameSite_None_Flag", Severity.BEST_PRACTICE, "", True
    )
    COOKIE_INVALID_SECURE_FLAG = VulnerabilityInfo.create(
        "Cookie_Invalid_Secure_Flag", Severity.MEDIUM, "", True
    )
    COOKIE_INVALID_SAMESITE_NONE_FLAG = VulnerabilityInfo.create(
        "Cookie_Invalid_SameSite_None_Flag", Severity.LOW, "", True
    )
    COOKIE_BIGIP_IP_DISCLOSURE = VulnerabilityInfo.create(
        "Cookie_BigIP_IP_Disclosure", Severity.LOW, "", True
    )

    DNS_CAA_MISSING = VulnerabilityInfo.create("Dns_CAA_Missing", Severity.LOW, "")
    DNS_DNSSEC_NOT_ENABLED = VulnerabilityInfo.create(
        "Dns_DNSSEC_Not_Enabled", Severity.BEST_PRACTICE, ""
    )

    JS_VULNERABLE_VERSION = VulnerabilityInfo.create(
        "Js_Vulnerable_Version", Severity.MEDIUM, "", True
    )
    JS_EXTERNAL_FILE = VulnerabilityInfo.create(
        "Js_External_File", Severity.LOW, "", True
    )
    JS_EXTERNAL_NO_SRI = VulnerabilityInfo.create(
        "Js_External_No_SRI", Severity.LOW, "", True
    )

    HTTP_BANNER_GENERIC_APACHE = VulnerabilityInfo.create(
        "Http_Banner_Generic_Apache", Severity.INFO, ""
    )
    HTTP_BANNER_APACHE_VERSION = VulnerabilityInfo.create(
        "Http_Banner_Apache_Version", Severity.LOW, ""
    )
    HTTP_BANNER_GENERIC_NGINX = VulnerabilityInfo.create(
        "Http_Banner_Generic_Nginx", Severity.INFO, ""
    )
    HTTP_BANNER_NGINX_VERSION = VulnerabilityInfo.create(
        "Http_Banner_Nginx_Version", Severity.LOW, ""
    )
    HTTP_BANNER_PYTHON_VERSION = VulnerabilityInfo.create(
        "Http_Banner_Python_Version", Severity.LOW, ""
    )
    HTTP_BANNER_IIS_VERSION = VulnerabilityInfo.create(
        "Http_Banner_IIS_Version", Severity.LOW, ""
    )
    HTTP_BANNER_OPENSSL_VERSION = VulnerabilityInfo.create(
        "Http_Banner_OpenSSL_Version", Severity.LOW, ""
    )
    HTTP_PHP_VERSION_EXPOSED = VulnerabilityInfo.create(
        "Http_PHP_Version_Exposed", Severity.LOW, ""
    )

    HTTP_HEADER_CONTENT_SECURITY_POLICY_MISSING = VulnerabilityInfo.create(
        "Http_Header_Content_Security_Policy_Missing", Severity.LOW, ""
    )
    HTTP_HEADER_CORS_ACAO_UNRESTRICTED = VulnerabilityInfo.create(
        "Http_Header_CORS_ACAO_Unrestricted", Severity.LOW, ""
    )
    HTTP_HEADER_FEATURE_POLICY_MISSING = VulnerabilityInfo.create(
        "Http_Header_Feature_Policy_Missing", Severity.BEST_PRACTICE, ""
    )
    HTTP_HEADER_HSTS_MISSING = VulnerabilityInfo.create(
        "Http_Hsts_Missing", Severity.MEDIUM, ""
    )
    HTTP_HEADER_REFERRER_POLICY_MISSING = VulnerabilityInfo.create(
        "Http_Header_Referrer_Policy_Missing", Severity.BEST_PRACTICE, ""
    )
    HTTP_HEADER_VIA = VulnerabilityInfo.create(
        "Http_Header_Via", Severity.BEST_PRACTICE, ""
    )
    HTTP_HEADER_X_BACKEND_SERVER = VulnerabilityInfo.create(
        "Http_Header_X_Backend_Server", Severity.BEST_PRACTICE, ""
    )
    HTTP_HEADER_X_CONTENT_TYPE_OPTIONS_MISSING = VulnerabilityInfo.create(
        "Http_Header_X_Content_Type_Options_Missing", Severity.LOW, ""
    )
    HTTP_HEADER_X_FRAME_OPTIONS_ALLOW = VulnerabilityInfo.create(
        "Http_Header_X_Frame_Options_Allow", Severity.LOW, ""
    )
    HTTP_HEADER_X_FRAME_OPTIONS_MISSING = VulnerabilityInfo.create(
        "Http_Header_X_Frame_Options_Missing", Severity.LOW, ""
    )
    HTTP_HEADER_X_POWERED_BY = VulnerabilityInfo.create(
        "Http_Header_X_Powered_By", Severity.BEST_PRACTICE, ""
    )
    HTTP_HEADER_X_RUNTIME = VulnerabilityInfo.create(
        "Http_Header_X_Runtime", Severity.BEST_PRACTICE, ""
    )
    HTTP_HEADER_X_XSS_PROTECTION_DISABLED = VulnerabilityInfo.create(
        "Http_Header_X_Xss_Protection_Disabled", Severity.LOW, ""
    )
    HTTP_HEADER_X_XSS_PROTECTION_MISSING = VulnerabilityInfo.create(
        "Http_Header_X_Xss_Protection_Missing", Severity.LOW, ""
    )
    HTTP_HEADER_X_ASPNETMVC_VERSION = VulnerabilityInfo.create(
        "Http_X_AspNetMvc_Version", Severity.LOW, ""
    )
    HTTP_HEADER_X_ASPNET_VERSION = VulnerabilityInfo.create(
        "Http_X_AspNet_Version", Severity.LOW, ""
    )
    HTTP_HEADER_CONTENT_TYPE_NO_CHARSET = VulnerabilityInfo.create(
        "Http_Header_Content_Type_No_Charset", Severity.LOW, ""
    )
    HTTP_HEADER_CONTENT_TYPE_MISSING = VulnerabilityInfo.create(
        "Http_Header_Content_Type_Missing", Severity.LOW, ""
    )
    HTTP_HEADER_CACHE_CONTROL_MISSING = VulnerabilityInfo.create(
        "Http_Header_Cache_Control_Missing", Severity.LOW, ""
    )
    HTTP_HEADER_CACHE_CONTROL_NO_CACHE_MISSING = VulnerabilityInfo.create(
        "Http_Header_Cache_Control_No_Cache_Missing", Severity.LOW, ""
    )
    HTTP_HEADER_CACHE_CONTROL_NO_STORE_MISSING = VulnerabilityInfo.create(
        "Http_Header_Cache_Control_No_Store_Missing", Severity.LOW, ""
    )
    HTTP_HEADER_CACHE_CONTROL_PRIVATE_MISSING = VulnerabilityInfo.create(
        "Http_Header_Cache_Control_Private_Missing", Severity.LOW, ""
    )
    HTTP_HEADER_CACHE_CONTROL_PUBLIC = VulnerabilityInfo.create(
        "Http_Header_Cache_Control_Public", Severity.LOW, ""
    )
    HTTP_HEADER_EXPIRES_MISSING = VulnerabilityInfo.create(
        "Http_Header_Expires_Missing", Severity.LOW, ""
    )
    HTTP_HEADER_EXPIRES_FUTURE = VulnerabilityInfo.create(
        "Http_Header_Expires_Future", Severity.LOW, ""
    )
    HTTP_HEADER_PRAGMA_NO_CACHE_MISSING = VulnerabilityInfo.create(
        "Http_Header_Pragma_No_Cache_Missing", Severity.LOW, ""
    )
    HTTP_HEADER_DUPLICATE = VulnerabilityInfo.create(
        "Http_Header_Duplicate", Severity.LOW, ""
    )

    HTTP_ERROR_MESSAGE = VulnerabilityInfo.create(
        "Http_Error_Message", Severity.MEDIUM, "", True
    )
    HTTP_INSECURE_LINK = VulnerabilityInfo.create(
        "Http_Insecure_Link", Severity.LOW, "", True
    )
    HTTP_PROPFIND_ENABLED = VulnerabilityInfo.create(
        "Http_Propfind_Enabled", Severity.LOW, ""
    )
    HTTP_TRACE_ENABLED = VulnerabilityInfo.create(
        "Http_Trace_Enabled", Severity.LOW, ""
    )
    HTTP_OPTIONS_ALLOW = VulnerabilityInfo.create(
        "Http_Option_Allow", Severity.INFO, ""
    )
    HTTP_OPTIONS_PUBLIC = VulnerabilityInfo.create(
        "Http_Option_Public", Severity.INFO, ""
    )
    HTTP_USER_ENUMERATION = VulnerabilityInfo.create(
        "Http_User_Enum_Responses", Severity.MEDIUM, ""
    )
    HTTP_USER_ENUMERATION_TIMING = VulnerabilityInfo.create(
        "Http_User_Enum_Timing", Severity.MEDIUM, ""
    )
    HTTP_BACKUP_FILE = VulnerabilityInfo.create(
        "Http_Backup_File", Severity.BEST_PRACTICE, "", True
    )
    HTTP_DS_STORE_FILE = VulnerabilityInfo.create(
        "Http_DS_Store_File", Severity.INFO, "", True
    )

    TLS_CBC_CIPHER_SUITE = VulnerabilityInfo.create(
        "Tls_CBC_Cipher_Suite", Severity.BEST_PRACTICE, ""
    )

    TLS_CERT_BAD_COMMON_NAME = VulnerabilityInfo.create(
        "Tls_Cert_Bad_Common_Name", Severity.HIGH, ""
    )
    TLS_CERT_BLACKLISTED = VulnerabilityInfo.create(
        "Tls_Cert_Blacklisted", Severity.HIGH, ""
    )
    TLS_CERT_EXPIRED = VulnerabilityInfo.create("Tls_Cert_Expired", Severity.HIGH, "")
    TLS_CERT_HOSTNAME_MISMATCH = VulnerabilityInfo.create(
        "Tls_Cert_Hostname_Mismatch", Severity.HIGH, ""
    )
    TLS_CERT_INSECURE_KEY = VulnerabilityInfo.create(
        "Tls_Cert_Insecure_Key", Severity.HIGH, ""
    )
    TLS_CERT_INSECURE_SIGNATURE = VulnerabilityInfo.create(
        "Tls_Cert_Insecure_Signature", Severity.HIGH, ""
    )
    TLS_CERT_NOT_YET_VALID = VulnerabilityInfo.create(
        "Tls_Cert_Not_Yet_Valid", Severity.HIGH, ""
    )
    TLS_CERT_NO_TRUST = VulnerabilityInfo.create("Tls_Cert_No_Trust", Severity.HIGH, "")
    TLS_CERT_REVOKED = VulnerabilityInfo.create("Tls_Cert_Revoked", Severity.HIGH, "")
    TLS_CERT_SELF_SIGNED = VulnerabilityInfo.create(
        "Tls_Cert_Self_Signed", Severity.HIGH, ""
    )

    TLS_COMPRESSION_ENABLED = VulnerabilityInfo.create(
        "Tls_Compression_Enabled", Severity.HIGH, "", True
    )
    TLS_DH_KNOWN_PRIMES_STRONG = VulnerabilityInfo.create(
        "Tls_DH_Known_Primes_Strong", Severity.MEDIUM, "", True
    )
    TLS_DH_KNOWN_PRIMES_WEAK = VulnerabilityInfo.create(
        "Tls_DH_Known_Primes_Weak", Severity.HIGH, "", True
    )
    TLS_DH_PARAM_REUSE = VulnerabilityInfo.create(
        "Tls_DH_Param_Reuse", Severity.LOW, "", True
    )
    TLS_DROWN = VulnerabilityInfo.create("Tls_Drown", Severity.MEDIUM, "", True)
    TLS_ECDH_PARAM_REUSE = VulnerabilityInfo.create(
        "Tls_ECDH_Param_Reuse", Severity.LOW, "", True
    )
    TLS_FALLBACK_SCSV_MISSING = VulnerabilityInfo.create(
        "Tls_Fallback_SCSV_Missing", Severity.LOW, "", True
    )
    TLS_FREAK = VulnerabilityInfo.create("Tls_Freak", Severity.HIGH, "", True)
    TLS_GOLDENDOODLE = VulnerabilityInfo.create(
        "Tls_Goldendoodle", Severity.HIGH, "", True
    )
    TLS_GOLDENDOODLE_NE = VulnerabilityInfo.create(
        "Tls_Goldendoodle_NE", Severity.MEDIUM, "", True
    )
    TLS_HEARTBEAT_ENABLED = VulnerabilityInfo.create(
        "Tls_Heartbeat_Enabled", Severity.BEST_PRACTICE, "", True
    )
    TLS_HEARTBLEED = VulnerabilityInfo.create(
        "Tls_Heartbleed", Severity.CRITICAL, "", True
    )
    TLS_INSECURE_CIPHER_SUITE = VulnerabilityInfo(
        "Tls_Insecure_Cipher_Suite", Severity.MEDIUM, "", True
    )
    TLS_INSECURE_RENEG = VulnerabilityInfo.create(
        "Tls_Insecure_Reneg", Severity.HIGH, "", True
    )
    TLS_LEGACY_SSL_ENABLED = VulnerabilityInfo.create(
        "Tls_Legacy_SSL_Enabled", Severity.HIGH, "", True
    )
    TLS_LEGACY_SSL_POODLE = VulnerabilityInfo.create(
        "Tls_Legacy_SSL_Poodle", Severity.HIGH, "", True
    )
    TLS_LIMITED_FORWARD_SECRECY = VulnerabilityInfo.create(
        "Tls_Limited_Forward_Secrecy", Severity.LOW, "", True
    )
    TLS_LOGJAM = VulnerabilityInfo.create("Tls_Logjam", Severity.HIGH, "", True)
    TLS_NO_AEAD_SUPPORT = VulnerabilityInfo.create(
        "Tls_No_AEAD_Support", Severity.BEST_PRACTICE, "", True
    )
    TLS_OCSP_STAPLE_MISSING = VulnerabilityInfo.create(
        "Tls_OCSP_Staple_Missing", Severity.LOW, "", True
    )

    TLS_OPENSSL_CVE_2014_0224 = VulnerabilityInfo.create(
        "Tls_OpenSSL_CVE_2014_0224", Severity.HIGH, "", True
    )
    TLS_OPENSSL_CVE_2014_0224_NE = VulnerabilityInfo.create(
        "Tls_OpenSSL_CVE_2014_0224_NE", Severity.MEDIUM, "", True
    )
    TLS_OPENSSL_CVE_2016_2107 = VulnerabilityInfo.create(
        "Tls_OpenSSL_CVE_2016_2107", Severity.HIGH, "", True
    )
    TLS_OPENSSL_CVE_2019_1559 = VulnerabilityInfo.create(
        "Tls_OpenSSL_CVE_2019_1559", Severity.HIGH, "", True
    )
    TLS_OPENSSL_CVE_2019_1559_NE = VulnerabilityInfo.create(
        "Tls_OpenSSL_CVE_2019_1559_NE", Severity.MEDIUM, "", True
    )

    TLS_POODLE = VulnerabilityInfo.create("Tls_Poodle", Severity.HIGH, "", True)
    TLS_ROBOT_ORACLE_STRONG = VulnerabilityInfo.create(
        "Tls_Robot_Oracle_Strong", Severity.MEDIUM, "", True
    )
    TLS_ROBOT_ORACLE_WEAK = VulnerabilityInfo.create(
        "Tls_Robot_Oracle_Weak", Severity.LOW, "", True
    )
    TLS_SESSION_RESP_ENABLED = VulnerabilityInfo.create(
        "Tls_Session_Resp_Enabled", Severity.BEST_PRACTICE, "", True
    )
    TLS_SLEEPING_POODLE = VulnerabilityInfo.create(
        "Tls_Sleeping_Poodle", Severity.HIGH, "", True
    )
    TLS_SLEEPING_POODLE_NE = VulnerabilityInfo.create(
        "Tls_Sleeping_Poodle_NE", Severity.MEDIUM, "", True
    )
    TLS_SWEET32 = VulnerabilityInfo.create("Tls_SWEET32", Severity.HIGH, "", True)
    TLS_SYMANTEC_ROOT = VulnerabilityInfo.create(
        "Tls_Symantec_Root", Severity.HIGH, "", True
    )
    TLS_TICKETBLEED = VulnerabilityInfo.create(
        "Tls_Ticketbleed", Severity.HIGH, "", True
    )

    TLS_VERSION_1_0_ENABLED = VulnerabilityInfo.create(
        "Tls_Version_1_0_Enabled", Severity.LOW, "", True
    )
    TLS_VERSION_1_3_EARLY_DATA_ENABLED = VulnerabilityInfo.create(
        "Tls_Version_1_3_Early_Data_Enabled", Severity.BEST_PRACTICE, "", True
    )
    TLS_VERSION_1_3_NOT_ENABLED = VulnerabilityInfo.create(
        "Tls_Version_1_3_Not_Enabled", Severity.BEST_PRACTICE, "", True
    )

    TLS_ZOMBIE_POODLE = VulnerabilityInfo.create(
        "Tls_Zombie_Poodle", Severity.HIGH, "", True
    )
    TLS_ZOMBIE_POODLE_NE = VulnerabilityInfo.create(
        "Tls_Zombie_Poodle_NE", Severity.MEDIUM, "", True
    )

    SERVER_APACHE_OUTDATED = VulnerabilityInfo.create(
        "Server_Apache_Outdated", Severity.MEDIUM, ""
    )
    SERVER_APACHE_STATUS = VulnerabilityInfo.create(
        "Server_Apache_Status", Severity.MEDIUM, ""
    )
    SERVER_APACHE_INFO = VulnerabilityInfo.create(
        "Server_Apache_Info", Severity.MEDIUM, ""
    )
    SERVER_TOMCAT_VERSION = VulnerabilityInfo.create(
        "Server_Tomcat_Version", Severity.MEDIUM, ""
    )
    SERVER_TOMCAT_OUTDATED = VulnerabilityInfo.create(
        "Server_Tomcat_Outdated", Severity.MEDIUM, ""
    )
    SERVER_TOMCAT_MANAGER_EXPOSED = VulnerabilityInfo.create(
        "Server_Tomcat_Manager_Exposed", Severity.HIGH, ""
    )
    SERVER_TOMCAT_HOST_MANAGER_EXPOSED = VulnerabilityInfo.create(
        "Server_Tomcat_Host_Manager_Exposed", Severity.HIGH, ""
    )
    SERVER_TOMCAT_MANAGER_WEAK_PASSWORD = VulnerabilityInfo.create(
        "Server_Tomcat_Manager_Weak_Password", Severity.CRITICAL, "", True
    )
    SERVER_TOMCAT_CVE_2017_12615 = VulnerabilityInfo.create(
        "Server_Tomcat_CVE_2017_12615", Severity.CRITICAL, ""
    )
    SERVER_TOMCAT_CVE_2019_0232 = VulnerabilityInfo.create(
        "Server_Tomcat_CVE_2019_0232", Severity.CRITICAL, ""
    )
    SERVER_TOMCAT_STRUTS_SAMPLE = VulnerabilityInfo.create(
        "Server_Tomcat_Struts_Sample", Severity.LOW, "", True
    )
    SERVER_NGINX_OUTDATED = VulnerabilityInfo.create(
        "Server_Nginx_Outdated", Severity.MEDIUM, ""
    )
    SERVER_NGINX_STATUS_EXPOSED = VulnerabilityInfo.create(
        "Server_Nginx_Status_Exposed", Severity.LOW, ""
    )
    SERVER_PHP_OUTDATED = VulnerabilityInfo.create(
        "Server_PHP_Outdated", Severity.MEDIUM, ""
    )
    SERVER_PHP_PHPINFO = VulnerabilityInfo.create(
        "Server_PHP_PHPInfo", Severity.LOW, ""
    )
    SERVER_PHP_CVE_2019_11043 = VulnerabilityInfo.create(
        "Server_PHP_CVE_2019_11043", Severity.CRITICAL, ""
    )
    SERVER_IIS_OUTDATED = VulnerabilityInfo.create(
        "Server_IIS_Outdated", Severity.MEDIUM, ""
    )
    SERVER_ASPNETMVC_OUTDATED = VulnerabilityInfo.create(
        "Server_AspNetMvc_Outdated", Severity.MEDIUM, ""
    )
    SERVER_ASPNET_OUTDATED = VulnerabilityInfo.create(
        "Server_AspNet_Outdated", Severity.MEDIUM, ""
    )
    SERVER_ASPNET_DEBUG_ENABLED = VulnerabilityInfo.create(
        "Server_AspNet_Debug_Enabled", Severity.HIGH, ""
    )
    SERVER_ASPNET_HANDLER_ENUM = VulnerabilityInfo.create(
        "Server_AspNet_Handler_Enum", Severity.LOW, "", True
    )
    SERVER_RAILS_CVE_2019_5418 = VulnerabilityInfo.create(
        "Server_Rails_CVE_2019_5418", Severity.CRITICAL, ""
    )
    SERVER_INVALID_404_FILE = VulnerabilityInfo.create(
        "Server_Invalid_404_File", Severity.INFO, ""
    )
    SERVER_INVALID_404_PATH = VulnerabilityInfo.create(
        "Server_Invalid_404_Path", Severity.INFO, ""
    )
    SERVER_SPECIAL_FILE_EXPOSED = VulnerabilityInfo.create(
        "Server_Special_File_Exposed", Severity.INFO, "", True
    )
    SERVER_INT_IP_EXP_HTTP10 = VulnerabilityInfo.create(
        "Server_Int_IP_Exp_Http10", Severity.LOW, ""
    )

    NETWORK_OPEN_PORT = VulnerabilityInfo.create(
        "Network_Open_Port", Severity.INFO, "", True
    )

    WAF_CLOUDFLARE = VulnerabilityInfo.create("Waf_Cloudflare", Severity.INFO, "")
    WAF_INCAPSULA = VulnerabilityInfo.create("Waf_Incapsula", Severity.INFO, "")

#!/usr/bin/env python3
"""
Generated CyberBattleSim scenario from Kubernetes cluster
Generated at: 2025-10-07T13:39:10.629710
Total nodes: 8
Total vulnerabilities: 48
"""

from cyberbattle.simulation import model as m
from cyberbattle.simulation.model import NodeID, NodeInfo, VulnerabilityID
from cyberbattle.simulation.vulenrabilites import VulnerabilityInfo, VulnerabilityType
from cyberbattle.simulation.vulenrabilites import LeakedCredentials, CachedCredential
from cyberbattle.simulation.vulenrabilites import LeakedNodesId, PrivilegeEscalation
from typing import Dict, Iterator, cast, Tuple


class K8sScenario_20251007_133910:
    """Auto-generated K8s environment for DRL research."""

    def create(self) -> m.Environment:
        """Create the environment."""
        
        # Define vulnerability library
        vulnerability_library = {
            "CVE-2011-3374": VulnerabilityInfo(
                description="""It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyring, leading to a potential man-in-the-middle attack.""",
                type=VulnerabilityType.LOCAL,
                outcome=LeakedNodesId(["discovered_node_0"]),
                reward_string="Exploited CVE-2011-3374",
                cost=3.0
            ),
            "TEMP-0841856-B18BAF": VulnerabilityInfo(
                description="""[Privilege escalation possible to other user than root]""",
                type=VulnerabilityType.REMOTE,
                outcome=LeakedCredentials([]),
                reward_string="Exploited TEMP-0841856-B18BAF",
                cost=10.0
            ),
            "CVE-2022-0563": VulnerabilityInfo(
                description="""A flaw was found in the util-linux chfn and chsh utilities when compiled with Readline support. The Readline library uses an "INPUTRC" environment variable to get a path to the library config file. Wh""",
                type=VulnerabilityType.LOCAL,
                outcome=LeakedCredentials([]),
                reward_string="Exploited CVE-2022-0563",
                cost=1.8
            ),
            "CVE-2016-2781": VulnerabilityInfo(
                description="""chroot in GNU coreutils, when used with --userspec, allows local users to escape to the parent session via a crafted TIOCSTI ioctl call, which pushes characters to the terminal's input buffer.""",
                type=VulnerabilityType.LOCAL,
                outcome=PrivilegeEscalation(),
                reward_string="Exploited CVE-2016-2781",
                cost=1.5
            ),
            "CVE-2017-18018": VulnerabilityInfo(
                description="""In GNU Coreutils through 8.29, chown-core.c in chown and chgrp does not prevent replacement of a plain file with a symlink during use of the POSIX "-R -L" options, which allows local users to modify t""",
                type=VulnerabilityType.LOCAL,
                outcome=LeakedCredentials([]),
                reward_string="Exploited CVE-2017-18018",
                cost=2.3
            ),
            "CVE-2025-5278": VulnerabilityInfo(
                description="""A flaw was found in GNU Coreutils. The sort utility's begfield() function is vulnerable to a heap buffer under-read. The program may access memory outside the allocated buffer if a user runs a crafted""",
                type=VulnerabilityType.REMOTE,
                outcome=LeakedCredentials([]),
                reward_string="Exploited CVE-2025-5278",
                cost=10.0
            ),
            "CVE-2025-6297": VulnerabilityInfo(
                description="""It was discovered that dpkg-deb does not properly sanitize directory permissions when extracting a control member into a temporary directory, which is
documented as being a safe operation even on untr""",
                type=VulnerabilityType.REMOTE,
                outcome=LeakedCredentials([]),
                reward_string="Exploited CVE-2025-6297",
                cost=10.0
            ),
            "CVE-2022-27943": VulnerabilityInfo(
                description="""libiberty/rust-demangle.c in GNU GCC 11.2 allows stack consumption in demangle_const, as demonstrated by nm-new.""",
                type=VulnerabilityType.LOCAL,
                outcome=LeakedCredentials([]),
                reward_string="Exploited CVE-2022-27943",
                cost=1.8
            ),
            "CVE-2022-3219": VulnerabilityInfo(
                description="""GnuPG can be made to spin on a relatively small input by (for example) crafting a public key with thousands of signatures attached, compressed down to just a few KB.""",
                type=VulnerabilityType.LOCAL,
                outcome=LeakedCredentials([]),
                reward_string="Exploited CVE-2022-3219",
                cost=2.8
            ),
            "CVE-2025-30258": VulnerabilityInfo(
                description="""In GnuPG before 2.5.5, if a user chooses to import a certificate with certain crafted subkey data that lacks a valid backsig or that has incorrect usage flags, the user loses the ability to verify sig""",
                type=VulnerabilityType.REMOTE,
                outcome=LeakedCredentials([]),
                reward_string="Exploited CVE-2025-30258",
                cost=10.0
            ),
            "CVE-2025-4802": VulnerabilityInfo(
                description="""Untrusted LD_LIBRARY_PATH environment variable vulnerability in the GNU C Library version 2.27 to 2.38 allows attacker controlled loading of dynamically shared library in statically compiled setuid bi""",
                type=VulnerabilityType.REMOTE,
                outcome=LeakedCredentials([]),
                reward_string="Exploited CVE-2025-4802",
                cost=10.0
            ),
            "CVE-2025-8058": VulnerabilityInfo(
                description="""The regcomp function in the GNU C library version from 2.4 to 2.41 is 
subject to a double free if some previous allocation fails. It can be 
accomplished either by a malloc failure or by using an int""",
                type=VulnerabilityType.REMOTE,
                outcome=LeakedNodesId(["discovered_node_0", "discovered_node_1", "discovered_node_2"]),
                reward_string="Exploited CVE-2025-8058",
                cost=10.0
            ),
            "CVE-2010-4756": VulnerabilityInfo(
                description="""The glob implementation in the GNU C Library (aka glibc or libc6) allows remote authenticated users to cause a denial of service (CPU and memory consumption) via crafted glob expressions that do not m""",
                type=VulnerabilityType.LOCAL,
                outcome=LeakedCredentials([]),
                reward_string="Exploited CVE-2010-4756",
                cost=1.9
            ),
            "CVE-2018-20796": VulnerabilityInfo(
                description="""In the GNU C Library (aka glibc or libc6) through 2.29, check_dst_limits_calc_pos_1 in posix/regexec.c has Uncontrolled Recursion, as demonstrated by '(\227|)(\\1\\1|t1|\\\2537)+' in grep.""",
                type=VulnerabilityType.LOCAL,
                outcome=LeakedCredentials([]),
                reward_string="Exploited CVE-2018-20796",
                cost=1.4
            ),
            "CVE-2019-1010022": VulnerabilityInfo(
                description="""GNU Libc current is affected by: Mitigation bypass. The impact is: Attacker may bypass stack guard protection. The component is: nptl. The attack vector is: Exploit stack buffer overflow vulnerability""",
                type=VulnerabilityType.LOCAL,
                outcome=LeakedCredentials([]),
                reward_string="Exploited CVE-2019-1010022",
                cost=1.1
            ),
            "CVE-2019-1010023": VulnerabilityInfo(
                description="""GNU Libc current is affected by: Re-mapping current loaded library with malicious ELF file. The impact is: In worst case attacker may evaluate privileges. The component is: libld. The attack vector is""",
                type=VulnerabilityType.LOCAL,
                outcome=LeakedCredentials([]),
                reward_string="Exploited CVE-2019-1010023",
                cost=1.2
            ),
            "CVE-2019-1010024": VulnerabilityInfo(
                description="""GNU Libc current is affected by: Mitigation bypass. The impact is: Attacker may bypass ASLR using cache of thread stack and heap. The component is: glibc. NOTE: Upstream comments indicate "this is bei""",
                type=VulnerabilityType.LOCAL,
                outcome=LeakedNodesId(["discovered_node_0"]),
                reward_string="Exploited CVE-2019-1010024",
                cost=2.1
            ),
            "CVE-2019-1010025": VulnerabilityInfo(
                description="""GNU Libc current is affected by: Mitigation bypass. The impact is: Attacker may guess the heap addresses of pthread_created thread. The component is: glibc. NOTE: the vendor's position is "ASLR bypass""",
                type=VulnerabilityType.LOCAL,
                outcome=LeakedCredentials([]),
                reward_string="Exploited CVE-2019-1010025",
                cost=2.3
            ),
            "CVE-2019-9192": VulnerabilityInfo(
                description="""In the GNU C Library (aka glibc or libc6) through 2.29, check_dst_limits_calc_pos_1 in posix/regexec.c has Uncontrolled Recursion, as demonstrated by '(|)(\\1\\1)*' in grep, a different issue than CVE""",
                type=VulnerabilityType.LOCAL,
                outcome=LeakedCredentials([]),
                reward_string="Exploited CVE-2019-9192",
                cost=1.3
            ),
            "CVE-2018-6829": VulnerabilityInfo(
                description="""cipher/elgamal.c in Libgcrypt through 1.8.2, when used to encrypt messages directly, improperly encodes plaintexts, which allows attackers to obtain sensitive information by reading ciphertext data (i""",
                type=VulnerabilityType.LOCAL,
                outcome=LeakedNodesId(["discovered_node_0"]),
                reward_string="Exploited CVE-2018-6829",
                cost=1.3
            ),
            "CVE-2024-2236": VulnerabilityInfo(
                description="""A timing-based side-channel flaw was found in libgcrypt's RSA implementation. This issue may allow a remote attacker to initiate a Bleichenbacher-style attack, which can lead to the decryption of RSA """,
                type=VulnerabilityType.REMOTE,
                outcome=LeakedCredentials([]),
                reward_string="Exploited CVE-2024-2236",
                cost=10.0
            ),
            "CVE-2011-3389": VulnerabilityInfo(
                description="""The SSL protocol, as used in certain configurations in Microsoft Windows and Microsoft Internet Explorer, Mozilla Firefox, Google Chrome, Opera, and other products, encrypts data by using CBC mode wit""",
                type=VulnerabilityType.LOCAL,
                outcome=LeakedCredentials([]),
                reward_string="Exploited CVE-2011-3389",
                cost=1.8
            ),
            "CVE-2023-50495": VulnerabilityInfo(
                description="""NCurse v6.4-20230418 was discovered to contain a segmentation fault via the component _nc_wrap_entry().""",
                type=VulnerabilityType.LOCAL,
                outcome=LeakedNodesId(["discovered_node_0", "discovered_node_1", "discovered_node_2"]),
                reward_string="Exploited CVE-2023-50495",
                cost=1.6
            ),
            "CVE-2025-6141": VulnerabilityInfo(
                description="""A vulnerability has been found in GNU ncurses up to 6.5-20250322 and classified as problematic. This vulnerability affects the function postprocess_termcap of the file tinfo/parse_entry.c. The manipul""",
                type=VulnerabilityType.REMOTE,
                outcome=LeakedCredentials([]),
                reward_string="Exploited CVE-2025-6141",
                cost=10.0
            ),
            "CVE-2025-6020": VulnerabilityInfo(
                description="""A flaw was found in linux-pam. The module pam_namespace may use access user-controlled paths without proper protection, allowing local users to elevate their privileges to root via multiple symlink at""",
                type=VulnerabilityType.REMOTE,
                outcome=LeakedCredentials([]),
                reward_string="Exploited CVE-2025-6020",
                cost=10.0
            ),
            "CVE-2024-10041": VulnerabilityInfo(
                description="""A vulnerability was found in PAM. The secret information is stored in memory, where the attacker can trigger the victim program to execute by sending characters to its standard input (stdin). As this """,
                type=VulnerabilityType.REMOTE,
                outcome=LeakedNodesId(["discovered_node_0"]),
                reward_string="Exploited CVE-2024-10041",
                cost=10.0
            ),
            "CVE-2024-22365": VulnerabilityInfo(
                description="""linux-pam (aka Linux PAM) before 1.6.0 allows attackers to cause a denial of service (blocked login process) via mkfifo because the openat call (for protect_dir) lacks O_DIRECTORY.""",
                type=VulnerabilityType.LOCAL,
                outcome=LeakedNodesId(["discovered_node_0", "discovered_node_1"]),
                reward_string="Exploited CVE-2024-22365",
                cost=1.6
            ),
            "CVE-2023-31484": VulnerabilityInfo(
                description="""CPAN.pm before 2.35 does not verify TLS certificates when downloading distributions over HTTPS.""",
                type=VulnerabilityType.LOCAL,
                outcome=LeakedCredentials([]),
                reward_string="Exploited CVE-2023-31484",
                cost=1.3
            ),
            "CVE-2025-40909": VulnerabilityInfo(
                description="""Perl threads have a working directory race condition where file operations may target unintended paths.

If a directory handle is open at thread creation, the process-wide current working directory is""",
                type=VulnerabilityType.REMOTE,
                outcome=LeakedNodesId(["discovered_node_0", "discovered_node_1", "discovered_node_2"]),
                reward_string="Exploited CVE-2025-40909",
                cost=10.0
            ),
            "CVE-2011-4116": VulnerabilityInfo(
                description="""_is_safe in the File::Temp module for Perl does not properly handle symlinks.""",
                type=VulnerabilityType.LOCAL,
                outcome=LeakedCredentials([]),
                reward_string="Exploited CVE-2011-4116",
                cost=2.7
            ),
            "CVE-2023-31486": VulnerabilityInfo(
                description="""HTTP::Tiny before 0.083, a Perl core module since 5.13.9 and available standalone on CPAN, has an insecure default TLS configuration where users must opt in to verify certificates.""",
                type=VulnerabilityType.LOCAL,
                outcome=LeakedCredentials([]),
                reward_string="Exploited CVE-2023-31486",
                cost=1.4
            ),
            "CVE-2023-4016": VulnerabilityInfo(
                description="""Under some circumstances, this weakness allows a user who has access to run the “ps” utility on a machine, the ability to write almost unlimited amounts of unfiltered data into the process heap.""",
                type=VulnerabilityType.LOCAL,
                outcome=LeakedCredentials([]),
                reward_string="Exploited CVE-2023-4016",
                cost=2.7
            ),
            "CVE-2025-27587": VulnerabilityInfo(
                description="""OpenSSL 3.0.0 through 3.3.2 on the PowerPC architecture is vulnerable to a Minerva attack, exploitable by measuring the time of signing of random messages using the EVP_DigestSign API, and then using """,
                type=VulnerabilityType.REMOTE,
                outcome=LeakedCredentials([]),
                reward_string="Exploited CVE-2025-27587",
                cost=10.0
            ),
            "CVE-2013-4392": VulnerabilityInfo(
                description="""systemd, when updating file permissions, allows local users to change the permissions and SELinux security contexts for arbitrary files via a symlink attack on unspecified files.""",
                type=VulnerabilityType.LOCAL,
                outcome=LeakedCredentials([]),
                reward_string="Exploited CVE-2013-4392",
                cost=2.7
            ),
            "CVE-2023-31437": VulnerabilityInfo(
                description="""An issue was discovered in systemd 253. An attacker can modify a sealed log file such that, in some views, not all existing and sealed log messages are displayed. NOTE: the vendor reportedly sent "a r""",
                type=VulnerabilityType.LOCAL,
                outcome=LeakedCredentials([]),
                reward_string="Exploited CVE-2023-31437",
                cost=1.8
            ),
            "CVE-2023-31438": VulnerabilityInfo(
                description="""An issue was discovered in systemd 253. An attacker can truncate a sealed log file and then resume log sealing such that checking the integrity shows no error, despite modifications. NOTE: the vendor """,
                type=VulnerabilityType.LOCAL,
                outcome=LeakedCredentials([]),
                reward_string="Exploited CVE-2023-31438",
                cost=1.9
            ),
            "CVE-2023-31439": VulnerabilityInfo(
                description="""An issue was discovered in systemd 253. An attacker can modify the contents of past events in a sealed log file and then adjust the file such that checking the integrity shows no error, despite modifi""",
                type=VulnerabilityType.LOCAL,
                outcome=LeakedCredentials([]),
                reward_string="Exploited CVE-2023-31439",
                cost=1.8
            ),
            "CVE-2007-5686": VulnerabilityInfo(
                description="""initscripts in rPath Linux 1 sets insecure permissions for the /var/log/btmp file, which allows local users to obtain sensitive information regarding authentication attempts.  NOTE: because sshd detec""",
                type=VulnerabilityType.LOCAL,
                outcome=LeakedCredentials([]),
                reward_string="Exploited CVE-2007-5686",
                cost=1.9
            ),
            "CVE-2024-56433": VulnerabilityInfo(
                description="""shadow-utils (aka shadow) 4.4 through 4.17.0 establishes a default /etc/subuid behavior (e.g., uid 100000 through 165535 for the first user account) that can realistically conflict with the uids of us""",
                type=VulnerabilityType.REMOTE,
                outcome=LeakedCredentials([]),
                reward_string="Exploited CVE-2024-56433",
                cost=10.0
            ),
            "TEMP-0628843-DBAD28": VulnerabilityInfo(
                description="""[more related to CVE-2005-4890]""",
                type=VulnerabilityType.REMOTE,
                outcome=LeakedCredentials([]),
                reward_string="Exploited TEMP-0628843-DBAD28",
                cost=10.0
            ),
            "TEMP-0517018-A83CE6": VulnerabilityInfo(
                description="""[sysvinit: no-root option in expert installer exposes locally exploitable security flaw]""",
                type=VulnerabilityType.REMOTE,
                outcome=LeakedCredentials([]),
                reward_string="Exploited TEMP-0517018-A83CE6",
                cost=10.0
            ),
            "CVE-2005-2541": VulnerabilityInfo(
                description="""Tar 1.15.1 does not properly warn the user when extracting setuid or setgid files, which may allow local users or remote attackers to gain privileges.""",
                type=VulnerabilityType.LOCAL,
                outcome=LeakedCredentials([]),
                reward_string="Exploited CVE-2005-2541",
                cost=1.1
            ),
            "TEMP-0290435-0B57B5": VulnerabilityInfo(
                description="""[tar's rmt command may have undesired side effects]""",
                type=VulnerabilityType.REMOTE,
                outcome=LeakedCredentials([]),
                reward_string="Exploited TEMP-0290435-0B57B5",
                cost=10.0
            ),
            "CVE-2023-45853": VulnerabilityInfo(
                description="""MiniZip in zlib through 1.3 has an integer overflow and resultant heap-based buffer overflow in zipOpenNewFileInZip4_64 via a long filename, comment, or extra field. NOTE: MiniZip is not a supported p""",
                type=VulnerabilityType.LOCAL,
                outcome=LeakedCredentials([]),
                reward_string="Exploited CVE-2023-45853",
                cost=1.1
            ),
            "CVE-2025-22869": VulnerabilityInfo(
                description="""SSH servers which implement file transfer protocols are vulnerable to a denial of service attack from clients which complete the key exchange slowly, or not at all, causing pending content to be read """,
                type=VulnerabilityType.REMOTE,
                outcome=LeakedCredentials([]),
                reward_string="Exploited CVE-2025-22869",
                cost=10.0
            ),
            "CVE-2025-22870": VulnerabilityInfo(
                description="""Matching of hosts against proxy patterns can improperly treat an IPv6 zone ID as a hostname component. For example, when the NO_PROXY environment variable is set to "*.example.com", a request to "[::1""",
                type=VulnerabilityType.REMOTE,
                outcome=LeakedNodesId(["discovered_node_0", "discovered_node_1", "discovered_node_2"]),
                reward_string="Exploited CVE-2025-22870",
                cost=10.0
            ),
            "CVE-2025-22872": VulnerabilityInfo(
                description="""The tokenizer incorrectly interprets tags with unquoted attribute values that end with a solidus character (/) as self-closing. When directly using Tokenizer, this can result in such tags incorrectly """,
                type=VulnerabilityType.REMOTE,
                outcome=LeakedNodesId(["discovered_node_0", "discovered_node_1", "discovered_node_2"]),
                reward_string="Exploited CVE-2025-22872",
                cost=10.0
            ),
            "CVE-2025-22868": VulnerabilityInfo(
                description="""An attacker can pass a malicious malformed token which causes unexpected memory to be consumed during parsing.""",
                type=VulnerabilityType.REMOTE,
                outcome=LeakedCredentials([]),
                reward_string="Exploited CVE-2025-22868",
                cost=10.0
            ),
        }

        # Define nodes
        nodes = {
            "master-1": m.NodeInfo(
                services=[],
                value=100,
                properties=["Linux", "K8s_Master", "arch:amd64", "runtime:docker", "subnet:default", "zone:zone-a"],
                vulnerabilities={},
            ),
            "master-2": m.NodeInfo(
                services=[{'name': '9200', 'port': 9200, 'protocol': 'TCP', 'port_name': 'rest-api', 'allowedCredentials': ['example-elasticsearch-data-0_elasticsearch_9200_cred'], 'container': 'elasticsearch'}, {'name': '9300', 'port': 9300, 'protocol': 'TCP', 'port_name': 'transport', 'allowedCredentials': ['example-elasticsearch-data-0_elasticsearch_9300_cred'], 'container': 'elasticsearch'}],
                value=100,
                properties=["Linux", "K8s_Master", "arch:amd64", "runtime:docker", "subnet:default", "zone:zone-b"],
                vulnerabilities={},
            ),
            "master-3": m.NodeInfo(
                services=[{'name': '9200', 'port': 9200, 'protocol': 'TCP', 'port_name': 'rest-api', 'allowedCredentials': ['example-elasticsearch-coordinating-1_elasticsearch_9200_cred'], 'container': 'elasticsearch'}, {'name': '9300', 'port': 9300, 'protocol': 'TCP', 'port_name': 'transport', 'allowedCredentials': ['example-elasticsearch-coordinating-1_elasticsearch_9300_cred'], 'container': 'elasticsearch'}],
                value=100,
                properties=["Linux", "K8s_Master", "arch:amd64", "runtime:docker", "subnet:default", "zone:zone-c"],
                vulnerabilities={},
            ),
            "worker-backend-tier-1": m.NodeInfo(
                services=[{'name': '9200', 'port': 9200, 'protocol': 'TCP', 'port_name': 'rest-api', 'allowedCredentials': ['example-elasticsearch-data-1_elasticsearch_9200_cred'], 'container': 'elasticsearch'}, {'name': '9300', 'port': 9300, 'protocol': 'TCP', 'port_name': 'transport', 'allowedCredentials': ['example-elasticsearch-data-1_elasticsearch_9300_cred'], 'container': 'elasticsearch'}, {'name': '9200', 'port': 9200, 'protocol': 'TCP', 'port_name': 'rest-api', 'allowedCredentials': ['example-elasticsearch-master-0_elasticsearch_9200_cred'], 'container': 'elasticsearch'}, {'name': '9300', 'port': 9300, 'protocol': 'TCP', 'port_name': 'transport', 'allowedCredentials': ['example-elasticsearch-master-0_elasticsearch_9300_cred'], 'container': 'elasticsearch'}],
                value=29,
                properties=["Linux", "K8s_Worker", "arch:amd64", "runtime:docker", "subnet:backend-tier", "zone:zone-c"],
                vulnerabilities={},
            ),
            "worker-backend-tier-2": m.NodeInfo(
                services=[{'name': '9200', 'port': 9200, 'protocol': 'TCP', 'port_name': 'rest-api', 'allowedCredentials': ['example-elasticsearch-master-1_elasticsearch_9200_cred'], 'container': 'elasticsearch'}, {'name': '9300', 'port': 9300, 'protocol': 'TCP', 'port_name': 'transport', 'allowedCredentials': ['example-elasticsearch-master-1_elasticsearch_9300_cred'], 'container': 'elasticsearch'}],
                value=57,
                properties=["Linux", "K8s_Worker", "arch:amd64", "runtime:docker", "subnet:backend-tier", "zone:zone-a"],
                vulnerabilities={},
            ),
            "worker-database-tier-1": m.NodeInfo(
                services=[{'name': '9200', 'port': 9200, 'protocol': 'TCP', 'port_name': 'rest-api', 'allowedCredentials': ['example-elasticsearch-coordinating-0_elasticsearch_9200_cred'], 'container': 'elasticsearch'}, {'name': '9300', 'port': 9300, 'protocol': 'TCP', 'port_name': 'transport', 'allowedCredentials': ['example-elasticsearch-coordinating-0_elasticsearch_9300_cred'], 'container': 'elasticsearch'}],
                value=78,
                properties=["Linux", "K8s_Worker", "arch:amd64", "runtime:docker", "subnet:database-tier", "zone:zone-b"],
                vulnerabilities={"CVE-2011-3374": vulnerability_library["CVE-2011-3374"], "TEMP-0841856-B18BAF": vulnerability_library["TEMP-0841856-B18BAF"], "CVE-2022-0563": vulnerability_library["CVE-2022-0563"], "CVE-2016-2781": vulnerability_library["CVE-2016-2781"], "CVE-2017-18018": vulnerability_library["CVE-2017-18018"], "CVE-2025-5278": vulnerability_library["CVE-2025-5278"], "CVE-2025-6297": vulnerability_library["CVE-2025-6297"], "CVE-2022-27943": vulnerability_library["CVE-2022-27943"], "CVE-2022-3219": vulnerability_library["CVE-2022-3219"], "CVE-2025-30258": vulnerability_library["CVE-2025-30258"], "CVE-2025-4802": vulnerability_library["CVE-2025-4802"], "CVE-2025-8058": vulnerability_library["CVE-2025-8058"], "CVE-2010-4756": vulnerability_library["CVE-2010-4756"], "CVE-2018-20796": vulnerability_library["CVE-2018-20796"], "CVE-2019-1010022": vulnerability_library["CVE-2019-1010022"], "CVE-2019-1010023": vulnerability_library["CVE-2019-1010023"], "CVE-2019-1010024": vulnerability_library["CVE-2019-1010024"], "CVE-2019-1010025": vulnerability_library["CVE-2019-1010025"], "CVE-2019-9192": vulnerability_library["CVE-2019-9192"], "CVE-2018-6829": vulnerability_library["CVE-2018-6829"], "CVE-2024-2236": vulnerability_library["CVE-2024-2236"], "CVE-2011-3389": vulnerability_library["CVE-2011-3389"], "CVE-2023-50495": vulnerability_library["CVE-2023-50495"], "CVE-2025-6141": vulnerability_library["CVE-2025-6141"], "CVE-2025-6020": vulnerability_library["CVE-2025-6020"], "CVE-2024-10041": vulnerability_library["CVE-2024-10041"], "CVE-2024-22365": vulnerability_library["CVE-2024-22365"], "CVE-2023-31484": vulnerability_library["CVE-2023-31484"], "CVE-2025-40909": vulnerability_library["CVE-2025-40909"], "CVE-2011-4116": vulnerability_library["CVE-2011-4116"], "CVE-2023-31486": vulnerability_library["CVE-2023-31486"], "CVE-2023-4016": vulnerability_library["CVE-2023-4016"], "CVE-2025-27587": vulnerability_library["CVE-2025-27587"], "CVE-2013-4392": vulnerability_library["CVE-2013-4392"], "CVE-2023-31437": vulnerability_library["CVE-2023-31437"], "CVE-2023-31438": vulnerability_library["CVE-2023-31438"], "CVE-2023-31439": vulnerability_library["CVE-2023-31439"], "CVE-2007-5686": vulnerability_library["CVE-2007-5686"], "CVE-2024-56433": vulnerability_library["CVE-2024-56433"], "TEMP-0628843-DBAD28": vulnerability_library["TEMP-0628843-DBAD28"], "TEMP-0517018-A83CE6": vulnerability_library["TEMP-0517018-A83CE6"], "CVE-2005-2541": vulnerability_library["CVE-2005-2541"], "TEMP-0290435-0B57B5": vulnerability_library["TEMP-0290435-0B57B5"], "CVE-2023-45853": vulnerability_library["CVE-2023-45853"], "CVE-2025-22869": vulnerability_library["CVE-2025-22869"], "CVE-2025-22870": vulnerability_library["CVE-2025-22870"], "CVE-2025-22872": vulnerability_library["CVE-2025-22872"], "CVE-2025-22868": vulnerability_library["CVE-2025-22868"]},
            ),
            "worker-frontend-tier-1": m.NodeInfo(
                services=[{'name': '9200', 'port': 9200, 'protocol': 'TCP', 'port_name': 'rest-api', 'allowedCredentials': ['example-elasticsearch-ingest-0_elasticsearch_9200_cred'], 'container': 'elasticsearch'}, {'name': '9300', 'port': 9300, 'protocol': 'TCP', 'port_name': 'transport', 'allowedCredentials': ['example-elasticsearch-ingest-0_elasticsearch_9300_cred'], 'container': 'elasticsearch'}],
                value=48,
                properties=["Linux", "K8s_Worker", "arch:amd64", "runtime:docker", "subnet:frontend-tier", "zone:zone-a"],
                vulnerabilities={},
            ),
            "worker-frontend-tier-2": m.NodeInfo(
                services=[{'name': '9200', 'port': 9200, 'protocol': 'TCP', 'port_name': 'rest-api', 'allowedCredentials': ['example-elasticsearch-ingest-1_elasticsearch_9200_cred'], 'container': 'elasticsearch'}, {'name': '9300', 'port': 9300, 'protocol': 'TCP', 'port_name': 'transport', 'allowedCredentials': ['example-elasticsearch-ingest-1_elasticsearch_9300_cred'], 'container': 'elasticsearch'}],
                value=35,
                properties=["Linux", "K8s_Worker", "arch:amd64", "runtime:docker", "subnet:frontend-tier", "zone:zone-b"],
                vulnerabilities={},
            ),
        }

        return m.Environment(
            network=m.create_network(nodes),
            vulnerability_library=vulnerability_library,
            identifiers=m.SAMPLE_IDENTIFIERS
        )


# Create environment instance
environment = K8sScenario_20251007_133910().create()
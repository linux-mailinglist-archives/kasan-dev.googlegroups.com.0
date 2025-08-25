Return-Path: <kasan-dev+bncBCMMDDFSWYCBBUEQWPCQMGQEKUPO4YA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x239.google.com (mail-oi1-x239.google.com [IPv6:2607:f8b0:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 1EB64B34C0C
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 22:32:18 +0200 (CEST)
Received: by mail-oi1-x239.google.com with SMTP id 5614622812f47-435de6f5a7bsf6656369b6e.1
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 13:32:18 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756153937; cv=pass;
        d=google.com; s=arc-20240605;
        b=BkpgiPfwlTOB8BqQIcEw2neXqCelkBM7UMcn7x4p5csJrgJ8vIKgPLx8pKwlDMZKB6
         oKTQHV/N3CorcVeURMIYx/TeS1X2jazgbNoIv1zz+PYlISGmXtCYvzEQ8u28lmiD36TI
         9TifghLhCf4o0uz3gPTdMWwJwsn1PtgZPf5HxrNWcikEW1/yDYqxbITohS81yJ+fgJES
         HkkXLV5hb7Y05I1LYqt8QVNI3PtC3XK2mLk4eGJlCJ85H9ZZHnjBzyo+r0Rp7XVn3sYc
         52PM5e1ZF+WXCKv6Sx3aMqT2frU1AW74XPwFusXee4Nn4VjE3NPqD/m94OatU+KxWejN
         6IFA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Kb+FxOLU5pTvP2QIbJumsdwrzjnUTGqXwz9qB8PoJQw=;
        fh=tkyLOd/MuI/XmgzxA8S7EXU3r7QLgfd+25hr8voMh3w=;
        b=Buf/zv5SNu/2k5HrZzm9W3Dv4bWlQBhrXi2i/+c0kgQp1vV5QG9Hi40vNjAhhUmq0j
         XRS627qbh6z1CgF8/kFssqSapXT5C3jXXbrjWyrjii4G8Ok9/WEJZ/XFkyERZQCZ5hgO
         g5FxKso5i3veinnXVhul3J5e3iqipWKkOQUrSKG672A6GlfArN8fYRg7SIcQVANOSPA6
         lOaLTLtwRvy8UMPR9OH/m1fcTdLjiOD4cfKSyHbvfXQ8e8SDh4vu9nsa6v7l/cxPZWUu
         Y2J7qjBhWRvDoCYmw8XYwvuCfLBgSPOjA9BPMMROFdmDluZ+I7fZVsv+QhvfpQn5YKc5
         G9yQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=HftsJqF2;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756153937; x=1756758737; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Kb+FxOLU5pTvP2QIbJumsdwrzjnUTGqXwz9qB8PoJQw=;
        b=TU/f0MANjX13aKBjXtADVR0Us4coRoVtkSiSm7KD5LRATkCwGL09CBR34NCUcjsYMM
         T9kAdicIZ9ogidRAZWDneVE/DtTOWyRL3gWnbuDHQTExZ/w+LN+h5x1mvAB1+i8qw2al
         GFJzw+oKCb1tVYKEcXoRK6+LkOgnlOz4S+qHeH3JolrkcYboktij8UZs1W0VEBMR66+g
         ZyvR2nLcblQWy2uIwuOwqIxsXLlAheCPswi0NBoUizzO8kmy1OIraESP/Um3xt8H0OKb
         Ap4Bv8m3HSlEoHvDj0xGuekEiYheDoQHeGN4auXnFujAeXVbl7b01ziqQEi+40uf6Tzw
         WOMg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756153937; x=1756758737;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Kb+FxOLU5pTvP2QIbJumsdwrzjnUTGqXwz9qB8PoJQw=;
        b=JTIJbwqe2kVd+3e/zodSYJVM1z27/z6uNn7kmZTX2kgwIYdNrdljLB4LpwrmGjbyem
         yKgSYd5HyLCI5nZzSNPYXbHy5R/qusP8igIwFseXFN284K6vU1rCBeahHn+DQIzCz7IW
         A8HYWiKxoqBDx/PlHYGyhTumLXZBL6rS5xxAPMk4oI6FWleXws+tJQap0v9EWrSV5qmd
         CjOY5BrW1ZSFOY0iD2QZQXcwmuh6iZHASXUB2rwyT1R1qGifC2eXeutB2qM3Mljt/ppi
         L292pP10Uh7eL8Ki5UA6fIY4aKaoIsAM2Rw8/s8ts54VtbAErCPgiHzI38tzPLU/GWiS
         KEEg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUBaaUq6H35pEyeledzlrO9pF8l6P/ssBNv0MGCI7EG95y7+3nkN35UtAlRHj8s6rGM/TfAag==@lfdr.de
X-Gm-Message-State: AOJu0Yw7QwbcczXXGd+RTK2pwn9tTA39ar14UZR24dHi+iO64MX7hACg
	JSnZvmBI9qgRpDq8dcmBkYh8bfY/wpRzOVOSbSaVJBJ34Xq3SW454AVC
X-Google-Smtp-Source: AGHT+IG13GaeFiFerFkHzdYYCeOFIcxdRz0LEwDsGF3yC3HPAyE7aMLW9/mqyX6PZ/Em8E9PmjAMHg==
X-Received: by 2002:a05:6808:bcd:b0:41e:9fd0:bd2c with SMTP id 5614622812f47-437851a3774mr5441579b6e.18.1756153936767;
        Mon, 25 Aug 2025 13:32:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcI/qX2aS1iIluR2liRjNFV6fNuuDhbFTfPfo9CRthXSA==
Received: by 2002:a05:6871:c30f:b0:30b:d6e4:3de6 with SMTP id
 586e51a60fabf-314c231454els2323111fac.2.-pod-prod-01-us; Mon, 25 Aug 2025
 13:32:16 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUHTttJZjYQM9tuPecZumnxi52WWRajxGtl+UHhCaT9s0MvYs8lwaTy74RUa4PAyaaP7sfJPAflsck=@googlegroups.com
X-Received: by 2002:a05:6871:5b08:b0:2ff:9604:b95a with SMTP id 586e51a60fabf-314dcabd35dmr6779761fac.3.1756153935866;
        Mon, 25 Aug 2025 13:32:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756153935; cv=none;
        d=google.com; s=arc-20240605;
        b=NEuN7DoRNuDMGxKmpsX3de4+ZqaZjFZS5LJDqV3qRzsQlUj79pslosYSsYz71xaROb
         RpUzqF6C7VQXcCwYUDwoPJpbmoOo4bRonIgsHJO1k8CleNbUoo75ruUIzhpAHI4rvWSz
         tgs+nwTO/twGQERS/4LnVNByi5EJN0/0KyynwHiAfSdRUdrsnffdTw5C5jtNT3rQBASL
         TwykfkaPvB/QCTGUfldGVPNEasSGmvAduTR/f9k8XApvZrp5vAmYvDNBdXARpdwYsWJR
         4tevtqUFW8Rjkm9WR1M/0sglAeuH0VoFj5BcqKsRL35NLaNRJ71YOsuDFs9acypRAlUh
         4wpA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=e9dZ7HYFm04sYh+3FqLYILOU5ulghIY66izoMMIko1I=;
        fh=d+GoPTlmu33D8YzMNxzEeUOBk4HhNGSLvAzcCqpwrJg=;
        b=XQuf6Lim3OMMudXSlclasYuIPDCVFnn/M0mJHahf8axQAJJNCTEq9t4Thfm2Mt0yt0
         YmctgoDDn/VCJa04C7CmIfxZgzVw9JnUEgPO80OZCBsWrHnPA5ROfCBgMd8iaTMSMwZA
         4Hv9uJl/KfdYtHWlAMtl+J3ipoEa6q/eGZzfUbWbjsPdLDHjU/iYPLjYzjknTVl0xOOh
         9xs/B3Lmrwd7FROBq+KDxY642u8UiZv8LL9Oqc34JIxNrnrMDiba82JhiqnukXGdclpO
         FvPjyjnSJshLiZ/7QzrOPiiImNEM61WFgte352JQA9+QszOPhAW4j2zJ3SLt8oX6QCkO
         qC7A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=HftsJqF2;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.11])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-314f7c34762si346695fac.4.2025.08.25.13.32.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 25 Aug 2025 13:32:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.11 as permitted sender) client-ip=192.198.163.11;
X-CSE-ConnectionGUID: x7NNXt/jSdmN0CgpyetEtA==
X-CSE-MsgGUID: bnzyx/HdTnyVA0f/aI2AJg==
X-IronPort-AV: E=McAfee;i="6800,10657,11533"; a="68971226"
X-IronPort-AV: E=Sophos;i="6.18,214,1751266800"; 
   d="scan'208";a="68971226"
Received: from fmviesa008.fm.intel.com ([10.60.135.148])
  by fmvoesa105.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 25 Aug 2025 13:32:14 -0700
X-CSE-ConnectionGUID: cXWZ7dRGQvecpjyhpKanvw==
X-CSE-MsgGUID: bpDPHCHLRsKzMlSFZem02A==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.18,214,1751266800"; 
   d="scan'208";a="169781042"
Received: from bergbenj-mobl1.ger.corp.intel.com (HELO wieczorr-mobl1.intel.com) ([10.245.245.6])
  by fmviesa008-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 25 Aug 2025 13:31:53 -0700
From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
To: sohil.mehta@intel.com,
	baohua@kernel.org,
	david@redhat.com,
	kbingham@kernel.org,
	weixugc@google.com,
	Liam.Howlett@oracle.com,
	alexandre.chartre@oracle.com,
	kas@kernel.org,
	mark.rutland@arm.com,
	trintaeoitogc@gmail.com,
	axelrasmussen@google.com,
	yuanchu@google.com,
	joey.gouly@arm.com,
	samitolvanen@google.com,
	joel.granados@kernel.org,
	graf@amazon.com,
	vincenzo.frascino@arm.com,
	kees@kernel.org,
	ardb@kernel.org,
	thiago.bauermann@linaro.org,
	glider@google.com,
	thuth@redhat.com,
	kuan-ying.lee@canonical.com,
	pasha.tatashin@soleen.com,
	nick.desaulniers+lkml@gmail.com,
	vbabka@suse.cz,
	kaleshsingh@google.com,
	justinstitt@google.com,
	catalin.marinas@arm.com,
	alexander.shishkin@linux.intel.com,
	samuel.holland@sifive.com,
	dave.hansen@linux.intel.com,
	corbet@lwn.net,
	xin@zytor.com,
	dvyukov@google.com,
	tglx@linutronix.de,
	scott@os.amperecomputing.com,
	jason.andryuk@amd.com,
	morbo@google.com,
	nathan@kernel.org,
	lorenzo.stoakes@oracle.com,
	mingo@redhat.com,
	brgerst@gmail.com,
	kristina.martsenko@arm.com,
	bigeasy@linutronix.de,
	luto@kernel.org,
	jgross@suse.com,
	jpoimboe@kernel.org,
	urezki@gmail.com,
	mhocko@suse.com,
	ada.coupriediaz@arm.com,
	hpa@zytor.com,
	maciej.wieczor-retman@intel.com,
	leitao@debian.org,
	peterz@infradead.org,
	wangkefeng.wang@huawei.com,
	surenb@google.com,
	ziy@nvidia.com,
	smostafa@google.com,
	ryabinin.a.a@gmail.com,
	ubizjak@gmail.com,
	jbohac@suse.cz,
	broonie@kernel.org,
	akpm@linux-foundation.org,
	guoweikang.kernel@gmail.com,
	rppt@kernel.org,
	pcc@google.com,
	jan.kiszka@siemens.com,
	nicolas.schier@linux.dev,
	will@kernel.org,
	andreyknvl@gmail.com,
	jhubbard@nvidia.com,
	bp@alien8.de
Cc: x86@kernel.org,
	linux-doc@vger.kernel.org,
	linux-mm@kvack.org,
	llvm@lists.linux.dev,
	linux-kbuild@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org
Subject: [PATCH v5 19/19] x86: Make software tag-based kasan available
Date: Mon, 25 Aug 2025 22:24:44 +0200
Message-ID: <3db48135aec987c99e8e6601249d4a4c023703c4.1756151769.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1756151769.git.maciej.wieczor-retman@intel.com>
References: <cover.1756151769.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=HftsJqF2;       spf=pass
 (google.com: domain of maciej.wieczor-retman@intel.com designates
 192.198.163.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Content-Type: text/plain; charset="UTF-8"
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

Make CONFIG_KASAN_SW_TAGS available for x86 machines if they have
ADDRESS_MASKING enabled (LAM) as that works similarly to Top-Byte Ignore
(TBI) that allows the software tag-based mode on arm64 platform.

Set scale macro based on KASAN mode: in software tag-based mode 16 bytes
of memory map to one shadow byte and 8 in generic mode.

Disable CONFIG_KASAN_INLINE and CONFIG_KASAN_STACK when
CONFIG_KASAN_SW_TAGS is enabled on x86 until the appropriate compiler
support is available.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
Changelog v4:
- Add x86 specific kasan_mem_to_shadow().
- Revert x86 to the older unsigned KASAN_SHADOW_OFFSET. Do the same to
  KASAN_SHADOW_START/END.
- Modify scripts/gdb/linux/kasan.py to keep x86 using unsigned offset.
- Disable inline and stack support when software tags are enabled on
  x86.

Changelog v3:
- Remove runtime_const from previous patch and merge the rest here.
- Move scale shift definition back to header file.
- Add new kasan offset for software tag based mode.
- Fix patch message typo 32 -> 16, and 16 -> 8.
- Update lib/Kconfig.kasan with x86 now having software tag-based
  support.

Changelog v2:
- Remove KASAN dense code.

 Documentation/arch/x86/x86_64/mm.rst | 6 ++++--
 arch/x86/Kconfig                     | 4 +++-
 arch/x86/boot/compressed/misc.h      | 1 +
 arch/x86/include/asm/kasan.h         | 1 +
 arch/x86/kernel/setup.c              | 2 ++
 lib/Kconfig.kasan                    | 3 ++-
 scripts/gdb/linux/kasan.py           | 4 ++--
 7 files changed, 15 insertions(+), 6 deletions(-)

diff --git a/Documentation/arch/x86/x86_64/mm.rst b/Documentation/arch/x86/x86_64/mm.rst
index a6cf05d51bd8..ccbdbb4cda36 100644
--- a/Documentation/arch/x86/x86_64/mm.rst
+++ b/Documentation/arch/x86/x86_64/mm.rst
@@ -60,7 +60,8 @@ Complete virtual memory map with 4-level page tables
    ffffe90000000000 |  -23    TB | ffffe9ffffffffff |    1 TB | ... unused hole
    ffffea0000000000 |  -22    TB | ffffeaffffffffff |    1 TB | virtual memory map (vmemmap_base)
    ffffeb0000000000 |  -21    TB | ffffebffffffffff |    1 TB | ... unused hole
-   ffffec0000000000 |  -20    TB | fffffbffffffffff |   16 TB | KASAN shadow memory
+   ffffec0000000000 |  -20    TB | fffffbffffffffff |   16 TB | KASAN shadow memory (generic mode)
+   fffff40000000000 |   -8    TB | fffffbffffffffff |    8 TB | KASAN shadow memory (software tag-based mode)
   __________________|____________|__________________|_________|____________________________________________________________
                                                               |
                                                               | Identical layout to the 56-bit one from here on:
@@ -130,7 +131,8 @@ Complete virtual memory map with 5-level page tables
    ffd2000000000000 |  -11.5  PB | ffd3ffffffffffff |  0.5 PB | ... unused hole
    ffd4000000000000 |  -11    PB | ffd5ffffffffffff |  0.5 PB | virtual memory map (vmemmap_base)
    ffd6000000000000 |  -10.5  PB | ffdeffffffffffff | 2.25 PB | ... unused hole
-   ffdf000000000000 |   -8.25 PB | fffffbffffffffff |   ~8 PB | KASAN shadow memory
+   ffdf000000000000 |   -8.25 PB | fffffbffffffffff |   ~8 PB | KASAN shadow memory (generic mode)
+   ffeffc0000000000 |   -6    PB | fffffbffffffffff |    4 PB | KASAN shadow memory (software tag-based mode)
   __________________|____________|__________________|_________|____________________________________________________________
                                                               |
                                                               | Identical layout to the 47-bit one from here on:
diff --git a/arch/x86/Kconfig b/arch/x86/Kconfig
index b8df57ac0f28..f44fec1190b6 100644
--- a/arch/x86/Kconfig
+++ b/arch/x86/Kconfig
@@ -69,6 +69,7 @@ config X86
 	select ARCH_CLOCKSOURCE_INIT
 	select ARCH_CONFIGURES_CPU_MITIGATIONS
 	select ARCH_CORRECT_STACKTRACE_ON_KRETPROBE
+	select ARCH_DISABLE_KASAN_INLINE	if X86_64 && KASAN_SW_TAGS
 	select ARCH_ENABLE_HUGEPAGE_MIGRATION if X86_64 && HUGETLB_PAGE && MIGRATION
 	select ARCH_ENABLE_MEMORY_HOTPLUG if X86_64
 	select ARCH_ENABLE_MEMORY_HOTREMOVE if MEMORY_HOTPLUG
@@ -199,6 +200,7 @@ config X86
 	select HAVE_ARCH_JUMP_LABEL_RELATIVE
 	select HAVE_ARCH_KASAN			if X86_64
 	select HAVE_ARCH_KASAN_VMALLOC		if X86_64
+	select HAVE_ARCH_KASAN_SW_TAGS		if ADDRESS_MASKING
 	select HAVE_ARCH_KFENCE
 	select HAVE_ARCH_KMSAN			if X86_64
 	select HAVE_ARCH_KGDB
@@ -403,7 +405,7 @@ config AUDIT_ARCH
 
 config KASAN_SHADOW_OFFSET
 	hex
-	depends on KASAN
+	default 0xeffffc0000000000 if KASAN_SW_TAGS
 	default 0xdffffc0000000000
 
 config HAVE_INTEL_TXT
diff --git a/arch/x86/boot/compressed/misc.h b/arch/x86/boot/compressed/misc.h
index db1048621ea2..ded92b439ada 100644
--- a/arch/x86/boot/compressed/misc.h
+++ b/arch/x86/boot/compressed/misc.h
@@ -13,6 +13,7 @@
 #undef CONFIG_PARAVIRT_SPINLOCKS
 #undef CONFIG_KASAN
 #undef CONFIG_KASAN_GENERIC
+#undef CONFIG_KASAN_SW_TAGS
 
 #define __NO_FORTIFY
 
diff --git a/arch/x86/include/asm/kasan.h b/arch/x86/include/asm/kasan.h
index f3e34a9754d2..385f4e9daab3 100644
--- a/arch/x86/include/asm/kasan.h
+++ b/arch/x86/include/asm/kasan.h
@@ -7,6 +7,7 @@
 #include <linux/types.h>
 #define KASAN_SHADOW_OFFSET _AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
 #ifdef CONFIG_KASAN_SW_TAGS
+#define KASAN_SHADOW_SCALE_SHIFT 4
 
 /*
  * LLVM ABI for reporting tag mismatches in inline KASAN mode.
diff --git a/arch/x86/kernel/setup.c b/arch/x86/kernel/setup.c
index 1b2edd07a3e1..5b819f84f6db 100644
--- a/arch/x86/kernel/setup.c
+++ b/arch/x86/kernel/setup.c
@@ -1207,6 +1207,8 @@ void __init setup_arch(char **cmdline_p)
 
 	kasan_init();
 
+	kasan_init_sw_tags();
+
 	/*
 	 * Sync back kernel address range.
 	 *
diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index f82889a830fa..9ddbc6aeb5d5 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -100,7 +100,8 @@ config KASAN_SW_TAGS
 
 	  Requires GCC 11+ or Clang.
 
-	  Supported only on arm64 CPUs and relies on Top Byte Ignore.
+	  Supported on arm64 CPUs that support Top Byte Ignore and on x86 CPUs
+	  that support Linear Address Masking.
 
 	  Consumes about 1/16th of available memory at kernel start and
 	  add an overhead of ~20% for dynamic allocations.
diff --git a/scripts/gdb/linux/kasan.py b/scripts/gdb/linux/kasan.py
index fca39968d308..4b86202b155f 100644
--- a/scripts/gdb/linux/kasan.py
+++ b/scripts/gdb/linux/kasan.py
@@ -7,7 +7,7 @@
 #
 
 import gdb
-from linux import constants, mm
+from linux import constants, utils, mm
 from ctypes import c_int64 as s64
 
 def help():
@@ -40,7 +40,7 @@ class KasanMemToShadow(gdb.Command):
         else:
             help()
     def kasan_mem_to_shadow(self, addr):
-        if constants.CONFIG_KASAN_SW_TAGS:
+        if constants.CONFIG_KASAN_SW_TAGS and not utils.is_target_arch('x86'):
             addr = s64(addr)
         return (addr >> self.p_ops.KASAN_SHADOW_SCALE_SHIFT) + self.p_ops.KASAN_SHADOW_OFFSET
 
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/3db48135aec987c99e8e6601249d4a4c023703c4.1756151769.git.maciej.wieczor-retman%40intel.com.

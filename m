Return-Path: <kasan-dev+bncBCMMDDFSWYCBBJUC5XCAMGQEZMNVHAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 8EAB0B2285B
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 15:27:03 +0200 (CEST)
Received: by mail-il1-x138.google.com with SMTP id e9e14a558f8ab-3e40bc54f89sf68479135ab.0
        for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 06:27:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755005222; cv=pass;
        d=google.com; s=arc-20240605;
        b=HNK0sfZxxjV5AyXQYMOTkQcDcuAaLThGfA0B/+ayrh54sRYiwUYdg26nrluGRGWFTH
         yBU9xQpfhd3qrosC+q+U+5VUop2SOnKzausTo2ziF/nCYrOhJ5UcPOwFcmwWAIvpsSmb
         8S0glNlZLhf1DaeYc2sqsYEMmT+sLwpn/Q6NNLoWG+m/9mJwJ75XbOJK58jFFPb/xIYe
         YX5VqafUCo2X3DsL0wEQAcQa2AJMiuzDW9tpVxz1oSS6ZTJ2HjCfkX6NFyNCAhyWkEJ7
         tr71qHlvVBwJcZSHBKD6jf8rSh6CcNPlRuAfnUljT6wJincU8StnW6Zf7joeBdcef243
         HNXg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=4H4lml5AaJ9Py3bSB6f2O2yBC9VgptQLlcFafw+thuk=;
        fh=8Yyzjf4RwmFbTlDjbldIDHNpQ8oCu1yGSa3CifPexj8=;
        b=JmmL6FlGWsRoTQvFhQI0HzX6TPXPY8J/cPSQpRjVrV3Zy+6iEXv700QVLXjgfp3XPA
         sPKXglX/7xMb0qBTfabPzjVTeJLvP0oAyKrX8ijGOmnInBSWQUv300AxAWUdO+9Ay8Qs
         jKJpd9uvGUBEhZgdkDewPWXNA9KgDXCmpFIuOwpn0BzUN0WkrhR/H0pyLuz763Y6thY+
         ctPrrdXcJsHHv0ZHKRwJtvkhgGN+gT6hxtBG2qy4ZAAxuXV/BPBvbMv23UpNJgqowy3L
         h0E3AZwBfUix/Ft4GkCOmAVHWXYTH3VIUXIRp8L+MfYhunXefTseLWNF2lJiavVqVf3d
         dxaQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=IvjkOruw;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.15 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755005222; x=1755610022; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=4H4lml5AaJ9Py3bSB6f2O2yBC9VgptQLlcFafw+thuk=;
        b=ruoEPqaJ3hJ4WwVne+tfkLmfDaqCZ9IGiL/qF/eoJIBGAgKSBMF3VeynOXZgM2DCGB
         sfaXCjefVD0YB95CR77qMMkpqqpO3BKvWZMHZF7W4twrSav1R78EXuGhGuAZanIpi9Uu
         Td6XyNN1phU2Ai08azHE9BIOSdxDNBapBqq7bIxKwwbelJv6JbBjKRJVj1uw3KPEjlnQ
         wxlukt+lQd4P76UBzOzQ53I9pFCtNqhVKPth1deoscLhiQgWdLDybaq+UVMEKozEtC9y
         neefeV01CvZdYJx8wAjgiaQFOQm7lskXPjF1a4f8YpLBuyL2VBQf9wSJSzDLY+JbhKVh
         W5DA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755005222; x=1755610022;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=4H4lml5AaJ9Py3bSB6f2O2yBC9VgptQLlcFafw+thuk=;
        b=kbRkeDres9TRk5+vPeh1njhr+GLR1IA0uuLfX+blD4zXPTNNfosQOBQK+DgI86Eqct
         KW0T1wBPoQC0aS84KmPFZeuOuHkg7H1Y88PnNPE4AWrxl5v83zrcPi7yH6vwxX8Gsv81
         s3IPB2r4e2KwkSLA+Qp8K1lhQnrnrUAlgoAKq8iZr5EB50A0ccKn07bWjHF8mJob4hGr
         w9XWgGIyvC03oP8alYDceOnUoTO0bmpacdWPbzzm78PJQtAC0sQdea/LU9gN2MEyRo9U
         CbljE6rrl77FdmlspXPcgm0+nVxsEuzkxmtYsw0ZvQPEvQYizaR5p2SefMnK3b5/qejw
         myfw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCViJADVUkUMgdpGpMAGPzV067WeNQMotQIPHqSD68uUqo+00b1dJ2wS5qu8T3G0pSIJybdE3w==@lfdr.de
X-Gm-Message-State: AOJu0Yx3iB1Y5O03LgR8zvMfOLvFWLpUvJ1HD95iGt5zWIaklF0WFIG9
	BdNMe5Qh83YJ0P8YzEb/iFZ5V5IrgzLEAqt6kFCBKElnLWDcGbD3M0X/
X-Google-Smtp-Source: AGHT+IEohJ32Wb2RkBW1OX8XhU4LlJYvNzZnao64EQqEET9Cc9V+J79Cs1MLEVlXMXCT1pzaiu3QDw==
X-Received: by 2002:a05:6e02:2286:b0:3e5:4da2:93ac with SMTP id e9e14a558f8ab-3e54da29b99mr118377115ab.17.1755005222215;
        Tue, 12 Aug 2025 06:27:02 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd/3iapmOjBHgcTxoReR4bW5Egcvz7pDaEMOzqIUAmwcg==
Received: by 2002:a05:6e02:218e:b0:3e5:640d:d985 with SMTP id
 e9e14a558f8ab-3e5640dd9fdls1181025ab.2.-pod-prod-09-us; Tue, 12 Aug 2025
 06:27:01 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWEMCERjiojqa6HNHgxgBSlUJGx+Yq8ziy/wlHUeW5b8Lwz+SryjkBd/iDO38Tirb/RWHm4zb9yXPw=@googlegroups.com
X-Received: by 2002:a05:6602:1481:b0:864:4b3a:9e3a with SMTP id ca18e2360f4ac-883f127b622mr2872286939f.13.1755005221311;
        Tue, 12 Aug 2025 06:27:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755005221; cv=none;
        d=google.com; s=arc-20240605;
        b=i4msrZq9yruN1XR1qg5fPsALmuLAZT2LexNbh0g5j+YuBezfX2fUGvq2Cgn5p5eOyN
         vkZplgfkwFkJTuV0S7KgQQn49KP4PK2Buc4M8AuSJuHQHb//mvY8W3lEYtbBQ6URxUZ5
         /NmIt20kh+x0o8EDSkOG1ey3pF9PT6uaKZ+Knqd3PnW2NdGSdv5gzDqgqGdUV+3rfuZ/
         qt4vo9d0AR+iiCyj45MzCDK1BSK2oxLD/3Yl7ewm7xLxweoL5D6oTcBa1eJ8VsVhMlH2
         xYUecMYPW179svI/CTTHp/qF0FLEUNVVRTI/HRgqgJrD+HFk6oQVhN4uRReqEqlatRUt
         brPQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=vi+DnfymbWINgDO7B71cxapm47NMkhYdRMHYX+0KAIs=;
        fh=eWu/aO2D40nqoCm67aTC6qXZDH3y79upeaB1pmat6Ew=;
        b=NmmA3/2iMZHmQ1KcLeN+A2OEpkD2iQwGcf9fh9nk+e0OXsSVLYJ35+IN5WmWJpDpmw
         C8AP0dgwafEeIt6B94u85YOH4dKTRn9OwXomH+hjRT7HPzyDl3wuUnhOfyECK40CYbRc
         Bn3axDqOIc14nXMU3dImRReKov7/wt71+Aeql+a20Jo2bKDSqFnLCpdbnvdOdaU1HJWV
         v5P6X7iKl9lXZteJzCwloRE2CVSgpQHHjHdcCCHiiMiBK7QaUHQHoe8AAjNIghsrRAUa
         9HmFazrwN/2gEl4fRDKZo7OMwSYv3hwnZ2cOX5jisRU3Nsqd6Id48BiMJctIKAiU53NF
         dNFA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=IvjkOruw;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.15 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.15])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-883f18eccc3si49156639f.1.2025.08.12.06.27.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 12 Aug 2025 06:27:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.15 as permitted sender) client-ip=198.175.65.15;
X-CSE-ConnectionGUID: RWC2RO82Q0apLVWCO1uMRA==
X-CSE-MsgGUID: 5jwG9OElQru4oqQqdGrJtg==
X-IronPort-AV: E=McAfee;i="6800,10657,11520"; a="60903389"
X-IronPort-AV: E=Sophos;i="6.17,284,1747724400"; 
   d="scan'208";a="60903389"
Received: from orviesa009.jf.intel.com ([10.64.159.149])
  by orvoesa107.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 12 Aug 2025 06:26:55 -0700
X-CSE-ConnectionGUID: 0gOP6hCJQl2mMyP4g+OHwQ==
X-CSE-MsgGUID: 99luYSpdRRigAj3rcRdRgg==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.17,284,1747724400"; 
   d="scan'208";a="165831406"
Received: from vpanait-mobl.ger.corp.intel.com (HELO wieczorr-mobl1.intel.com) ([10.245.245.54])
  by orviesa009-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 12 Aug 2025 06:26:32 -0700
From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
To: nathan@kernel.org,
	arnd@arndb.de,
	broonie@kernel.org,
	Liam.Howlett@oracle.com,
	urezki@gmail.com,
	will@kernel.org,
	kaleshsingh@google.com,
	rppt@kernel.org,
	leitao@debian.org,
	coxu@redhat.com,
	surenb@google.com,
	akpm@linux-foundation.org,
	luto@kernel.org,
	jpoimboe@kernel.org,
	changyuanl@google.com,
	hpa@zytor.com,
	dvyukov@google.com,
	kas@kernel.org,
	corbet@lwn.net,
	vincenzo.frascino@arm.com,
	smostafa@google.com,
	nick.desaulniers+lkml@gmail.com,
	morbo@google.com,
	andreyknvl@gmail.com,
	alexander.shishkin@linux.intel.com,
	thiago.bauermann@linaro.org,
	catalin.marinas@arm.com,
	ryabinin.a.a@gmail.com,
	jan.kiszka@siemens.com,
	jbohac@suse.cz,
	dan.j.williams@intel.com,
	joel.granados@kernel.org,
	baohua@kernel.org,
	kevin.brodsky@arm.com,
	nicolas.schier@linux.dev,
	pcc@google.com,
	andriy.shevchenko@linux.intel.com,
	wei.liu@kernel.org,
	bp@alien8.de,
	ada.coupriediaz@arm.com,
	xin@zytor.com,
	pankaj.gupta@amd.com,
	vbabka@suse.cz,
	glider@google.com,
	jgross@suse.com,
	kees@kernel.org,
	jhubbard@nvidia.com,
	joey.gouly@arm.com,
	ardb@kernel.org,
	thuth@redhat.com,
	pasha.tatashin@soleen.com,
	kristina.martsenko@arm.com,
	bigeasy@linutronix.de,
	maciej.wieczor-retman@intel.com,
	lorenzo.stoakes@oracle.com,
	jason.andryuk@amd.com,
	david@redhat.com,
	graf@amazon.com,
	wangkefeng.wang@huawei.com,
	ziy@nvidia.com,
	mark.rutland@arm.com,
	dave.hansen@linux.intel.com,
	samuel.holland@sifive.com,
	kbingham@kernel.org,
	trintaeoitogc@gmail.com,
	scott@os.amperecomputing.com,
	justinstitt@google.com,
	kuan-ying.lee@canonical.com,
	maz@kernel.org,
	tglx@linutronix.de,
	samitolvanen@google.com,
	mhocko@suse.com,
	nunodasneves@linux.microsoft.com,
	brgerst@gmail.com,
	willy@infradead.org,
	ubizjak@gmail.com,
	peterz@infradead.org,
	mingo@redhat.com,
	sohil.mehta@intel.com
Cc: linux-mm@kvack.org,
	linux-kbuild@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org,
	x86@kernel.org,
	llvm@lists.linux.dev,
	kasan-dev@googlegroups.com,
	linux-doc@vger.kernel.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH v4 05/18] kasan: arm64: x86: Make special tags arch specific
Date: Tue, 12 Aug 2025 15:23:41 +0200
Message-ID: <788b6f9a1f5adf2b69564489d16de436ba1bdc3c.1755004923.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1755004923.git.maciej.wieczor-retman@intel.com>
References: <cover.1755004923.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=IvjkOruw;       spf=pass
 (google.com: domain of maciej.wieczor-retman@intel.com designates
 198.175.65.15 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
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

KASAN's tag-based mode defines multiple special tag values. They're
reserved for:
- Native kernel value. On arm64 it's 0xFF and it causes an early return
  in the tag checking function.
- Invalid value. 0xFE marks an area as freed / unallocated. It's also
  the value that is used to initialize regions of shadow memory.
- Max value. 0xFD is the highest value that can be randomly generated
  for a new tag.

Metadata macro is also defined:
- Tag width equal to 8.

Tag-based mode on x86 is going to use 4 bit wide tags so all the above
values need to be changed accordingly.

Make native kernel tag arch specific for x86 and arm64.

Replace hardcoded kernel tag value and tag width with macros in KASAN's
non-arch specific code.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
Changelog v4:
- Move KASAN_TAG_MASK to kasan-tags.h.

Changelog v2:
- Remove risc-v from the patch.

 MAINTAINERS                         |  2 +-
 arch/arm64/include/asm/kasan-tags.h |  9 +++++++++
 arch/x86/include/asm/kasan-tags.h   |  9 +++++++++
 include/linux/kasan-tags.h          | 10 +++++++++-
 include/linux/kasan.h               |  4 +++-
 include/linux/mm.h                  |  6 +++---
 include/linux/mmzone.h              |  1 -
 include/linux/page-flags-layout.h   |  9 +--------
 8 files changed, 35 insertions(+), 15 deletions(-)
 create mode 100644 arch/arm64/include/asm/kasan-tags.h
 create mode 100644 arch/x86/include/asm/kasan-tags.h

diff --git a/MAINTAINERS b/MAINTAINERS
index fe168477caa4..7ce8c6b86e3d 100644
--- a/MAINTAINERS
+++ b/MAINTAINERS
@@ -13166,7 +13166,7 @@ L:	kasan-dev@googlegroups.com
 S:	Maintained
 B:	https://bugzilla.kernel.org/buglist.cgi?component=Sanitizers&product=Memory%20Management
 F:	Documentation/dev-tools/kasan.rst
-F:	arch/*/include/asm/*kasan.h
+F:	arch/*/include/asm/*kasan*.h
 F:	arch/*/mm/kasan_init*
 F:	include/linux/kasan*.h
 F:	lib/Kconfig.kasan
diff --git a/arch/arm64/include/asm/kasan-tags.h b/arch/arm64/include/asm/kasan-tags.h
new file mode 100644
index 000000000000..8cb12ebae57f
--- /dev/null
+++ b/arch/arm64/include/asm/kasan-tags.h
@@ -0,0 +1,9 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+#ifndef __ASM_KASAN_TAGS_H
+#define __ASM_KASAN_TAGS_H
+
+#define KASAN_TAG_KERNEL	0xFF /* native kernel pointers tag */
+
+#define KASAN_TAG_WIDTH		8
+
+#endif /* ASM_KASAN_TAGS_H */
diff --git a/arch/x86/include/asm/kasan-tags.h b/arch/x86/include/asm/kasan-tags.h
new file mode 100644
index 000000000000..68ba385bc75c
--- /dev/null
+++ b/arch/x86/include/asm/kasan-tags.h
@@ -0,0 +1,9 @@
+/* SPDX-License-Identifier: GPL-2.0 */
+#ifndef __ASM_KASAN_TAGS_H
+#define __ASM_KASAN_TAGS_H
+
+#define KASAN_TAG_KERNEL	0xF /* native kernel pointers tag */
+
+#define KASAN_TAG_WIDTH		4
+
+#endif /* ASM_KASAN_TAGS_H */
diff --git a/include/linux/kasan-tags.h b/include/linux/kasan-tags.h
index e07c896f95d3..fe80fa8f3315 100644
--- a/include/linux/kasan-tags.h
+++ b/include/linux/kasan-tags.h
@@ -2,7 +2,15 @@
 #ifndef _LINUX_KASAN_TAGS_H
 #define _LINUX_KASAN_TAGS_H
 
-#include <asm/kasan.h>
+#if defined(CONFIG_KASAN_SW_TAGS) || defined(CONFIG_KASAN_HW_TAGS)
+#include <asm/kasan-tags.h>
+#endif
+
+#ifndef KASAN_TAG_WIDTH
+#define KASAN_TAG_WIDTH		0
+#endif
+
+#define KASAN_TAG_MASK		((1UL << KASAN_TAG_WIDTH) - 1)
 
 #ifndef KASAN_TAG_KERNEL
 #define KASAN_TAG_KERNEL	0xFF /* native kernel pointers tag */
diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index b396feca714f..54481f8c30c5 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -40,7 +40,9 @@ typedef unsigned int __bitwise kasan_vmalloc_flags_t;
 
 #ifdef CONFIG_KASAN_SW_TAGS
 /* This matches KASAN_TAG_INVALID. */
-#define KASAN_SHADOW_INIT 0xFE
+#ifndef KASAN_SHADOW_INIT
+#define KASAN_SHADOW_INIT KASAN_TAG_INVALID
+#endif
 #else
 #define KASAN_SHADOW_INIT 0
 #endif
diff --git a/include/linux/mm.h b/include/linux/mm.h
index 1ae97a0b8ec7..bb494cb1d5af 100644
--- a/include/linux/mm.h
+++ b/include/linux/mm.h
@@ -1692,7 +1692,7 @@ static inline u8 page_kasan_tag(const struct page *page)
 
 	if (kasan_enabled()) {
 		tag = (page->flags >> KASAN_TAG_PGSHIFT) & KASAN_TAG_MASK;
-		tag ^= 0xff;
+		tag ^= KASAN_TAG_KERNEL;
 	}
 
 	return tag;
@@ -1705,7 +1705,7 @@ static inline void page_kasan_tag_set(struct page *page, u8 tag)
 	if (!kasan_enabled())
 		return;
 
-	tag ^= 0xff;
+	tag ^= KASAN_TAG_KERNEL;
 	old_flags = READ_ONCE(page->flags);
 	do {
 		flags = old_flags;
@@ -1724,7 +1724,7 @@ static inline void page_kasan_tag_reset(struct page *page)
 
 static inline u8 page_kasan_tag(const struct page *page)
 {
-	return 0xff;
+	return KASAN_TAG_KERNEL;
 }
 
 static inline void page_kasan_tag_set(struct page *page, u8 tag) { }
diff --git a/include/linux/mmzone.h b/include/linux/mmzone.h
index 0c5da9141983..c139fb3d862d 100644
--- a/include/linux/mmzone.h
+++ b/include/linux/mmzone.h
@@ -1166,7 +1166,6 @@ static inline bool zone_is_empty(struct zone *zone)
 #define NODES_MASK		((1UL << NODES_WIDTH) - 1)
 #define SECTIONS_MASK		((1UL << SECTIONS_WIDTH) - 1)
 #define LAST_CPUPID_MASK	((1UL << LAST_CPUPID_SHIFT) - 1)
-#define KASAN_TAG_MASK		((1UL << KASAN_TAG_WIDTH) - 1)
 #define ZONEID_MASK		((1UL << ZONEID_SHIFT) - 1)
 
 static inline enum zone_type page_zonenum(const struct page *page)
diff --git a/include/linux/page-flags-layout.h b/include/linux/page-flags-layout.h
index 760006b1c480..b2cc4cb870e0 100644
--- a/include/linux/page-flags-layout.h
+++ b/include/linux/page-flags-layout.h
@@ -3,6 +3,7 @@
 #define PAGE_FLAGS_LAYOUT_H
 
 #include <linux/numa.h>
+#include <linux/kasan-tags.h>
 #include <generated/bounds.h>
 
 /*
@@ -72,14 +73,6 @@
 #define NODE_NOT_IN_PAGE_FLAGS	1
 #endif
 
-#if defined(CONFIG_KASAN_SW_TAGS)
-#define KASAN_TAG_WIDTH 8
-#elif defined(CONFIG_KASAN_HW_TAGS)
-#define KASAN_TAG_WIDTH 4
-#else
-#define KASAN_TAG_WIDTH 0
-#endif
-
 #ifdef CONFIG_NUMA_BALANCING
 #define LAST__PID_SHIFT 8
 #define LAST__PID_MASK  ((1 << LAST__PID_SHIFT)-1)
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/788b6f9a1f5adf2b69564489d16de436ba1bdc3c.1755004923.git.maciej.wieczor-retman%40intel.com.

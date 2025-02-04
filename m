Return-Path: <kasan-dev+bncBCMMDDFSWYCBBUVARG6QMGQE7EAKUGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113b.google.com (mail-yw1-x113b.google.com [IPv6:2607:f8b0:4864:20::113b])
	by mail.lfdr.de (Postfix) with ESMTPS id ABD26A278A4
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Feb 2025 18:37:25 +0100 (CET)
Received: by mail-yw1-x113b.google.com with SMTP id 00721157ae682-6f980a6feabsf7114987b3.0
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Feb 2025 09:37:25 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738690644; cv=pass;
        d=google.com; s=arc-20240605;
        b=cFzQv6SQxYq80UGjSI9bCJUBFuaxQ/8MWAdF4MoKbLsv/Asn+/UGK6pIU6CUSuldt/
         2XvxpPTAd4pcGYFprwp7X/r4w1o6P70W0r1WMESZ7VzCvJaCY4LPPk8tWtiUaS9KTYC4
         QAiWwMFjtN5UY9n0lgbeyOh/Ez3i8yy4tgVUnjurPk185Rk5WK9ZVLARTXteyG7pMC1c
         9pjy1pjmKguOoIfmY9RzFBKCXkodf7oE2i9UeT+aEHooPLhhCTCzUrQKFY6fYUx8Y9B9
         0MqNuF3vxpxDjdYJxAsNX8Nbc/Uik9BvqDCRZzRrIbYD4geztAd5NMJYUz9Fx2RtQXGR
         TYQA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Bk6a4+1tGLwk6tfvtWoa3Pdx4xdIshD9AK/LlO/8EZo=;
        fh=EwJbLgZDqhNpmbj0H4pCDr0crJgpfBMgMLiiDkEiEqk=;
        b=jgbZeqHRkQufG5RtFVSW6CEEYgxCs/4Dn8eQzpvMh2gBxgy1SuOUd269RyhESf9lvS
         ZALi9dIdgfTTJW701mEPTLecFnYOECxn0pSn5pmiw0NKIgcugbf7KKf7NI/aGvDMDrR/
         5xxdDvposD0pw8WmmEKl198Ow6RRX6f6+f8KyHkjuaOLm9Toz4Fr0OFK1PcGRkJLTXn6
         Zw+lJ49FlyUgg1cNDdpTK78HeyTXQY+zYVtNT2pt1jTawZk0SCnQqo4bzY19j1+EpOus
         fhuSOxxwFSJTMHhAjp8QvdzL8UibwL7RL8jpp78AwrsrqR8VVbixj67WuLCH54Ag0tRO
         8cKQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=gV4EEFEv;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.20 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738690644; x=1739295444; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Bk6a4+1tGLwk6tfvtWoa3Pdx4xdIshD9AK/LlO/8EZo=;
        b=UU0weUJgXjY55Uu5CtYQdkXxS/8MW+LdFhQAiH3/zAesb2XJKZP+JqPJhGz15K/Yqs
         B3akB52/8l/QaT8Y4T9whgJUOl8ZggePJ8GzlA+RHRTErTDkjKpVItSflq8V5y5w2Qj5
         oVpLxGczmKQ3CtrSQtO7wLwiGS0a+orgxAWt4kyCSJNPSqNJ9BPbZvfEKcnFaDFuKFbl
         yF2NttdPqy03pygBAYi2ziQZdtgZ1mLUa7eRMekoRE29OYvxHGQXiruoJgvUZbdM3k2G
         iBRq25LJ/P6qZfu/FjKCpN+BxdIR/HYnYUxwUrH1ICfDx0Jyd+kfwM9MuUZx6nI8j4V/
         Eb2w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738690644; x=1739295444;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Bk6a4+1tGLwk6tfvtWoa3Pdx4xdIshD9AK/LlO/8EZo=;
        b=H01lGmt2i1R+7uVAxbhneap6uVZPlC8UlaUXFa3I+Q3M21lhnsiP2iYKTz6TZR/9Ih
         PkrTKFsiaRbsNQOmCHqw7ZK9xhh3kD4/WxM0nKTTDPvNiQGDeNId7+x4/h6ii3TVl/G2
         jOS/hFK6KlBo5Ptz6uZ6dQVMzaoT5FMMuQcG6NLUUS7Uef8p7Sxfi4szoeBWbSp4JaO1
         ugz96i+RmxGX+lYn7jL3BFdnBoKoi+vZMGIyftNn6fogd+b2qEE3VV8W2aPJjhq+vZSu
         qquC7BIa4wIPTcnylPRYmflVWrXSmoHN7qbc3nDW25oUnIMNC9vjlBT6Qq9NeP4aShuS
         XASg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCURlW5/4VQZR9ODiakBA2ktdCUXZ6bS+WGs+d7AadolCLx8xQej7kmd90z/HVy1uFe8/9SXKw==@lfdr.de
X-Gm-Message-State: AOJu0YyEsWEMVLA4dyip0vu0wVjOlHjeABVOF02FJ+azsbyXtAoF0l43
	rIzIhrXT3dpL388Cw9iHk6IcdXRGAQj6It02DUAL399u8TZNh4O8
X-Google-Smtp-Source: AGHT+IGnuEFpG3iFzrEHuD0lzSNhlVwV5X6Dw3cruSsf7IerxsXx7pOSmkN5jFNwhKOpDhWZRVRalg==
X-Received: by 2002:a05:6902:18cb:b0:e58:1249:c538 with SMTP id 3f1490d57ef6-e58a4a9c6ecmr18524434276.9.1738690642686;
        Tue, 04 Feb 2025 09:37:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:aa42:0:b0:e5b:1425:c431 with SMTP id 3f1490d57ef6-e5b1425c650ls319406276.0.-pod-prod-09-us;
 Tue, 04 Feb 2025 09:37:21 -0800 (PST)
X-Received: by 2002:a05:690c:708d:b0:6f9:7801:7b2b with SMTP id 00721157ae682-6f9780192f9mr39617117b3.35.1738690641200;
        Tue, 04 Feb 2025 09:37:21 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738690641; cv=none;
        d=google.com; s=arc-20240605;
        b=Gu1TtUFGOZzCOFC65YFIQJK6WS2v2Wrmc+8y3ku5mrBZiztm9N90ZM+w3LCJR22j8J
         G61pIIrfCFAOjp1F3+TsLQF9/Vr92b7o8V+0oiQe47L+hRLiT94PCsCpZulGYd0qlxAQ
         lKKB+ygzgSQbo89CsMUgrVXYW4x+Hthq6hCxDPN8G2Y9EQBjOQ9KBHMXp8TcVYPNjzU4
         a/WQdNHVF+oqcP4clwhXB6/vsFsczkazCZ4Yid3imZzrR7T/dvto2UjQD6tfJkPXeoA+
         NaDNJJcoyusGG9cc8j3nEy5JVMNynVywrLZcb1MhZlb9jMQLTbZMNbqqOrxynJtg4sY6
         1l8A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=AJ+KNrmQGw87u/Lv3sW/ixn2Pc83/zgfJdm0b3G7QSs=;
        fh=myKcqxhIRjMnoyrCVROunGJsGQztaP+cwVmDG62got8=;
        b=HtZQDWOLOGQhYyqPOAQUa3ePJ+LGVSwxhk/lBgRGYJzLvSl+4RkkBHUJEn5uD7Kg1P
         aUst6vDict/icxv+Onie4xVdIualvogEEdg4G5HMA//hEFSyowo1xzKclsgiolcXxHv1
         TN6rTlmQXDgrDS7oOk3H+YaahR4bGAdhk4IGHKEDcibV/zvClg+GnTUr87Qfi6uEWyZo
         EglYsuRRFfwbPPw0MnohsPIOdeMbQ+gQNrSMl7bqAcDeC0veaZpSvutMTR5Eh4Dxjp+Z
         puvkxwDwaytA8+sosr3yxCl02EkoC7F5qdkHt/CSxe+5DXdanVnQFJJTl4jZ+ms++ScL
         eXgQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=gV4EEFEv;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.20 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.20])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-6f8c47c306dsi5993657b3.3.2025.02.04.09.37.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 04 Feb 2025 09:37:21 -0800 (PST)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.20 as permitted sender) client-ip=198.175.65.20;
X-CSE-ConnectionGUID: xOUEIO4RR/qS5hpELhY8Qg==
X-CSE-MsgGUID: p+DeApZzSLOe0V+bs9tObw==
X-IronPort-AV: E=McAfee;i="6700,10204,11336"; a="38931113"
X-IronPort-AV: E=Sophos;i="6.13,259,1732608000"; 
   d="scan'208";a="38931113"
Received: from orviesa001.jf.intel.com ([10.64.159.141])
  by orvoesa112.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Feb 2025 09:37:19 -0800
X-CSE-ConnectionGUID: OH9xu6cPRWustG/bFhP1dw==
X-CSE-MsgGUID: vAuLaG4TRpmkRprgXY7/Og==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.12,224,1728975600"; 
   d="scan'208";a="147867096"
Received: from mjarzebo-mobl1.ger.corp.intel.com (HELO wieczorr-mobl1.intel.com) ([10.245.244.61])
  by smtpauth.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Feb 2025 09:37:04 -0800
From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
To: luto@kernel.org,
	xin@zytor.com,
	kirill.shutemov@linux.intel.com,
	palmer@dabbelt.com,
	tj@kernel.org,
	andreyknvl@gmail.com,
	brgerst@gmail.com,
	ardb@kernel.org,
	dave.hansen@linux.intel.com,
	jgross@suse.com,
	will@kernel.org,
	akpm@linux-foundation.org,
	arnd@arndb.de,
	corbet@lwn.net,
	maciej.wieczor-retman@intel.com,
	dvyukov@google.com,
	richard.weiyang@gmail.com,
	ytcoode@gmail.com,
	tglx@linutronix.de,
	hpa@zytor.com,
	seanjc@google.com,
	paul.walmsley@sifive.com,
	aou@eecs.berkeley.edu,
	justinstitt@google.com,
	jason.andryuk@amd.com,
	glider@google.com,
	ubizjak@gmail.com,
	jannh@google.com,
	bhe@redhat.com,
	vincenzo.frascino@arm.com,
	rafael.j.wysocki@intel.com,
	ndesaulniers@google.com,
	mingo@redhat.com,
	catalin.marinas@arm.com,
	junichi.nomura@nec.com,
	nathan@kernel.org,
	ryabinin.a.a@gmail.com,
	dennis@kernel.org,
	bp@alien8.de,
	kevinloughlin@google.com,
	morbo@google.com,
	dan.j.williams@intel.com,
	julian.stecklina@cyberus-technology.de,
	peterz@infradead.org,
	cl@linux.com,
	kees@kernel.org
Cc: kasan-dev@googlegroups.com,
	x86@kernel.org,
	linux-arm-kernel@lists.infradead.org,
	linux-riscv@lists.infradead.org,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	llvm@lists.linux.dev,
	linux-doc@vger.kernel.org
Subject: [PATCH 13/15] x86: runtime_const used for KASAN_SHADOW_END
Date: Tue,  4 Feb 2025 18:33:54 +0100
Message-ID: <5d0f9dbd0f7c2326229f2a1f3dcedd46842a9615.1738686764.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.47.1
In-Reply-To: <cover.1738686764.git.maciej.wieczor-retman@intel.com>
References: <cover.1738686764.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=gV4EEFEv;       spf=pass
 (google.com: domain of maciej.wieczor-retman@intel.com designates
 198.175.65.20 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
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

On x86, generic KASAN is setup in a way that needs a single
KASAN_SHADOW_OFFSET value for both 4 and 5 level paging. It's required
to facilitate boot time switching and it's a compiler ABI so it can't be
changed during runtime.

Software tag-based mode doesn't tie shadow start and end to any linear
addresses as part of the compiler ABI so it can be changed during
runtime. This notion, for KASAN purposes, allows to optimize out macros
such us pgtable_l5_enabled() which would otherwise be used in every
single KASAN related function.

Use runtime_const infrastructure with pgtable_l5_enabled() to initialize
the end address of KASAN's shadow address space. It's a good choice
since in software tag based mode KASAN_SHADOW_OFFSET and
KASAN_SHADOW_END refer to the same value and the offset in
kasan_mem_to_shadow() is a signed negative value.

Setup KASAN_SHADOW_END values so that they're aligned to 4TB in 4-level
paging mode and to 2PB in 5-level paging mode. Also update x86 memory
map documentation.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
 Documentation/arch/x86/x86_64/mm.rst |  6 ++++--
 arch/x86/Kconfig                     |  3 +--
 arch/x86/include/asm/kasan.h         | 14 +++++++++++++-
 arch/x86/kernel/vmlinux.lds.S        |  1 +
 arch/x86/mm/kasan_init_64.c          |  5 ++++-
 5 files changed, 23 insertions(+), 6 deletions(-)

diff --git a/Documentation/arch/x86/x86_64/mm.rst b/Documentation/arch/x86/x86_64/mm.rst
index 35e5e18c83d0..4e8c04d71a13 100644
--- a/Documentation/arch/x86/x86_64/mm.rst
+++ b/Documentation/arch/x86/x86_64/mm.rst
@@ -48,7 +48,8 @@ Complete virtual memory map with 4-level page tables
    ffffe90000000000 |  -23    TB | ffffe9ffffffffff |    1 TB | ... unused hole
    ffffea0000000000 |  -22    TB | ffffeaffffffffff |    1 TB | virtual memory map (vmemmap_base)
    ffffeb0000000000 |  -21    TB | ffffebffffffffff |    1 TB | ... unused hole
-   ffffec0000000000 |  -20    TB | fffffbffffffffff |   16 TB | KASAN shadow memory
+   ffffec0000000000 |  -20    TB | fffffbffffffffff |   16 TB | KASAN shadow memory (generic mode)
+   fffff80000000000 |   -8    TB | fffffc0000000000 |    4 TB | KASAN shadow memory (software tag-based mode)
   __________________|____________|__________________|_________|____________________________________________________________
                                                               |
                                                               | Identical layout to the 56-bit one from here on:
@@ -107,7 +108,8 @@ Complete virtual memory map with 5-level page tables
    ffd2000000000000 |  -11.5  PB | ffd3ffffffffffff |  0.5 PB | ... unused hole
    ffd4000000000000 |  -11    PB | ffd5ffffffffffff |  0.5 PB | virtual memory map (vmemmap_base)
    ffd6000000000000 |  -10.5  PB | ffdeffffffffffff | 2.25 PB | ... unused hole
-   ffdf000000000000 |   -8.25 PB | fffffbffffffffff |   ~8 PB | KASAN shadow memory
+   ffdf000000000000 |   -8.25 PB | fffffbffffffffff |   ~8 PB | KASAN shadow memory (generic mode)
+   ffe8000000000000 |   -6    PB | fff0000000000000 |    2 PB | KASAN shadow memory (software tag-based mode)
   __________________|____________|__________________|_________|____________________________________________________________
                                                               |
                                                               | Identical layout to the 47-bit one from here on:
diff --git a/arch/x86/Kconfig b/arch/x86/Kconfig
index 7b9a7e8f39ac..dfec7bc692d4 100644
--- a/arch/x86/Kconfig
+++ b/arch/x86/Kconfig
@@ -392,8 +392,7 @@ config AUDIT_ARCH
 
 config KASAN_SHADOW_OFFSET
 	hex
-	depends on KASAN
-	default 0xdffffc0000000000
+	default 0xdffffc0000000000 if KASAN_GENERIC
 
 config HAVE_INTEL_TXT
 	def_bool y
diff --git a/arch/x86/include/asm/kasan.h b/arch/x86/include/asm/kasan.h
index f7a8d3763615..79151356d5f2 100644
--- a/arch/x86/include/asm/kasan.h
+++ b/arch/x86/include/asm/kasan.h
@@ -5,7 +5,7 @@
 #include <linux/const.h>
 #include <linux/kasan-tags.h>
 #include <linux/types.h>
-#define KASAN_SHADOW_OFFSET _AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
+
 #define KASAN_SHADOW_SCALE_SHIFT 3
 
 /*
@@ -14,6 +14,8 @@
  * for kernel really starts from compiler's shadow offset +
  * 'kernel address space start' >> KASAN_SHADOW_SCALE_SHIFT
  */
+#ifdef CONFIG_KASAN_GENERIC
+#define KASAN_SHADOW_OFFSET _AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
 #define KASAN_SHADOW_START      (KASAN_SHADOW_OFFSET + \
 					((-1UL << __VIRTUAL_MASK_SHIFT) >> \
 						KASAN_SHADOW_SCALE_SHIFT))
@@ -24,12 +26,22 @@
 #define KASAN_SHADOW_END        (KASAN_SHADOW_START + \
 					(1ULL << (__VIRTUAL_MASK_SHIFT - \
 						  KASAN_SHADOW_SCALE_SHIFT)))
+#endif
+
 
 #ifndef __ASSEMBLY__
+#include <asm/runtime-const.h>
 #include <linux/bitops.h>
 #include <linux/bitfield.h>
 #include <linux/bits.h>
 
+#ifdef CONFIG_KASAN_SW_TAGS
+extern unsigned long KASAN_SHADOW_END_RC;
+#define KASAN_SHADOW_END	runtime_const_ptr(KASAN_SHADOW_END_RC)
+#define KASAN_SHADOW_OFFSET	KASAN_SHADOW_END
+#define KASAN_SHADOW_START	(KASAN_SHADOW_END - ((UL(1)) << (__VIRTUAL_MASK_SHIFT - KASAN_SHADOW_SCALE_SHIFT)))
+#endif
+
 #define arch_kasan_set_tag(addr, tag)	__tag_set(addr, tag)
 #define arch_kasan_reset_tag(addr)	__tag_reset(addr)
 #define arch_kasan_get_tag(addr)	__tag_get(addr)
diff --git a/arch/x86/kernel/vmlinux.lds.S b/arch/x86/kernel/vmlinux.lds.S
index feb8102a9ca7..46183f7439c9 100644
--- a/arch/x86/kernel/vmlinux.lds.S
+++ b/arch/x86/kernel/vmlinux.lds.S
@@ -359,6 +359,7 @@ SECTIONS
 
 	RUNTIME_CONST_VARIABLES
 	RUNTIME_CONST(ptr, USER_PTR_MAX)
+	RUNTIME_CONST(ptr, KASAN_SHADOW_END_RC)
 
 	. = ALIGN(PAGE_SIZE);
 
diff --git a/arch/x86/mm/kasan_init_64.c b/arch/x86/mm/kasan_init_64.c
index 55d468d83682..0f8190e0e5f6 100644
--- a/arch/x86/mm/kasan_init_64.c
+++ b/arch/x86/mm/kasan_init_64.c
@@ -358,6 +358,9 @@ void __init kasan_init(void)
 	int i;
 
 	memcpy(early_top_pgt, init_top_pgt, sizeof(early_top_pgt));
+	unsigned long KASAN_SHADOW_END_RC = pgtable_l5_enabled() ? 0xfff0000000000000 : 0xfffffc0000000000;
+
+	runtime_const_init(ptr, KASAN_SHADOW_END_RC);
 
 	/*
 	 * We use the same shadow offset for 4- and 5-level paging to
@@ -372,7 +375,7 @@ void __init kasan_init(void)
 	 * bunch of things like kernel code, modules, EFI mapping, etc.
 	 * We need to take extra steps to not overwrite them.
 	 */
-	if (pgtable_l5_enabled()) {
+	if (pgtable_l5_enabled() && !IS_ENABLED(CONFIG_KASAN_SW_TAGS)) {
 		void *ptr;
 
 		ptr = (void *)pgd_page_vaddr(*pgd_offset_k(KASAN_SHADOW_END));
-- 
2.47.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/5d0f9dbd0f7c2326229f2a1f3dcedd46842a9615.1738686764.git.maciej.wieczor-retman%40intel.com.

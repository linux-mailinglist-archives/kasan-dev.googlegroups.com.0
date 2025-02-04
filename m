Return-Path: <kasan-dev+bncBCMMDDFSWYCBBTE7RG6QMGQEG5CF2VA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63c.google.com (mail-pl1-x63c.google.com [IPv6:2607:f8b0:4864:20::63c])
	by mail.lfdr.de (Postfix) with ESMTPS id C0707A27884
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Feb 2025 18:35:11 +0100 (CET)
Received: by mail-pl1-x63c.google.com with SMTP id d9443c01a7336-2166f9f52fbsf195359725ad.2
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Feb 2025 09:35:11 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738690509; cv=pass;
        d=google.com; s=arc-20240605;
        b=I4iD8l/txpxzABZVk9o0ulUItoQPDAmbnbmusHmFRKLFYFL0fUrOiqVYGlbq0DgTe5
         vVXxMTtm+RvWbZ/hmVp48xM8WZVCfSSc9JgWK6N+CB5Zy7nNHPApRFcQNQKjRebN6EuA
         J8rO7Un2P7ZldP810lDgNpiL4e17Vm7wh80YL05q8ZyDPROCQYHKpudyjXSWb0VBLQzk
         VzHalPXsoSPckE9wk/2UsB41IGyZjnHaDKFoQxa/S4vh9zcFozdLtd9pzPWa5QMmV1Wd
         kD9p+k5QS/Es0B4hMki7oqfdsoc3KjjV2qctqAajMLu+40L3tZXTCpSN4awUWlq5B8ne
         H/dg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=2jLHecQwNQMuJ43MrBifVhdMNOEyRMfoVxovYseQbQg=;
        fh=GqirwiGbQpgMTdxcReOB9bf94mvYt93dUxuyS7+waik=;
        b=S2ilcedD8/LCaCSyVCOD9+LKSGwYEFU4mOq6KjLkC4EOoPoFqw5vv9+IDMwc7i7Snh
         37KV2AlVXPH46axwwMMQSqYFrkt/8229Og9vGbTJOXUIp0hJO6TRG9ZfTrd6xl12+kMr
         lsBrYjzv15KV3I13vKT6n0FJwEkU1KrIUVqKD61XGDRJF86IDbLhv+BbqkecRegjVgrP
         kC0/SHEURZ8qoTeY7mjHmanezQ9cFLQHrVtN3SywWZf6jx9mLYMEdkgQEtJqnu6r4g7x
         ngJHJirZ/i4CD0OC1NQfP4U0HNsdCEbbRf9sqxBkHzrwTJrzvXKFRsl4c1XgIiLol5Vz
         tocw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=TwwfPvFy;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.20 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738690509; x=1739295309; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=2jLHecQwNQMuJ43MrBifVhdMNOEyRMfoVxovYseQbQg=;
        b=ITt+KExR2DkB4iyTHU2mmcM2Nzer8zhjcUOFRaxW8y3GYWfNL6tSnIu3sCsYZB0TMQ
         97B4GiTjP5+jk+T0msoS7wxG8JUEAahcw9N0l6KrnAXBItkDsH1Qkltmh2JTeflMR+X+
         ekYKL9xvif82A8X4ulcMMrP8bK6CmCYlU3KPvJQY0FapkGw0ykmoKMWCalY2e7DYsyiu
         VYM8QW4RHiCGzztOpDgRRgiN1qpRNeFnDiBgxi7IU2iYxzNOXxTz+1boaRQiefhl0Ysd
         P/xw9rBssxkUANjEwF1BgJStRRKvGC/BWIQmYFwp0lrGWoZtz05Si+BiPGqkXH7R3I0J
         isEw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738690509; x=1739295309;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=2jLHecQwNQMuJ43MrBifVhdMNOEyRMfoVxovYseQbQg=;
        b=Eq+YhKE3d37Zy3DrYKZZ7VxzMUs7XnSvN/r51om+IktBPpQWUJKz0TKcd+lgP3DxYN
         3ys7WRIvnFGU16GPB/wQvlC3+NYgUvW+BTtyAOGvkGxSfFaFVXtfw0uFONMxIOyIZ7BD
         CiOR9pJxZW86lRXJgZ5Z0uvR9Cj0ekorsjdgSG4vNRQBaGYDIvgnpdHn1MVD9Hqv/IK1
         cD6flxzBeKCSrWdjuyWKdKcRJvf+wsX7DzWEF26RBGUKSVixs1gkYfYmFOfMmZIjZrcG
         1mCRccB+htGqpoPKRH/IbwSJED9DIMiyrmUna5RIdANGQOjHTIKqpDnISCa2oR0ovNZI
         +yRQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVtkkhPy0BwQ6ULLDdONqY8+N+n1e81HpwDL0e+wWVByeRs2Npimgy2wY2JVk27dv7vvDplhA==@lfdr.de
X-Gm-Message-State: AOJu0YyMSUDF9vNiq+6AlRqRTNLtKqyoJMBqH+EtB1nPa5e4zGxLywy6
	J/z9wKJwddnTRxF2oe9wJ+tZVM/PCXCnWgUPkJ2qBGl0UibyLyMR
X-Google-Smtp-Source: AGHT+IGo04+OvFEyc4DApujRBEbuF6AvXdFFWWH+pXt3LFBkUSbAsG8KneoP+cGUr1QALXN6mcQP8A==
X-Received: by 2002:a17:903:298f:b0:21f:1549:a55a with SMTP id d9443c01a7336-21f1549a709mr3316745ad.1.1738690509009;
        Tue, 04 Feb 2025 09:35:09 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:f68c:b0:216:59e6:95c4 with SMTP id
 d9443c01a7336-21f14fa56fbls1138105ad.0.-pod-prod-03-us; Tue, 04 Feb 2025
 09:35:07 -0800 (PST)
X-Received: by 2002:a17:902:dace:b0:21a:8d70:3865 with SMTP id d9443c01a7336-21dd7c653cdmr442366235ad.14.1738690507294;
        Tue, 04 Feb 2025 09:35:07 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738690507; cv=none;
        d=google.com; s=arc-20240605;
        b=SkRUiGh1MbqUSVkMTEjWjFCBDEaegfFXwjUqsQZOOmHfOQx80gBKutAdK9Jdz0urzp
         UbWLXqoTiu+LivMZUEdsNoqREOLtgsbrN7j5kJ78owZ685SM+w0yyiJlzNyuzzJ9iIWO
         +R3A3Y4HW7mSbn7Lb/5wFR7886L4/zejut4Y8VEuFcNoW8/qw73jmKn6PKCBTh5R/qib
         pujc4WNnbI7r5uLlJKDPmCLYHKkI9gpZoE81P0qer3D3sFZdExrhnAW/rItiZaY5l7YA
         60eHlLPfjkScZsEHhei8wrpfC2x94zUouLqrdvDyey3oy6yVAVfx4S5O5dxa+Zrw4/cD
         CQlA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=pvxPfnrd9zxeTvTnimcFo2KrbNr0G4HQhkaUqyV3B7o=;
        fh=myKcqxhIRjMnoyrCVROunGJsGQztaP+cwVmDG62got8=;
        b=Yp+pSp9cExw+ksaTfOsHd9RCUqCSLCluXc7r3UmQOXggd6YMkH3Ie30LSXYwQJ8uZB
         skvLXNL9XMt9dHkblFF9Ag6l33r5pYyPMnpD3CeGlxABsbSUOib/QX3XNKzhYMAXEuT8
         /aIu5PjaFG0CasT5tXciambs0UcX6Fcg0GGZC+j1AG+IeY84AJ0wZZjKAvZjYnLmMWSn
         6GJnN56481OLhKhYp65mf2NMiYmYIIP//AWaL2mUYDwhVf9xoqYggZUVpAOoMb+D/4D7
         Wliz9BnQiA/NAjQb+oMN0t3lb94CXpxZN3GmmNQMwp7+fnz0Q8AIpu7nO89mqK1w3Hfj
         1g/Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=TwwfPvFy;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.20 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.20])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-21de32fcbd3si5631485ad.8.2025.02.04.09.35.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 04 Feb 2025 09:35:07 -0800 (PST)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.20 as permitted sender) client-ip=198.175.65.20;
X-CSE-ConnectionGUID: qiQEoSGaTMi0adJVhltKwQ==
X-CSE-MsgGUID: 20dRh6feR6KaPpWW2GY4mQ==
X-IronPort-AV: E=McAfee;i="6700,10204,11336"; a="38930389"
X-IronPort-AV: E=Sophos;i="6.13,259,1732608000"; 
   d="scan'208";a="38930389"
Received: from orviesa001.jf.intel.com ([10.64.159.141])
  by orvoesa112.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Feb 2025 09:35:04 -0800
X-CSE-ConnectionGUID: eBbq5MWaSZONJhS+dGPi8A==
X-CSE-MsgGUID: mjasgO5WTcSBmxRL24BE0w==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.12,224,1728975600"; 
   d="scan'208";a="147866217"
Received: from mjarzebo-mobl1.ger.corp.intel.com (HELO wieczorr-mobl1.intel.com) ([10.245.244.61])
  by smtpauth.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Feb 2025 09:34:49 -0800
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
Subject: [PATCH 02/15] kasan: Tag checking with dense tag-based mode
Date: Tue,  4 Feb 2025 18:33:43 +0100
Message-ID: <8f790bb7e166c1ea2e5003318149eb1d7aba3596.1738686764.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.47.1
In-Reply-To: <cover.1738686764.git.maciej.wieczor-retman@intel.com>
References: <cover.1738686764.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=TwwfPvFy;       spf=pass
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

In KASAN's tag-based mode (arm64) when a memory access occurs, the tag
stored in the top 8 bits of the pointer is compared with tags saved in
the region of the shadow memory that maps to memory the pointer points
to. If any of the tags in the shadow memory region do not match the one
stored in the pointer an error report is generated.

With the introduction of the dense mode, tags won't necessarily occupy
whole bytes of shadow memory if the previously allocated memory wasn't
aligned to 32 bytes - which is the coverage of one shadow byte.

Add an alternative implementation of kasan_check_range() that performs
special checks on first and last bytes of shadow memory ranges if the
originally allocated memory wasn't aligned to 32 bytes.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
 include/linux/kasan.h     | 47 +++++++++++++++-------
 mm/kasan/Makefile         |  3 ++
 mm/kasan/dense.c          | 83 +++++++++++++++++++++++++++++++++++++++
 mm/kasan/kasan.h          |  2 +-
 mm/kasan/report.c         |  2 +-
 mm/kasan/report_sw_tags.c | 12 ++----
 mm/kasan/sw_tags.c        |  8 ++++
 7 files changed, 133 insertions(+), 24 deletions(-)
 create mode 100644 mm/kasan/dense.c

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index ea0f5acd875b..5a3e9bec21c2 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -33,6 +33,20 @@ typedef unsigned int __bitwise kasan_vmalloc_flags_t;
 
 #include <linux/pgtable.h>
 
+#ifndef kasan_mem_to_shadow
+static inline void *kasan_mem_to_shadow(const void *addr)
+{
+	void *scaled;
+
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
+		scaled = (void *)((unsigned long)addr >> KASAN_SHADOW_SCALE_SHIFT);
+	else
+		scaled = (void *)((long)addr >> KASAN_SHADOW_SCALE_SHIFT);
+
+	return KASAN_SHADOW_OFFSET + scaled;
+}
+#endif
+
 /* Software KASAN implementations use shadow memory. */
 
 #ifdef CONFIG_KASAN_SW_TAGS_DENSE
@@ -53,6 +67,25 @@ static inline u8 kasan_dense_tag(u8 tag)
 
 #define KASAN_GRANULE_SIZE	(1UL << KASAN_GRANULE_SHIFT)
 
+#ifdef CONFIG_KASAN_SW_TAGS_DENSE
+static inline u8 kasan_get_shadow_tag(const void *ptr)
+{
+	u8 shadow_byte = *(u8 *)kasan_mem_to_shadow(ptr);
+	unsigned long addr = (unsigned long)ptr;
+	int shift;
+
+	shift = !!(addr & KASAN_GRANULE_SIZE) * KASAN_TAG_WIDTH;
+	shadow_byte >>= shift;
+
+	return shadow_byte & KASAN_TAG_KERNEL;
+}
+#else
+static inline u8 kasan_get_shadow_tag(const void *addr)
+{
+	return (*(u8 *)kasan_mem_to_shadow(addr));
+}
+#endif
+
 #ifdef CONFIG_KASAN_SW_TAGS
 /* This matches KASAN_TAG_INVALID. */
 #define KASAN_SHADOW_INIT 0xFE
@@ -73,20 +106,6 @@ extern p4d_t kasan_early_shadow_p4d[MAX_PTRS_PER_P4D];
 int kasan_populate_early_shadow(const void *shadow_start,
 				const void *shadow_end);
 
-#ifndef kasan_mem_to_shadow
-static inline void *kasan_mem_to_shadow(const void *addr)
-{
-	void *scaled;
-
-	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
-		scaled = (void *)((unsigned long)addr >> KASAN_SHADOW_SCALE_SHIFT);
-	else
-		scaled = (void *)((long)addr >> KASAN_SHADOW_SCALE_SHIFT);
-
-	return KASAN_SHADOW_OFFSET + scaled;
-}
-#endif
-
 int kasan_add_zero_shadow(void *start, unsigned long size);
 void kasan_remove_zero_shadow(void *start, unsigned long size);
 
diff --git a/mm/kasan/Makefile b/mm/kasan/Makefile
index b88543e5c0cc..3a460abd4c18 100644
--- a/mm/kasan/Makefile
+++ b/mm/kasan/Makefile
@@ -5,6 +5,7 @@ KCOV_INSTRUMENT := n
 
 # Disable ftrace to avoid recursion.
 CFLAGS_REMOVE_common.o = $(CC_FLAGS_FTRACE)
+CFLAGS_REMOVE_dense.o = $(CC_FLAGS_FTRACE)
 CFLAGS_REMOVE_generic.o = $(CC_FLAGS_FTRACE)
 CFLAGS_REMOVE_init.o = $(CC_FLAGS_FTRACE)
 CFLAGS_REMOVE_quarantine.o = $(CC_FLAGS_FTRACE)
@@ -24,6 +25,7 @@ CC_FLAGS_KASAN_RUNTIME += -fno-stack-protector
 CC_FLAGS_KASAN_RUNTIME += -DDISABLE_BRANCH_PROFILING
 
 CFLAGS_common.o := $(CC_FLAGS_KASAN_RUNTIME)
+CFLAGS_dense.o := $(CC_FLAGS_KASAN_RUNTIME)
 CFLAGS_generic.o := $(CC_FLAGS_KASAN_RUNTIME)
 CFLAGS_init.o := $(CC_FLAGS_KASAN_RUNTIME)
 CFLAGS_quarantine.o := $(CC_FLAGS_KASAN_RUNTIME)
@@ -49,6 +51,7 @@ RUSTFLAGS_kasan_test_rust.o := $(RUSTFLAGS_KASAN)
 CFLAGS_kasan_test_module.o := $(CFLAGS_KASAN_TEST)
 
 obj-y := common.o report.o
+obj-$(CONFIG_KASAN_SW_TAGS_DENSE) += dense.o
 obj-$(CONFIG_KASAN_GENERIC) += init.o generic.o report_generic.o shadow.o quarantine.o
 obj-$(CONFIG_KASAN_HW_TAGS) += hw_tags.o report_hw_tags.o tags.o report_tags.o
 obj-$(CONFIG_KASAN_SW_TAGS) += init.o report_sw_tags.o shadow.o sw_tags.o tags.o report_tags.o
diff --git a/mm/kasan/dense.c b/mm/kasan/dense.c
new file mode 100644
index 000000000000..306bbbfdce29
--- /dev/null
+++ b/mm/kasan/dense.c
@@ -0,0 +1,83 @@
+// SPDX-License-Identifier: GPL-2.0
+
+#include "kasan.h"
+
+static __always_inline bool kasan_check_range_inline(const void *addr,
+						     size_t size, bool write,
+						     unsigned long ret_ip)
+{
+	u8 *shadow_first, *shadow_last, *shadow, *shadow_first_aligned, *shadow_last_aligned;
+	u64 addr_start_aligned, addr_end_aligned;
+	u8 tag, kasan_granule_offset;
+	size_t aligned_size;
+	void *untagged_addr;
+
+	if (unlikely(size == 0))
+		return true;
+
+	if (unlikely(addr + size < addr))
+		return !kasan_report(addr, size, write, ret_ip);
+
+	tag = get_tag((const void *)addr);
+
+	/*
+	 * Ignore accesses for pointers tagged with native kernel
+	 * pointer tag to suppress false positives caused by kmap.
+	 *
+	 * Some kernel code was written to account for archs that don't keep
+	 * high memory mapped all the time, but rather map and unmap particular
+	 * pages when needed. Instead of storing a pointer to the kernel memory,
+	 * this code saves the address of the page structure and offset within
+	 * that page for later use. Those pages are then mapped and unmapped
+	 * with kmap/kunmap when necessary and virt_to_page is used to get the
+	 * virtual address of the page. For arm64 (that keeps the high memory
+	 * mapped all the time), kmap is turned into a page_address call.
+
+	 * The issue is that with use of the page_address + virt_to_page
+	 * sequence the top byte value of the original pointer gets lost (gets
+	 * set to KASAN_TAG_KERNEL).
+	 */
+	if (tag == KASAN_TAG_KERNEL)
+		return true;
+
+	untagged_addr = kasan_reset_tag((void *)round_down((u64)addr, KASAN_GRANULE_SIZE));
+	if (unlikely(!addr_has_metadata(untagged_addr)))
+		return !kasan_report(addr, size, write, ret_ip);
+
+	kasan_granule_offset = ((u64)addr & KASAN_GRANULE_MASK);
+	aligned_size = round_up(size + kasan_granule_offset, KASAN_GRANULE_SIZE);
+	shadow_first = kasan_mem_to_shadow(untagged_addr);
+	shadow_last = kasan_mem_to_shadow(untagged_addr + aligned_size);
+	addr_start_aligned = round_up((u64)untagged_addr, KASAN_SHADOW_SCALE_SIZE);
+	addr_end_aligned = round_down((u64)untagged_addr + aligned_size, KASAN_SHADOW_SCALE_SIZE);
+	shadow_first_aligned = kasan_mem_to_shadow((void *)addr_start_aligned);
+	shadow_last_aligned = kasan_mem_to_shadow((void *)addr_end_aligned);
+
+	/* Check the first unaligned tag in shadow memory. */
+	if ((u64)untagged_addr % KASAN_SHADOW_SCALE_SIZE) {
+		if (unlikely((*shadow_first >> KASAN_TAG_WIDTH) != tag))
+			return !kasan_report(addr, size, write, ret_ip);
+	}
+
+	/* Check the middle aligned part in shadow memory. */
+	for (shadow = shadow_first_aligned; shadow < shadow_last_aligned; shadow++) {
+		if (unlikely(*shadow != ((tag << KASAN_TAG_WIDTH) | tag)))
+			return !kasan_report(addr, size, write, ret_ip);
+	}
+
+	/* Check the last unaligned tag in shadow memory. */
+	if (((u64)untagged_addr + aligned_size) % KASAN_SHADOW_SCALE_SIZE) {
+		if (unlikely((*shadow_last & KASAN_TAG_MASK) != tag))
+			return !kasan_report(addr, size, write, ret_ip);
+	}
+
+	return true;
+}
+
+#if IS_ENABLED(CONFIG_KASAN_SW_TAGS_DENSE)
+bool kasan_check_range(const void *addr, size_t size, bool write,
+		       unsigned long ret_ip)
+{
+	return kasan_check_range_inline(addr, size, write, ret_ip);
+}
+#endif
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index 0e04c5e2c405..d29bd0e65020 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -183,7 +183,7 @@ static inline bool kasan_requires_meta(void)
 #define META_BYTES_PER_BLOCK 1
 #define META_BLOCKS_PER_ROW 16
 #define META_BYTES_PER_ROW (META_BLOCKS_PER_ROW * META_BYTES_PER_BLOCK)
-#define META_MEM_BYTES_PER_ROW (META_BYTES_PER_ROW * KASAN_GRANULE_SIZE)
+#define META_MEM_BYTES_PER_ROW (META_BYTES_PER_ROW * KASAN_SHADOW_SCALE_SIZE)
 #define META_ROWS_AROUND_ADDR 2
 
 #define KASAN_STACK_DEPTH 64
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index c08097715686..ee9e406b0cdb 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -436,7 +436,7 @@ static int meta_pointer_offset(const void *row, const void *addr)
 	 *    plus 1 byte for space.
 	 */
 	return 3 + (BITS_PER_LONG / 8) * 2 +
-		(addr - row) / KASAN_GRANULE_SIZE * 3 + 1;
+		(addr - row) / KASAN_SHADOW_SCALE_SIZE * 3 + 1;
 }
 
 static void print_memory_metadata(const void *addr)
diff --git a/mm/kasan/report_sw_tags.c b/mm/kasan/report_sw_tags.c
index 689e94f9fe3c..1ac5c7a9011d 100644
--- a/mm/kasan/report_sw_tags.c
+++ b/mm/kasan/report_sw_tags.c
@@ -39,7 +39,7 @@ const void *kasan_find_first_bad_addr(const void *addr, size_t size)
 	if (!addr_has_metadata(p))
 		return p;
 
-	while (p < end && tag == *(u8 *)kasan_mem_to_shadow(p))
+	while (p < end && tag == kasan_get_shadow_tag(p))
 		p += KASAN_GRANULE_SIZE;
 
 	return p;
@@ -48,7 +48,6 @@ const void *kasan_find_first_bad_addr(const void *addr, size_t size)
 size_t kasan_get_alloc_size(void *object, struct kmem_cache *cache)
 {
 	size_t size = 0;
-	u8 *shadow;
 
 	/*
 	 * Skip the addr_has_metadata check, as this function only operates on
@@ -59,13 +58,11 @@ size_t kasan_get_alloc_size(void *object, struct kmem_cache *cache)
 	 * The loop below returns 0 for freed objects, for which KASAN cannot
 	 * calculate the allocation size based on the metadata.
 	 */
-	shadow = (u8 *)kasan_mem_to_shadow(object);
 	while (size < cache->object_size) {
-		if (*shadow != KASAN_TAG_INVALID)
+		if (kasan_get_shadow_tag(object + size) != KASAN_TAG_INVALID)
 			size += KASAN_GRANULE_SIZE;
 		else
 			return size;
-		shadow++;
 	}
 
 	return cache->object_size;
@@ -78,9 +75,8 @@ void kasan_metadata_fetch_row(char *buffer, void *row)
 
 void kasan_print_tags(u8 addr_tag, const void *addr)
 {
-	u8 *shadow = (u8 *)kasan_mem_to_shadow(addr);
-
-	pr_err("Pointer tag: [%02x], memory tag: [%02x]\n", addr_tag, *shadow);
+	pr_err("Pointer tag: [%02x], memory tag: [%02x]\n", addr_tag,
+	       kasan_get_shadow_tag(addr));
 }
 
 #ifdef CONFIG_KASAN_STACK
diff --git a/mm/kasan/sw_tags.c b/mm/kasan/sw_tags.c
index 32435d33583a..7a6b8ea9bf78 100644
--- a/mm/kasan/sw_tags.c
+++ b/mm/kasan/sw_tags.c
@@ -79,6 +79,7 @@ u8 __hwasan_generate_tag(void)
 }
 EXPORT_SYMBOL(__hwasan_generate_tag);
 
+#if !IS_ENABLED(CONFIG_KASAN_SW_TAGS_DENSE)
 bool kasan_check_range(const void *addr, size_t size, bool write,
 			unsigned long ret_ip)
 {
@@ -127,17 +128,24 @@ bool kasan_check_range(const void *addr, size_t size, bool write,
 
 	return true;
 }
+#endif
 
 bool kasan_byte_accessible(const void *addr)
 {
 	u8 tag = get_tag(addr);
 	void *untagged_addr = kasan_reset_tag(addr);
 	u8 shadow_byte;
+	int shift;
 
 	if (!addr_has_metadata(untagged_addr))
 		return false;
 
 	shadow_byte = READ_ONCE(*(u8 *)kasan_mem_to_shadow(untagged_addr));
+	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS_DENSE)) {
+		shift = !!((u64)addr & BIT(KASAN_TAG_WIDTH)) * KASAN_TAG_WIDTH;
+		shadow_byte = (shadow_byte >> shift) & KASAN_TAG_KERNEL;
+	}
+
 	return tag == KASAN_TAG_KERNEL || tag == shadow_byte;
 }
 
-- 
2.47.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/8f790bb7e166c1ea2e5003318149eb1d7aba3596.1738686764.git.maciej.wieczor-retman%40intel.com.

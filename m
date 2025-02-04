Return-Path: <kasan-dev+bncBCMMDDFSWYCBBW5ARG6QMGQEVFHFZKY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id B9A39A278A7
	for <lists+kasan-dev@lfdr.de>; Tue,  4 Feb 2025 18:37:32 +0100 (CET)
Received: by mail-il1-x13f.google.com with SMTP id e9e14a558f8ab-3ce7a0ec1easf43228945ab.0
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Feb 2025 09:37:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738690651; cv=pass;
        d=google.com; s=arc-20240605;
        b=PUC+8GIcyS0ZcsVI2CIiueI/I/F80Z0dpYHS8hTZZudEeGvqT3CyjgEMjdAlmtCVDD
         YT/H3LADxwBh5qAK9Jzg7C0mYB0K0c2nKsrOrqwjWvAM9+hhr0pcoPscR7NNu5Hvc+CK
         C19pUWkFI6VQI5T1Ucvrnp3HSfObvXUrvxtZ52AEjKzyJBqtm0NUA7Ttk6SIuQgTosUG
         sq2l5ImZOySUYNXkJWUhEBaJxZZUQDITzkD9c8D57sKkiJPi6Zt0qgmNwIyn6vw0avi+
         ZFwSfj3Os3zgVY6owLLepnp/Stz4HRsAv+lX9JagpsGsaQLpzv6Z5xQ1WjU2UsjVmD8a
         D/gg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=ltlmUXfrjPzGSbpMNYWnk/VwTzSgaYOJhvEyBLorBIs=;
        fh=9YdzmDE3i0ZEe9UhNHV1Nq6bUBHY9cEEUEzT6XCzKZo=;
        b=NJoJHf/+dhHYghhKCZp7fd9XcqLcU9CmkGg2vBpzmNOXpCi/6RsZVwH4QH22+PE5A5
         biJDYJ+fyEbBTPvxQMVxoxiQbArodNRy6tyLPkL/Kk2z3FNUJVCk7FNiLNKmgOxr3RJN
         vrKAzkO0BVXhdCU7c3kA1Rufe/Ag06kitw2Gsa2u7Rt9QxhOb7eXHAU9VZ3c/8szKVSC
         G8uQg4dn0tVHZEVRAdnzaHGuEg5HWxPASw5p38VMQiUM0j7iUbcUutHzKHOk2eOXVMr+
         AsYtHEtKghnxIxJQRvWtwGkFRlnbcmqhOJpzMg2OuOdmSwmvKuc9QYQiL1U5KMzararu
         MmMg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=dleCM97N;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.20 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738690651; x=1739295451; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ltlmUXfrjPzGSbpMNYWnk/VwTzSgaYOJhvEyBLorBIs=;
        b=MYQEU4rXP++bThZtj7aeTczPMFbLEUiFO0Pb4sEb/Lf0xqHhKWC/FOiWDucpAv3bOQ
         t0lRDKdKspmUL+EwJjCAr5MRhmA+jsX6D2MEDXRhTHvBs2PYNIkOteM0f/+zwVWTM28d
         89iEhtxXgUz8493JlWyLk8ZxTVchXaTvIRoZywEG2YOfKhXvD15gczhX/Or2f78J8pTU
         4QUKtmoMhO2A1JLJGGSeJMfvsPhEA4vHI2anW6KQ0aRe1urx4Bk/AloYkZ6gPgMap3lq
         +Q3mdgyQGQIY2inOgu8pJyUcqfVRHPxPfq46mMEsLwmnBHveapsko1+w5nYEsNTXHWxk
         4Ing==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738690651; x=1739295451;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ltlmUXfrjPzGSbpMNYWnk/VwTzSgaYOJhvEyBLorBIs=;
        b=YS4f9fbfeCvY3CEpSesubAOxWE480CBeHnr0lHHUHrN3VrBCtSvDJUgypvVFD0JA7U
         cLMWW1/i2kvDiNDG8T/zgJn82jNPG9xbZ2n6kROT/xvzoO0RaD/gdhR16fiFmjR6JNDn
         OJFt+rsa1L4pMQXInfhN/9Hw3wgXOIj0sBkEgjj1omLySteKnBqZHVSBDCZRjBVXcail
         SyCXj7ypX5WNsX+dq5FOjUgOsskPEG+nKk1fQWt5+6enad4fkg4jHETcPggTWiZv7ZfF
         zNqmyRDV+RxFG0ZccdRzh+nzxwSBsQ8xk3DFhXtYTFNIbiuweD6hF9bBqm8oG5i1znGg
         5XxA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVsyEDdDUPqabf2pWNi3VunXhc13znEUtZBydeNAmg0l17LKo64nfU8bOP/gQdDTeShfh/4QA==@lfdr.de
X-Gm-Message-State: AOJu0Yza5dwPGOu+yLg3MogIjGvECkcl824pQung8j3VZn7B3RWv64Fe
	1ITz/1DRPUvhUD6gN2Ne4Oxdqkg0C/d5Udz7zNHkYO93zIYWtHrG
X-Google-Smtp-Source: AGHT+IHkCUC/tbkrAz6Ehn/sZ079zGb4bS7O80dV2vuXNjt40UAl5w45Ocn2zlG8TiJiTwZHA4+Sfg==
X-Received: by 2002:a05:6e02:3193:b0:3d0:4d76:79b8 with SMTP id e9e14a558f8ab-3d04d767d4bmr6652385ab.0.1738690651288;
        Tue, 04 Feb 2025 09:37:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:2184:b0:3a8:1477:b10a with SMTP id
 e9e14a558f8ab-3d008c3b9ddls23583015ab.0.-pod-prod-06-us; Tue, 04 Feb 2025
 09:37:30 -0800 (PST)
X-Received: by 2002:a05:6e02:1fc2:b0:3a7:6566:1e8f with SMTP id e9e14a558f8ab-3cffe4b3f76mr217203485ab.16.1738690650430;
        Tue, 04 Feb 2025 09:37:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738690650; cv=none;
        d=google.com; s=arc-20240605;
        b=KlgKftRnzFHzUXGOHl4p/8d1Zd14n5JA0x2No7hrMDjFLpwd3ulc7nXysWBDfodxQE
         3TlihU/DydcOkySyeHPf76R3ca8XT1Ywz4wJw/dhMdAN/Md0RUnyuW4V5f6oyL3kKiOA
         ZUuAKQUXn/feFwHoo0krJmK8I+TtRPsRuWcuep9/9PNPMnyUdhnLHzh10r6MGKVbBSlr
         oKKIEnh7wxAm3BqWEWbYV1Xk2XJZIbylmUKfm/esOSmsV2APk2dfxPo0Eqtl7OXfILuG
         eJphnjRYHCls9IRIykQaISOzLFdUJAwllj7+FhB7zWnsVsPzgiCKoAa6d2GaKp+aKR8Z
         snBQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=PCQPfnDRBxmJXeqGE9pZTyAVVotiYe5di+G+aFzDagA=;
        fh=myKcqxhIRjMnoyrCVROunGJsGQztaP+cwVmDG62got8=;
        b=ecbSKGd9ewT3tsXW58eWgrzRSxNsVUjjmG2lmyLWY419662GO9Uzt9d7lVbYbbmBDD
         Ai77NVZou1ZETwANTNiLw9fpf41RTBPjHV2e+5jdeprX578BHktg1LfmL2D4JdcwtTmP
         sWdpRCZFV0uBLidfIh0owbdW6MibSUZHDsz3+8ccTVjznU4pewK4DZtWRSWLrbOFLKUd
         9J2dnPZzZ5rb4hH2yKfFvCQwI7BukZBYu83X72C3JXIOvUunECdYG97hb8NXn4t05DXJ
         hR9rzVqgbJaXtgpHLf/9OaBOmWn0Hw6O5S6PKDmI/jGH84iItY1hG4k6XehD2q1ZjOET
         iCJQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=dleCM97N;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.20 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.20])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3d00a577fcbsi5372665ab.3.2025.02.04.09.37.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 04 Feb 2025 09:37:30 -0800 (PST)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.20 as permitted sender) client-ip=198.175.65.20;
X-CSE-ConnectionGUID: jKECcB+uS4WQ8xXttjgNcg==
X-CSE-MsgGUID: kLew7DymQW+4Z9T76IP3/w==
X-IronPort-AV: E=McAfee;i="6700,10204,11336"; a="38931158"
X-IronPort-AV: E=Sophos;i="6.13,259,1732608000"; 
   d="scan'208";a="38931158"
Received: from orviesa001.jf.intel.com ([10.64.159.141])
  by orvoesa112.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Feb 2025 09:37:29 -0800
X-CSE-ConnectionGUID: VKIBhH62QgyxuyV1BEgDvg==
X-CSE-MsgGUID: /T7gEKWsTDWNscbEm9C8IA==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.12,224,1728975600"; 
   d="scan'208";a="147867163"
Received: from mjarzebo-mobl1.ger.corp.intel.com (HELO wieczorr-mobl1.intel.com) ([10.245.244.61])
  by smtpauth.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Feb 2025 09:37:17 -0800
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
Subject: [PATCH 14/15] x86: Make software tag-based kasan available
Date: Tue,  4 Feb 2025 18:33:55 +0100
Message-ID: <794a931acfb8e73e28c02932ef08bed9254f164e.1738686764.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.47.1
In-Reply-To: <cover.1738686764.git.maciej.wieczor-retman@intel.com>
References: <cover.1738686764.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=dleCM97N;       spf=pass
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

Make CONFIG_KASAN_SW_TAGS available for x86 machines if they have
ADDRESS_MASKING enabled (LAM) as that works similarly to Top-Byte Ignore
(TBI) that allows the software tag-based mode on arm64 platform.

Set scale macro based on KASAN mode: in software tag-based mode 32 bytes
of memory map to one shadow byte and 16 in generic mode.

Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
 arch/x86/Kconfig                | 8 ++++++++
 arch/x86/boot/compressed/misc.h | 2 ++
 arch/x86/include/asm/kasan.h    | 2 +-
 arch/x86/kernel/setup.c         | 2 ++
 4 files changed, 13 insertions(+), 1 deletion(-)

diff --git a/arch/x86/Kconfig b/arch/x86/Kconfig
index dfec7bc692d4..afbcf27ad278 100644
--- a/arch/x86/Kconfig
+++ b/arch/x86/Kconfig
@@ -36,6 +36,7 @@ config X86_64
 	select ARCH_HAS_ELFCORE_COMPAT
 	select ZONE_DMA32
 	select EXECMEM if DYNAMIC_FTRACE
+	select ARCH_HAS_KASAN_SW_TAGS_DENSE
 
 config FORCE_DYNAMIC_FTRACE
 	def_bool y
@@ -190,6 +191,7 @@ config X86
 	select HAVE_ARCH_JUMP_LABEL_RELATIVE
 	select HAVE_ARCH_KASAN			if X86_64
 	select HAVE_ARCH_KASAN_VMALLOC		if X86_64
+	select HAVE_ARCH_KASAN_SW_TAGS		if ADDRESS_MASKING
 	select HAVE_ARCH_KFENCE
 	select HAVE_ARCH_KMSAN			if X86_64
 	select HAVE_ARCH_KGDB
@@ -394,6 +396,12 @@ config KASAN_SHADOW_OFFSET
 	hex
 	default 0xdffffc0000000000 if KASAN_GENERIC
 
+config KASAN_SHADOW_SCALE_SHIFT
+	int
+	default 5 if KASAN_SW_TAGS_DENSE
+	default 4 if KASAN_SW_TAGS
+	default 3
+
 config HAVE_INTEL_TXT
 	def_bool y
 	depends on INTEL_IOMMU && ACPI
diff --git a/arch/x86/boot/compressed/misc.h b/arch/x86/boot/compressed/misc.h
index dd8d1a85f671..397a70558ffa 100644
--- a/arch/x86/boot/compressed/misc.h
+++ b/arch/x86/boot/compressed/misc.h
@@ -13,6 +13,8 @@
 #undef CONFIG_PARAVIRT_SPINLOCKS
 #undef CONFIG_KASAN
 #undef CONFIG_KASAN_GENERIC
+#undef CONFIG_KASAN_SW_TAGS
+#undef CONFIG_KASAN_SW_TAGS_DENSE
 
 #define __NO_FORTIFY
 
diff --git a/arch/x86/include/asm/kasan.h b/arch/x86/include/asm/kasan.h
index 79151356d5f2..99ff4ae83bf7 100644
--- a/arch/x86/include/asm/kasan.h
+++ b/arch/x86/include/asm/kasan.h
@@ -6,7 +6,7 @@
 #include <linux/kasan-tags.h>
 #include <linux/types.h>
 
-#define KASAN_SHADOW_SCALE_SHIFT 3
+#define KASAN_SHADOW_SCALE_SHIFT CONFIG_KASAN_SHADOW_SCALE_SHIFT
 
 /*
  * Compiler uses shadow offset assuming that addresses start
diff --git a/arch/x86/kernel/setup.c b/arch/x86/kernel/setup.c
index f1fea506e20f..c300274e205a 100644
--- a/arch/x86/kernel/setup.c
+++ b/arch/x86/kernel/setup.c
@@ -1121,6 +1121,8 @@ void __init setup_arch(char **cmdline_p)
 
 	kasan_init();
 
+	kasan_init_sw_tags();
+
 	/*
 	 * Sync back kernel address range.
 	 *
-- 
2.47.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/794a931acfb8e73e28c02932ef08bed9254f164e.1738686764.git.maciej.wieczor-retman%40intel.com.

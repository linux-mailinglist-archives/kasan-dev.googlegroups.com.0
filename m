Return-Path: <kasan-dev+bncBCMMDDFSWYCBBS4D2G6QMGQEV7JTO2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103f.google.com (mail-pj1-x103f.google.com [IPv6:2607:f8b0:4864:20::103f])
	by mail.lfdr.de (Postfix) with ESMTPS id 722BAA394D4
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Feb 2025 09:16:14 +0100 (CET)
Received: by mail-pj1-x103f.google.com with SMTP id 98e67ed59e1d1-2fc0bc05afdsf10598152a91.0
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Feb 2025 00:16:14 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739866573; cv=pass;
        d=google.com; s=arc-20240605;
        b=frdfiAfMqhwnScSKCLWJgGh5zUUKfSFyQ6FqHHr+BIJ99ZjNpHfKVqBZug6tMQqDNZ
         HUP1bFf8guIiHt59RvCaJM0j/mFKWIhhS5V9DAzFvKFda8LsxyOw6W1fh+zr22snfz3Y
         YHi8hJ90q49KyztJ7yob7/gjAuwszEWE5o5IeKuedV0dHwaoLJaAa4RegeayLM5jsDuL
         FGPasKthPF5WPEIp6xGqOJUSe4WceuRfm/XRyngwB5T3NNRWnPZyF3dVTtABs5a96qFC
         sFFSCs56XWOa7tZCMqp5IQT1uUkGu9qXOxhyA9tILOlrT0CfPYtNwiashvJ8h5CgWnrm
         +jhw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=vr98fblN70I/uRT9uhusWrW/AScsSQyfZkhyIH8FpFg=;
        fh=yi+MhuTKrHZq3kqIgWLUy7FW8Fw7BsjvbzVzcaT4+Ko=;
        b=DxlGqau8PIi1ZzoOajhhTFQqxCrrH6O4BfaQlp+nyWS0jEFd0D3/dEiwF7hQGMbOew
         zYoUisZJle9Bx8FbAZAaRzuEck1RBmGJde0vsSnF5opTwIwcAXMIa+0TiCilhbpwaskY
         lwuJkNWcdZzllGymxtV64uetLZeAOvHkSiqALCwe2or9KQXuSEPju5PYQfZ3jjpYfMVL
         4HCpOQspPSCvibHG2YPegrMfr5ywO9y0j0FD6lBwXYjZO4gH22KFvoRlwtTke4flHHRM
         DA6B76tQQNxaNcmbgen9wvQBkACdVZ20F5OtMMsFRQouBFP/3UA1IwiKv4BSuCxjTWow
         WvGQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=Mr2umJ2f;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.16 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739866572; x=1740471372; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=vr98fblN70I/uRT9uhusWrW/AScsSQyfZkhyIH8FpFg=;
        b=D4Dg5zdB/fden8ADAVFryJ8FUbAYAMNjZdHokk/H2Hc1GPhVrMGRXtMd/A5Bfuz8WJ
         oyqwZlbSfTZp1nCdXQIi4DC0S6E2OVMIQcgvAATrwDJFJOmahqw8+FJQ9ZcOEUNBgJRp
         kPsszY0Pt+GEynPB8xVchTx1VZWzOkieiRKRhxUxQ5xEDCe/54KM38WEG0/HEByrkXM5
         wLgK43exrFyD5ZwhV5x2gDItNWiH6Nw069UuoVmeuTRLwwY4i6KvZ2LyAnK4Z71iUz7c
         PlCOWfMlowZ16GXfLzBZPkkqwp0yvTzyUwZC5V7IT6qbdyMXHs+O/P0hgvFjhE75R83s
         gPCQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739866573; x=1740471373;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=vr98fblN70I/uRT9uhusWrW/AScsSQyfZkhyIH8FpFg=;
        b=nlEWJc9hIv/UcrbB/MvVEpDhhatxtcRM5Qv1bBeE7v1rolOdpmG7OnGjWkjRyyEaWf
         m5eCAqfQyYdxRO1W5LMme0qT4vG2lE+oDVRp/D5wYMJA201pqPk2IJ+lQwERAGQSSyWh
         o7zhVFWC1d810UsdNb6f3TwP8P+Lffq4fUpwTdrBT+0MWRlkBy4lYDnqvu98E/8y7W8L
         qr1jSrjY4MCE4OT5obNL9PLb3iEVGJ95kynP0mV2Xix7ZBJTccri87q8GzvnfVRocsbl
         gKBRu4j4bD+nnH9XBPx35ZF9ZLxZfNhbyAV4YCkaiJ8SsdWllTmP76qNyP4jO6GPvD1C
         93yw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWPmE7VoYKuT4wF57jDV8QN5/h+skHQ4OnVgj2JupEUiyV6Pbhr0GVKyMiOLVBmRq2xcKfjEg==@lfdr.de
X-Gm-Message-State: AOJu0YxsZBjXr/tVR09zfYotGnlOtwze52ZJwXRjn8XKeHMXqO5l7yDi
	nEcT/gl3zg0jBHaUJGLnhCXU8FRvo+rWd+a/bLpnjelRTED0yVlo
X-Google-Smtp-Source: AGHT+IFo4W6k0iVppIj6RhPuCAqOSx9lNgCvVhHD9/9BdnN1zJNbl4MUxexceU4UbrRtcySFcSwwog==
X-Received: by 2002:a17:90b:3ec5:b0:2f9:cf97:56ac with SMTP id 98e67ed59e1d1-2fc40790624mr24969899a91.0.1739866571953;
        Tue, 18 Feb 2025 00:16:11 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVF4QvcIY6tpbnBE6ZFoiq6KxWIoXvzyh5Ug+eM9R5vrVQ==
Received: by 2002:a17:90a:c909:b0:2fa:2268:1aee with SMTP id
 98e67ed59e1d1-2fc0d6fc2e1ls1445610a91.1.-pod-prod-05-us; Tue, 18 Feb 2025
 00:16:11 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXFh5ugEEOPCz5NfYI+f5x7kQtj7BBzTt0pal09owj+Xo6KLDvOM9J+XPJoxyedw3zc/a8IdLTCpEc=@googlegroups.com
X-Received: by 2002:a17:90b:4cc3:b0:2ee:af31:a7bd with SMTP id 98e67ed59e1d1-2fc40d13e11mr19123351a91.5.1739866570849;
        Tue, 18 Feb 2025 00:16:10 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739866570; cv=none;
        d=google.com; s=arc-20240605;
        b=cCkgp7KURaWbR9QuxnHDmvNbCY/x3ic7FWBhgTcOZnLpJFGs5yod+SzU2t7ytoX6SE
         CmWzuBEeaZWRu/xyb1e2wEpNaI1m+frK0JgWKdhwJAlBBE961fBdFW9ZilJ+EviMuJhe
         Xi9dUJTVM7bqETwOXxKQXhUr2IUb3+3P/P0jecIMKbWDzCa4FDmTNWRm2Jq9BJKWJjHv
         7UCnHp6lWLBPhHTbvimJErEuwQKP/PkpMQt6GKDm8Ru8XNDHAZLGNs4yy+w5n4K7ap1L
         ec7fLskB+teMJQJIdCfEelBdNU5HQ4NizHUa6H9/HV7lk3qspp1Z4KFKijA1mOcleYZn
         z7AA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=jXc2dMufLT2gniCBcRcAn7bZr49akp5vxRSqoWdVFpY=;
        fh=t/SH+Gg/XGt5WVAQfMl2l/LCcdyTZmDfR0ct3DuRE8Y=;
        b=Raw/RkqDZ25lepf1mrDBCWD0xFXMXM0CPfXDyB/14qzsef375oBL/qATHzAkl2Xipa
         0jPbTRd9L7G68N7m9HCMhSThSANMNEe3062jLHOFioCf3cS6V+bh0poELRvAX0ENZMxb
         Qd0f7yQBCGAwl6Tu+eVCnUEeuJpK/UczjZftUFxJpl+yYWIo4xtGol0wRLFYVOL/ClGR
         8ipYfrxHx1oLLzcNYgUQKjtoFMOLukANQsAkXk6u/FjsBaGOJqM6ms/x5d2Vz7L19+o/
         h0Jm4MFNaDwfB1/SEWs7OIRow+OA7GwXz41RVdJ39QW91wjMpxhpkjjMPkdHz90ZiPTK
         Pl3w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=Mr2umJ2f;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.16 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.16])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2faa4b0e10dsi2073880a91.0.2025.02.18.00.16.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 18 Feb 2025 00:16:10 -0800 (PST)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.16 as permitted sender) client-ip=192.198.163.16;
X-CSE-ConnectionGUID: d1P5w5I0RxSVmvH0TiJJLw==
X-CSE-MsgGUID: 3xR9jBsTS3ioaCCkHjLPcw==
X-IronPort-AV: E=McAfee;i="6700,10204,11348"; a="28149889"
X-IronPort-AV: E=Sophos;i="6.13,295,1732608000"; 
   d="scan'208";a="28149889"
Received: from orviesa003.jf.intel.com ([10.64.159.143])
  by fmvoesa110.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 18 Feb 2025 00:16:10 -0800
X-CSE-ConnectionGUID: 4lVz8jdKThmi+vw7tnu8lA==
X-CSE-MsgGUID: xFRyo/FSQWKQw+ynAaEsIg==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.11,199,1725346800"; 
   d="scan'208";a="119247279"
Received: from ijarvine-mobl1.ger.corp.intel.com (HELO wieczorr-mobl1.intel.com) ([10.245.245.49])
  by ORVIESA003-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 18 Feb 2025 00:15:48 -0800
From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
To: kees@kernel.org,
	julian.stecklina@cyberus-technology.de,
	kevinloughlin@google.com,
	peterz@infradead.org,
	tglx@linutronix.de,
	justinstitt@google.com,
	catalin.marinas@arm.com,
	wangkefeng.wang@huawei.com,
	bhe@redhat.com,
	ryabinin.a.a@gmail.com,
	kirill.shutemov@linux.intel.com,
	will@kernel.org,
	ardb@kernel.org,
	jason.andryuk@amd.com,
	dave.hansen@linux.intel.com,
	pasha.tatashin@soleen.com,
	ndesaulniers@google.com,
	guoweikang.kernel@gmail.com,
	dwmw@amazon.co.uk,
	mark.rutland@arm.com,
	broonie@kernel.org,
	apopple@nvidia.com,
	bp@alien8.de,
	rppt@kernel.org,
	kaleshsingh@google.com,
	richard.weiyang@gmail.com,
	luto@kernel.org,
	glider@google.com,
	pankaj.gupta@amd.com,
	andreyknvl@gmail.com,
	pawan.kumar.gupta@linux.intel.com,
	kuan-ying.lee@canonical.com,
	tony.luck@intel.com,
	tj@kernel.org,
	jgross@suse.com,
	dvyukov@google.com,
	baohua@kernel.org,
	samuel.holland@sifive.com,
	dennis@kernel.org,
	akpm@linux-foundation.org,
	thomas.weissschuh@linutronix.de,
	surenb@google.com,
	kbingham@kernel.org,
	ankita@nvidia.com,
	nathan@kernel.org,
	maciej.wieczor-retman@intel.com,
	ziy@nvidia.com,
	xin@zytor.com,
	rafael.j.wysocki@intel.com,
	andriy.shevchenko@linux.intel.com,
	cl@linux.com,
	jhubbard@nvidia.com,
	hpa@zytor.com,
	scott@os.amperecomputing.com,
	david@redhat.com,
	jan.kiszka@siemens.com,
	vincenzo.frascino@arm.com,
	corbet@lwn.net,
	maz@kernel.org,
	mingo@redhat.com,
	arnd@arndb.de,
	ytcoode@gmail.com,
	xur@google.com,
	morbo@google.com,
	thiago.bauermann@linaro.org
Cc: linux-doc@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	llvm@lists.linux.dev,
	linux-mm@kvack.org,
	linux-arm-kernel@lists.infradead.org,
	x86@kernel.org
Subject: [PATCH v2 00/14] kasan: x86: arm64: KASAN tag-based mode for x86
Date: Tue, 18 Feb 2025 09:15:16 +0100
Message-ID: <cover.1739866028.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.47.1
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=Mr2umJ2f;       spf=pass
 (google.com: domain of maciej.wieczor-retman@intel.com designates
 192.198.163.16 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
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

Changes v2:
- Split the series into one adding KASAN tag-based mode (this one) and
  another one that adds the dense mode to KASAN (will post later).
- Removed exporting kasan_poison() and used a wrapper instead in
  kasan_init_64.c
- Prepended series with 4 patches from the risc-v series and applied
  review comments to the first patch as the rest already are reviewed.

======= Introduction
The patchset aims to add a KASAN tag-based mode for the x86 architecture
with the help of the new CPU feature called Linear Address Masking
(LAM). Main improvement introduced by the series is 2x lower memory
usage compared to KASAN's generic mode, the only currently available
mode on x86.

There are two relevant series in the process of adding KASAN tag-based
support to x86. This one focuses on implementing and enabling the
tag-based mode for the x86 architecture by using LAM. The second one
attempts to add a new memory saving mechanism called "dense mode" to the
non-arch part of the tag-based KASAN code. It can provide another 2x
memory savings by packing tags denser in the shadow memory.

======= How KASAN tag-based mode works?
When enabled, memory accesses and allocations are augmented by the
compiler during kernel compilation. Instrumentation functions are added
to each memory allocation and each pointer dereference.

The allocation related functions generate a random tag and save it in
two places: in shadow memory that maps to the allocated memory, and in
the top bits of the pointer that points to the allocated memory. Storing
the tag in the top of the pointer is possible because of Top-Byte Ignore
(TBI) on arm64 architecture and LAM on x86.

The access related functions are performing a comparison between the tag
stored in the pointer and the one stored in shadow memory. If the tags
don't match an out of bounds error must have occurred and so an error
report is generated.

The general idea for the tag-based mode is very well explained in the
series with the original implementation [1].

[1] https://lore.kernel.org/all/cover.1544099024.git.andreyknvl@google.com/

======= Differences summary compared to the arm64 tag-based mode
- Tag width:
	- Tag width influences the chance of a tag mismatch due to two
	  tags from different allocations having the same value. The
	  bigger the possible range of tag values the lower the chance
	  of that happening.
	- Shortening the tag width from 8 bits to 4, while it can help
	  with memory usage, it also increases the chance of not
	  reporting an error. 4 bit tags have a ~7% chance of a tag
	  mismatch.

- TBI and LAM
	- TBI in arm64 allows for storing metadata in the top 8 bits of
	  the virtual address.
	- LAM in x86 allows storing tags in bits [62:57] of the pointer.
	  To maximize memory savings the tag width is reduced to bits
	  [60:57].

- KASAN offset calculations
	- When converting addresses from memory to shadow memory the
	  address is treated as a signed number.
	- On arm64 due to TBI half of tagged addresses will be positive
	  and half negative. KASAN shadow offset means the middle point
	  of the shadow memory there.
	- On x86 - due to the top bit of the pointer always being set in
	  kernel address space - all the addresses will be negative when
	  treated as signed offsets into shadow memory. KASAN shadow
	  offset means the end of the shadow memory there.

======= Testing
Checked all the kunits for both software tags and generic KASAN after
making changes.

In generic mode the results were:

kasan: pass:59 fail:0 skip:13 total:72
Totals: pass:59 fail:0 skip:13 total:72
ok 1 kasan

and for software tags:

kasan: pass:63 fail:0 skip:9 total:72
Totals: pass:63 fail:0 skip:9 total:72
ok 1 kasan

======= Benchmarks
All tests were ran on a Sierra Forest server platform with 512GB of
memory. The only differences between the tests were kernel options:
	- CONFIG_KASAN
	- CONFIG_KASAN_GENERIC
	- CONFIG_KASAN_SW_TAGS
	- CONFIG_KASAN_INLINE [1]
	- CONFIG_KASAN_OUTLINE [1]

More benchmarks are noted in the second series that adds the dense mode
to KASAN. That's because most values on x86' tag-based mode are tailored
to work well with that.

Boot time (until login prompt):
* 03:48 for clean kernel
* 08:02 / 09:45 for generic KASAN (inline/outline)
* 08:50 for tag-based KASAN
* 04:50 for tag-based KASAN with stacktrace disabled [2]

Compilation time comparison (10 cores):
* 7:27 for clean kernel
* 8:21/7:44 for generic KASAN (inline/outline)
* 7:41 for tag-based KASAN

[1] Based on hwasan and asan compiler parameters used in
scripts/Makefile.kasan it looks like inline/outline modes have a bigger
impact on generic mode than the tag-based mode. In the former inlining
actually increases the kernel image size and improves performance. In
the latter it un-inlines some code portions for debugging purposes when
the outline mode is chosen but no real difference is visible in
performance and kernel image size.

[2] Memory allocation and freeing performance suffers heavily from saving
stacktraces that can be later displayed in error reports.

======= Compilation
Clang was used to compile the series (make LLVM=1) since gcc doesn't
seem to have support for KASAN tag-based compiler instrumentation on
x86.

======= Dependencies
Series bases on four patches taken from [1] series. Mainly the idea of
converting memory addresses to shadow memory addresses by treating them
as signed as opposed to unsigned. I tried applying review comments to
the first patch, while the other three are unchanged.

The base branch for the series is the tip x86/mm branch.

[1] https://lore.kernel.org/all/20241022015913.3524425-1-samuel.holland@sifive.com/

======= Enabling LAM for testing the series without LASS
Since LASS is needed for LAM and it can't be compiled without it I
enabled LAM during testing with the patch below:

--- a/arch/x86/Kconfig
+++ b/arch/x86/Kconfig
@@ -2275,7 +2275,7 @@ config RANDOMIZE_MEMORY_PHYSICAL_PADDING
 config ADDRESS_MASKING
 	bool "Linear Address Masking support"
 	depends on X86_64
-	depends on COMPILE_TEST || !CPU_MITIGATIONS # wait for LASS
+	#depends on COMPILE_TEST || !CPU_MITIGATIONS # wait for LASS
 	help
 	  Linear Address Masking (LAM) modifies the checking that is applied
 	  to 64-bit linear addresses, allowing software to use of the

--- a/arch/x86/kernel/cpu/common.c
+++ b/arch/x86/kernel/cpu/common.c
@@ -2401,9 +2401,10 @@ void __init arch_cpu_finalize_init(void)

 		/*
 		 * Enable this when LAM is gated on LASS support
+		 */
 		if (cpu_feature_enabled(X86_FEATURE_LAM))
 			USER_PTR_MAX = (1ul << 63) - PAGE_SIZE;
-		 */
+
 		runtime_const_init(ptr, USER_PTR_MAX);

 		/*

Maciej Wieczor-Retman (10):
  kasan: arm64: x86: Make special tags arch specific
  x86: Add arch specific kasan functions
  x86: Reset tag for virtual to physical address conversions
  x86: Physical address comparisons in fill_p*d/pte
  mm: Pcpu chunk address tag reset
  x86: KASAN raw shadow memory PTE init
  x86: LAM initialization
  x86: Minimal SLAB alignment
  x86: runtime_const used for KASAN_SHADOW_END
  x86: Make software tag-based kasan available

Samuel Holland (4):
  kasan: sw_tags: Use arithmetic shift for shadow computation
  kasan: sw_tags: Check kasan_flag_enabled at runtime
  kasan: sw_tags: Support outline stack tag generation
  kasan: sw_tags: Support tag widths less than 8 bits

 Documentation/arch/x86/x86_64/mm.rst |  6 ++--
 MAINTAINERS                          |  2 +-
 arch/arm64/Kconfig                   | 10 +++---
 arch/arm64/include/asm/kasan-tags.h  |  9 +++++
 arch/arm64/include/asm/kasan.h       |  6 ++--
 arch/arm64/include/asm/memory.h      | 14 +++++++-
 arch/arm64/include/asm/uaccess.h     |  1 +
 arch/arm64/mm/kasan_init.c           |  7 ++--
 arch/x86/Kconfig                     |  9 +++--
 arch/x86/boot/compressed/misc.h      |  1 +
 arch/x86/include/asm/kasan-tags.h    |  9 +++++
 arch/x86/include/asm/kasan.h         | 50 +++++++++++++++++++++++++---
 arch/x86/include/asm/page.h          | 17 +++++++---
 arch/x86/include/asm/page_64.h       |  2 +-
 arch/x86/kernel/head_64.S            |  3 ++
 arch/x86/kernel/setup.c              |  2 ++
 arch/x86/kernel/vmlinux.lds.S        |  1 +
 arch/x86/mm/init.c                   |  3 ++
 arch/x86/mm/init_64.c                | 11 +++---
 arch/x86/mm/kasan_init_64.c          | 24 ++++++++++---
 arch/x86/mm/physaddr.c               |  1 +
 include/linux/kasan-enabled.h        | 15 +++------
 include/linux/kasan-tags.h           | 19 ++++++++---
 include/linux/kasan.h                | 14 ++++++--
 include/linux/mm.h                   |  6 ++--
 include/linux/page-flags-layout.h    |  7 +---
 mm/kasan/hw_tags.c                   | 10 ------
 mm/kasan/kasan.h                     |  2 ++
 mm/kasan/report.c                    | 26 ++++++++++++---
 mm/kasan/sw_tags.c                   |  9 +++++
 mm/kasan/tags.c                      | 10 ++++++
 mm/percpu-vm.c                       |  2 +-
 scripts/gdb/linux/mm.py              |  5 +--
 33 files changed, 237 insertions(+), 76 deletions(-)
 create mode 100644 arch/arm64/include/asm/kasan-tags.h
 create mode 100644 arch/x86/include/asm/kasan-tags.h

-- 
2.47.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/cover.1739866028.git.maciej.wieczor-retman%40intel.com.

Return-Path: <kasan-dev+bncBCMMDDFSWYCBBSNWX67QMGQEAQA6O3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf38.google.com (mail-qv1-xf38.google.com [IPv6:2607:f8b0:4864:20::f38])
	by mail.lfdr.de (Postfix) with ESMTPS id 55390A7BD52
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Apr 2025 15:14:51 +0200 (CEST)
Received: by mail-qv1-xf38.google.com with SMTP id 6a1803df08f44-6e8fae3e448sf42131886d6.2
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Apr 2025 06:14:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1743772490; cv=pass;
        d=google.com; s=arc-20240605;
        b=ZWh/cblnVbfvSqODPuraFtL7wJ25JPvIIN/Z00Dn+H+ddide0blBbTbyIHCq9CppfV
         62MwVbdcvKLqXHiGI+BTPiBFugkmv7f7ExsR4Z4BBk3mxSJM9wpVKhJfBZa2+fU29/6b
         FWO0Bx2CVlNvh+JymX0Z22D/LVMrtKekDh5g08Eaa94r6BTrq/A5D//GsSnuiFm2gRtU
         dR8qaJvvaBPlanvLSC7zxDWXg5mW5msgTLQfQYfQH/W8SACVIsN121bpXkiFbRAdvLNP
         PLc3/0eVtAk4c/wNaXQi47qyDROZV0FmkmNoBfhjkp9TMn4c2VZqPIbvE4aTg3FmZNFJ
         mF/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=JCdd/xbOEULf6fgflpvdzmVJ7mbul2tUFqPMkQsMUvo=;
        fh=wdgVWbJsOAWuVpJxQcxpOaUdJTwJSyrcY1Y3WyZdwn0=;
        b=ifR7zsK8iOUJGbUNl3PAKAXQzcM1qSsjoSnVj9qUapwl0YNQrr56FmdBZqMsgxuHOR
         y19rDIxRxoNIJmhA6amGbmwhJUA0aV/JSkPQDoDtoG7cJMvYOluV3wtD92I/1Ypv5hIp
         71NbA+AxdAEE8eRXwpsQ7G/5d0X51FbpDxxTFbAAHcb+lNgKWC73irK4IY8X6jASniGC
         SgaIRKgwoO1ip8UcxmKapOkz3PhxW+1wOTPtIAIo86Uqo7nRAzeRniABLGWpmxBkUVqz
         kN+AuGsy6uoJZ4CWLdrwqlziJZkZ2nVIfQOtGAYvb0qmDpO1z19K+f5vHDObvZ7F8VY3
         HFNw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=lPurcNdH;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1743772490; x=1744377290; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:message-id:date:subject:cc:to:from
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=JCdd/xbOEULf6fgflpvdzmVJ7mbul2tUFqPMkQsMUvo=;
        b=gZo8xYeJ6NtbKa6XqBgIOqZoNvP0q3mHrrxYbj7ZfPB0dAmKVx0AbA+Kni97R0hTFH
         fI/eF7bZWCA40/syfr7w9rRc9/boxPeh2HE8AVNfVVFBDHwyGAjwzGsVOqaosej9tufS
         NNPNAwERw1LhP9deWbwYv3ZSNf7GUZT6FPYL1fBnVhRVXHifHjr3dTsY+xN7vfxdIz2C
         XJ3xdHQ995N5QSwr27aI7KbBJBdwjxxbPxQ6ypk845t0XID9q/QO6mop87bwfibOnJJY
         AnWDQJsbzlHGGN9pgT/nsQmqUu/sUEJA+5A3vEwheUpfCtM64uXTsXhenh4i2nEUPmeH
         1PAQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1743772490; x=1744377290;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :message-id:date:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=JCdd/xbOEULf6fgflpvdzmVJ7mbul2tUFqPMkQsMUvo=;
        b=qkH8XZbstLxWmOw0kNNPfSAbAAJM7t31WfomCVQt4tOR70gbcAC51Jz3sYmZ1E7A/M
         cJb0HDnsggkI+LnSvt45Tg/mCFYM2tdNZ8wr+2NPwF5bv0i2QzycC9hIh7fWgD6aoM4k
         t5GJlppNZ/5s4oIl42XEo1VOSy+eH2d12GkZoqVwS/2xzmYU8ruwh8luMAqTRr6AuDio
         Q1KMnola51CVFzbdVVgREM5hF1Gd2bI1wb8kZQQsz82e/HtgnKhaFd7dt9nCNp3CH/p2
         6A9rwlURxhj5ErBO9kJHcNObuSvw17ROLNcil4J2g4yBloTx+Rmutse8zJCPbJ95pps3
         58aQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUr3xUPVK1SOesU7g8bNfvIsl+CaQMeDR0khFX2aRLA8PJWNtYhgrLdxputkQRpsPPdFNCG1A==@lfdr.de
X-Gm-Message-State: AOJu0Yy9q3fTXyUN1SsKoYvtIgBINihIIfQagNzerLhjp1Uni4RvgkHs
	uFfVPy+LiKp02cAJ+LK8c02ZJU3fDfGr3bwiJYg/+l5ycfzU8ljQ
X-Google-Smtp-Source: AGHT+IGDdcpA/G+5QsrTYiPXYgo3FvQntfOtGT515Az73TB2YoVOLKiaa+xkBR6h6rjrXqpxwscQCw==
X-Received: by 2002:a05:6214:29e3:b0:6e8:9021:9095 with SMTP id 6a1803df08f44-6f01e77d162mr50049636d6.32.1743772489871;
        Fri, 04 Apr 2025 06:14:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAIs3vbnjllROj2wcmzf2fjl3/d7kYV9hhNLuJ5ftLquiw==
Received: by 2002:a05:6214:3b85:b0:6e8:efc0:7a3f with SMTP id
 6a1803df08f44-6ef0bfa9529ls20628806d6.2.-pod-prod-03-us; Fri, 04 Apr 2025
 06:14:49 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWragyK1eWHKGHVJVefmBO/+b3TcM1TP0l0ZSq/v6O0JlezB4UCmIiDHBVW274BEGWyKLucOYwNyro=@googlegroups.com
X-Received: by 2002:ad4:5ce8:0:b0:6e4:4484:f35b with SMTP id 6a1803df08f44-6f01e77c85dmr38901316d6.30.1743772488846;
        Fri, 04 Apr 2025 06:14:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1743772488; cv=none;
        d=google.com; s=arc-20240605;
        b=OCFOCIC9/+zDro8tlHnfedPCw1FerFGI0hf1B7jAwgECMVKwAFYrQHOrEy8V0lMmVR
         iCO1ifVXK3YqNACHTWvnHqwzXkIzJj9eL+/L3krUQGiouUgawZX2xcY3AmC4+wBFDT9W
         v9VYJEG4ooYa4CCtdhp2kE56HnzvjsnMEUPIaqkf+RPUS1T3r8AyQNrlJYBMswGNhiQK
         /wGXkjspXJGy7ipAmhHxrdTXdMbioI2Qvbj5QjdNSunDeCsIb+Ac6ED672bqXnE2C0JO
         /J37kHztEyhTLU61PupUoLplZ85UNAaGgyT8gWojXZ5JRGYlu49+Ye17BjMyNwXHO9lb
         Idcw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=l4F8b7WMOxIQd3psluu41JltXSgqfaRMAJ4I4X5qMAg=;
        fh=J7nw2tc4gzRvdzI0P/GwtR3jWmwmM/GxmLt8uthQMV0=;
        b=k97a75S7qOhPLpN0KFqZy2cpWYk8f/8DtHZ/+RO4EdGI4tWUCdOoKEfUsGcOOtINmp
         s0Bhb+jnSn6RvvbZj6tbYciTD/h7EnNLsdIVi0noKNo+2Kq270mK9SfyFCJ6Irm9VSqJ
         pJxO3uyGPh1Y7wjRIkgwOKVhlIZ9kKQgG5/Mfc8U/whoKZrkMr/q5JgYCxWkNdy1xGBa
         GO/HVSJIs52Nee/ur9JVjYxBgSPcIwJOSqIKwtv0W+Et6PsfbiyY2sCFhxRPs/LpOw10
         /fG4vfbcv9hsaa2JepijlkxyZifpWqJHQwRtOj0ru5X1tKYilQxCEto2uwxNCVhcK9GF
         CErQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=lPurcNdH;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.11])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6ef0efc0132si1733356d6.2.2025.04.04.06.14.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Fri, 04 Apr 2025 06:14:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.11 as permitted sender) client-ip=198.175.65.11;
X-CSE-ConnectionGUID: 02NNEFxIQlCbqEZmA1MTlQ==
X-CSE-MsgGUID: FyErkb8SSiy2SwuRTOtbbA==
X-IronPort-AV: E=McAfee;i="6700,10204,11394"; a="55401504"
X-IronPort-AV: E=Sophos;i="6.15,188,1739865600"; 
   d="scan'208";a="55401504"
Received: from fmviesa009.fm.intel.com ([10.60.135.149])
  by orvoesa103.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Apr 2025 06:14:47 -0700
X-CSE-ConnectionGUID: FZxz6OJGQf6jyVDmqeoQgQ==
X-CSE-MsgGUID: loB3APGTTAqGkdlmWdKwag==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.15,188,1739865600"; 
   d="scan'208";a="128156901"
Received: from opintica-mobl1 (HELO wieczorr-mobl1.intel.com) ([10.245.245.50])
  by fmviesa009-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Apr 2025 06:14:32 -0700
From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
To: hpa@zytor.com,
	hch@infradead.org,
	nick.desaulniers+lkml@gmail.com,
	kuan-ying.lee@canonical.com,
	masahiroy@kernel.org,
	samuel.holland@sifive.com,
	mingo@redhat.com,
	corbet@lwn.net,
	ryabinin.a.a@gmail.com,
	guoweikang.kernel@gmail.com,
	jpoimboe@kernel.org,
	ardb@kernel.org,
	vincenzo.frascino@arm.com,
	glider@google.com,
	kirill.shutemov@linux.intel.com,
	apopple@nvidia.com,
	samitolvanen@google.com,
	maciej.wieczor-retman@intel.com,
	kaleshsingh@google.com,
	jgross@suse.com,
	andreyknvl@gmail.com,
	scott@os.amperecomputing.com,
	tony.luck@intel.com,
	dvyukov@google.com,
	pasha.tatashin@soleen.com,
	ziy@nvidia.com,
	broonie@kernel.org,
	gatlin.newhouse@gmail.com,
	jackmanb@google.com,
	wangkefeng.wang@huawei.com,
	thiago.bauermann@linaro.org,
	tglx@linutronix.de,
	kees@kernel.org,
	akpm@linux-foundation.org,
	jason.andryuk@amd.com,
	snovitoll@gmail.com,
	xin@zytor.com,
	jan.kiszka@siemens.com,
	bp@alien8.de,
	rppt@kernel.org,
	peterz@infradead.org,
	pankaj.gupta@amd.com,
	thuth@redhat.com,
	andriy.shevchenko@linux.intel.com,
	joel.granados@kernel.org,
	kbingham@kernel.org,
	nicolas@fjasle.eu,
	mark.rutland@arm.com,
	surenb@google.com,
	catalin.marinas@arm.com,
	morbo@google.com,
	justinstitt@google.com,
	ubizjak@gmail.com,
	jhubbard@nvidia.com,
	urezki@gmail.com,
	dave.hansen@linux.intel.com,
	bhe@redhat.com,
	luto@kernel.org,
	baohua@kernel.org,
	nathan@kernel.org,
	will@kernel.org,
	brgerst@gmail.com
Cc: llvm@lists.linux.dev,
	linux-mm@kvack.org,
	linux-doc@vger.kernel.org,
	linux-arm-kernel@lists.infradead.org,
	linux-kbuild@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	x86@kernel.org
Subject: [PATCH v3 00/14] kasan: x86: arm64: KASAN tag-based mode for x86
Date: Fri,  4 Apr 2025 15:14:04 +0200
Message-ID: <cover.1743772053.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.49.0
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=lPurcNdH;       spf=pass
 (google.com: domain of maciej.wieczor-retman@intel.com designates
 198.175.65.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
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

Changes v3:
- Remove the runtime_const patch and setup a unified offset for both 5
  and 4 paging levels.
- Add a fix for inline mode on x86 tag-based KASAN. Add a handler for
  int3 that is generated on inline tag mismatches.
- Fix scripts/gdb/linux/kasan.py so the new signed mem_to_shadow() is
  reflected there.
- Fix Documentation/arch/arm64/kasan-offsets.sh to take new offsets into
  account.
- Made changes to the kasan_non_canonical_hook() according to upstream
  discussion.
- Remove patches 2 and 3 since they related to risc-v and this series
  adds only x86 related things.
- Reorder __tag_*() functions so they're before arch_kasan_*(). Remove
  CONFIG_KASAN condition from __tag_set().

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

======= How does KASAN' tag-based mode work?
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
	- CONFIG_KASAN_OUTLINE

More benchmarks are noted in the second series that adds the dense mode
to KASAN. That's because most values on x86' tag-based mode are tailored
to work well with that.

Boot time (until login prompt):
* 03:48 for clean kernel
* 08:02 / 09:45 for generic KASAN (inline/outline)
* 08:50 for tag-based KASAN
* 04:50 for tag-based KASAN with stacktrace disabled [1]

Compilation time comparison (10 cores):
* 7:27 for clean kernel
* 8:21/7:44 for generic KASAN (inline/outline)
* 7:41 for tag-based KASAN

[1] Currently (after getting it enabled in the Makefile) inline mode
doesn't work on x86. It's probably due to something missing in the
compiler and I aim to figure this out when working on the second series
that adds the dense mode (and will need compiler support anyway).

[2] Memory allocation and freeing performance suffers heavily from saving
stacktraces that can be later displayed in error reports.

======= Compilation
Clang was used to compile the series (make LLVM=1) since gcc doesn't
seem to have support for KASAN tag-based compiler instrumentation on
x86.

======= Dependencies
The base branch for the series is the tip x86/mm branch.

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

Maciej Wieczor-Retman (12):
  x86: Add arch specific kasan functions
  kasan: arm64: x86: Make special tags arch specific
  x86: Reset tag for virtual to physical address conversions
  x86: Physical address comparisons in fill_p*d/pte
  x86: KASAN raw shadow memory PTE init
  x86: LAM initialization
  x86: Minimal SLAB alignment
  x86: Update the KASAN non-canonical hook
  x86: Handle int3 for inline KASAN reports
  kasan: Fix inline mode for x86 tag-based mode
  mm: Unpoison pcpu chunks with base address tag
  x86: Make software tag-based kasan available

Samuel Holland (2):
  kasan: sw_tags: Use arithmetic shift for shadow computation
  kasan: sw_tags: Support tag widths less than 8 bits

 Documentation/arch/arm64/kasan-offsets.sh |  8 ++-
 Documentation/arch/x86/x86_64/mm.rst      |  6 +-
 MAINTAINERS                               |  2 +-
 arch/arm64/Kconfig                        | 10 ++--
 arch/arm64/include/asm/kasan-tags.h       |  9 +++
 arch/arm64/include/asm/kasan.h            |  6 +-
 arch/arm64/include/asm/memory.h           | 14 ++++-
 arch/arm64/include/asm/uaccess.h          |  1 +
 arch/arm64/mm/kasan_init.c                |  7 ++-
 arch/x86/Kconfig                          |  5 +-
 arch/x86/boot/compressed/misc.h           |  1 +
 arch/x86/include/asm/cache.h              |  4 ++
 arch/x86/include/asm/kasan-tags.h         |  9 +++
 arch/x86/include/asm/kasan.h              | 41 ++++++++++++-
 arch/x86/include/asm/page.h               | 17 ++++--
 arch/x86/include/asm/page_64.h            |  2 +-
 arch/x86/kernel/alternative.c             |  3 +
 arch/x86/kernel/head_64.S                 |  3 +
 arch/x86/kernel/setup.c                   |  2 +
 arch/x86/kernel/traps.c                   | 52 +++++++++++++++++
 arch/x86/mm/fault.c                       |  2 +
 arch/x86/mm/init.c                        |  3 +
 arch/x86/mm/init_64.c                     | 11 ++--
 arch/x86/mm/kasan_init_64.c               | 21 +++++--
 arch/x86/mm/physaddr.c                    |  1 +
 include/linux/kasan-tags.h                | 19 ++++--
 include/linux/kasan.h                     | 24 +++++++-
 include/linux/mm.h                        |  6 +-
 include/linux/page-flags-layout.h         |  7 +--
 lib/Kconfig.kasan                         |  3 +-
 mm/kasan/report.c                         | 70 +++++++++++++++++++++--
 mm/kasan/shadow.c                         | 11 ++++
 mm/vmalloc.c                              |  3 +-
 scripts/Makefile.kasan                    |  3 +
 scripts/gdb/linux/kasan.py                |  3 +
 scripts/gdb/linux/mm.py                   |  5 +-
 36 files changed, 336 insertions(+), 58 deletions(-)
 mode change 100644 => 100755 Documentation/arch/arm64/kasan-offsets.sh
 create mode 100644 arch/arm64/include/asm/kasan-tags.h
 create mode 100644 arch/x86/include/asm/kasan-tags.h

-- 
2.49.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/cover.1743772053.git.maciej.wieczor-retman%40intel.com.

Return-Path: <kasan-dev+bncBCMMDDFSWYCBBVENWPCQMGQE6NJ3WWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3a.google.com (mail-oa1-x3a.google.com [IPv6:2001:4860:4864:20::3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 95957B34BB2
	for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 22:25:58 +0200 (CEST)
Received: by mail-oa1-x3a.google.com with SMTP id 586e51a60fabf-30cceaaa4c5sf1262624fac.2
        for <lists+kasan-dev@lfdr.de>; Mon, 25 Aug 2025 13:25:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756153557; cv=pass;
        d=google.com; s=arc-20240605;
        b=ECsuVzka2lPTXdjIvCLUBErUv7cOk0aswYRxaEiXm8Q7x3JtoSF3HITqFR5Mv9SJtZ
         IKEV8dmCnqHvtIuUdNxFFcUL2xwxPrMLN14mNPO/gc1+Yg0KZoR3ir2ceq297rwgJsrB
         41v9Ah62g66KkOz5fcQj3e7CV+Nkm+UyxwSIrsQl6XjiO7bYE3JY8uHBHC0xnI9e8SnZ
         fHsqF7ahBxPbl6sjJbUGNi/yJ6VB5jq98gZTsmbwz9wS1aC23IppBih+16z6kMxgA5px
         /x4Z9uZP9hlEumXnmNzuoenFotaUw042Ov5MNuGWCSEg9LHkF0/BMSfASuuIOTDfLhuO
         AgTQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=4KM0t6rUXBZef7lchUKlpJJN1C8UW3jiS+Es8BaUBBE=;
        fh=333IaLJoSebuO2WUYYnAdVhR8nvPlico+7s949//eH4=;
        b=Aqq6IvzH9vwlF2e/tFZwUMZrK2+wYcm8kEWUTvhtpEcJAS7dLSWU3MYWADzZWzwkrd
         BvwzJo2QnAEglk/E6m6040V7FXAvXZUDkNyhNzKqfnjJz1ncaItIDSazLGBk7n14Cr8q
         r87MMQnCgS9o87tmXR+YxL193Y38dAvQFwzUztcw/SaCQdhxDCffp5hb3UzXKhvQkSzc
         x1e9RqqpiBnsG6+yPiucYAGAEYsG2HmxZO30IhjaDvQNU/kI3xylnNmztEEec/KcfnXC
         Nbn8vlfoFS1UYBvpA7mHcSsUmYDVojrezTDLfrHl1Pdc5oSD+uI9Ib6vhesDPbB2aG/D
         ARbw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=YkHyYmAC;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756153557; x=1756758357; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=4KM0t6rUXBZef7lchUKlpJJN1C8UW3jiS+Es8BaUBBE=;
        b=WzKuZDZ2nOUKEgSNTAOM+iKZog0o3DC4ISQv08JxVnGuMIgT/B+VnWMHVJH/IvFTyZ
         dAQ6JXcWqWGxuGLNFk5vtNGoehM2eT4GIZ5vlcZHb1kR7irXdyDUpD0XpA2T2nxgJun2
         Gn2nfhZ8LVKXzpqIAp1Zc9cRAN9R5W7jFq/iovqjyVP9sKxIwO52c3B3mya6CMJ1wlrj
         3k7wt8/VmiS8jTnoH1Kv7r2RcuvYS0oC6qUdM0PV7YqvRRveUEIvdaECzyDedkkupcMD
         wo/KPdhRduU33bnwNsoMbm2CJ03aWERnwAs+qRfgrJUMoJGKvw1EkOakNwzgDg8UfUq7
         zvkw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756153557; x=1756758357;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=4KM0t6rUXBZef7lchUKlpJJN1C8UW3jiS+Es8BaUBBE=;
        b=FghaRAfadLeHXOE1dj4NV82zbaSYFmOxyy6yftFtx6Bxh2j5kBM3qzIF3NFj6sRQLO
         yw9Yb5I8Je7gZQHz3KRm/0htVWSug/8iyfdAIeY0M8ElMmHfpw17V9kjwPUFtXCqxHts
         Yv/UMbGJljOMVwNGBnv29UDc/cT9ha+pWE4/x+y6WXGfR5G8YlOz5oBcxHDUA3LmlQqQ
         HqF7GoOIgIIkShogX1hoIwC4niDiGPp1RbtKeBpFWQQ4sWP9ZQsOUqLpwdPoZWciOgC0
         2zVD49rmznoE0EJHVrng8l8BBCNiHnuwLmTC591I+nckbul7B1j1QETWbhCKHfpltuSm
         +/eA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVBmKbNIf0tZRKBYU3WIdvpsaARHM/Ac8VdhqbA2qNV1pdDbZtw5CKSkJzfTYYIu0h28oma0A==@lfdr.de
X-Gm-Message-State: AOJu0YzBJF3Yp7HMLx0VUtYWCQ6JgQmeaIING9Lw/wOOP4MbFgMWulHU
	zW4EpDpzy5aCZ7WGQsWteh3HtufavGzs0g7AB+nwv93hsjaWZhWWJc6y
X-Google-Smtp-Source: AGHT+IER21KSWhnf4Ypw9zsadZLEWCepgyYvYnSq5Dy7A/PpKdFIe2CJ2LddtQyuQrRDQXFDwNO5LQ==
X-Received: by 2002:a05:6870:a70d:b0:30b:beb3:5420 with SMTP id 586e51a60fabf-314dcb33d68mr6411338fac.17.1756153556898;
        Mon, 25 Aug 2025 13:25:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZflXU0bIaa1o2K+E1fV2ZVFUJB5GBeH+nC3TAQPymJeGQ==
Received: by 2002:a05:6871:e008:b0:2ef:3020:be7e with SMTP id
 586e51a60fabf-314c225e2edls1307144fac.1.-pod-prod-06-us; Mon, 25 Aug 2025
 13:25:55 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWca4r3Fe2BKYOVf73hQDI2swcCaIe4+EhFy4Jsp+ICDcIvnwTE5gAXx7p20fZX9new3EggNkC7h9k=@googlegroups.com
X-Received: by 2002:a05:6871:81da:20b0:315:30b7:404b with SMTP id 586e51a60fabf-31530b741aamr1373131fac.40.1756153554950;
        Mon, 25 Aug 2025 13:25:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756153554; cv=none;
        d=google.com; s=arc-20240605;
        b=SX4YJMsJA60DiDezyrONWVBaNTHOptg3QWaz+GudoS4W3Wnv8ot02YinJHa+dNkBdk
         7A7m0FTSjqbVmkMAosXOlYbUQus7TOShJzf0ZwMFDgVt300AUYLl8POzaYXrmHBb/0yu
         Qu7oUQqckgJrGGL55NX/5SdJnvliBGctiFkUGbk4HRM0e60dBIDklvA4GQ+8zTBPqjlh
         kXIgBAInRl1X6WCp8WqZ6Mwebk5UqbNibw+iSm062iRVtpDSx9RcQdfsRNA9GYpO3639
         JR0fBjcF2SGMhdJ8c/6Qgo/GcycE2zfPgkQiny6y7GKIx20f/wI7jPsdT3ht2cAuBZLV
         fhRA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=uHTJ9s9YMvaM2p0Fv0kvWS50c+p1aRICOMM/MPFtDD8=;
        fh=d+GoPTlmu33D8YzMNxzEeUOBk4HhNGSLvAzcCqpwrJg=;
        b=ZXSNF1anXsHslKQxnH0MPXDgGp1UW5OkAoLKOSgKlw/mKJx2o7nOeY9HD1ZMCitCDX
         ES2JPt6lVl6pSaG6Ug/o9S5gSFcTywiE7QUxZhneh4Kx3d5TfzBG51FpSvHS8VkvEPDD
         LDkKLg7J1r+lN5EBNQG8nhZ7V16medylSpzkramWcQugr7Ei0yemsBQzApVmOF/xnjBT
         KmWDZTC30H9dcOS6ei1Byb0zVlOuXXgFaJEfTCHDjpamUop5SxbNCM17+fW3WX2yXGUG
         q6TWD5rs2CP0Vw1HX4NXxGzf8PhKQgD07KQpExuwtiGhGjIHS3i9N7Sclx+6nHfJedwE
         gqbQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=YkHyYmAC;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.11])
        by gmr-mx.google.com with ESMTPS id 586e51a60fabf-314f7628375si379713fac.0.2025.08.25.13.25.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Mon, 25 Aug 2025 13:25:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.11 as permitted sender) client-ip=192.198.163.11;
X-CSE-ConnectionGUID: +rAdlp0TRq6RGuHXD5nDFw==
X-CSE-MsgGUID: rsTEC+etTTekRkorahMPWw==
X-IronPort-AV: E=McAfee;i="6800,10657,11533"; a="68970242"
X-IronPort-AV: E=Sophos;i="6.18,214,1751266800"; 
   d="scan'208";a="68970242"
Received: from fmviesa008.fm.intel.com ([10.60.135.148])
  by fmvoesa105.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 25 Aug 2025 13:25:52 -0700
X-CSE-ConnectionGUID: mFiywEvyTiCAxUVk2a9p/Q==
X-CSE-MsgGUID: DHS3og96Q0yCJmHB4RsCnA==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.18,214,1751266800"; 
   d="scan'208";a="169779868"
Received: from bergbenj-mobl1.ger.corp.intel.com (HELO wieczorr-mobl1.intel.com) ([10.245.245.6])
  by fmviesa008-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 25 Aug 2025 13:25:30 -0700
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
Subject: [PATCH v5 01/19] kasan: sw_tags: Use arithmetic shift for shadow computation
Date: Mon, 25 Aug 2025 22:24:26 +0200
Message-ID: <7e314394fc5643def4cd4c6f34ebe09c85c43852.1756151769.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.50.1
In-Reply-To: <cover.1756151769.git.maciej.wieczor-retman@intel.com>
References: <cover.1756151769.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=YkHyYmAC;       spf=pass
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

From: Samuel Holland <samuel.holland@sifive.com>

Currently, kasan_mem_to_shadow() uses a logical right shift, which turns
canonical kernel addresses into non-canonical addresses by clearing the
high KASAN_SHADOW_SCALE_SHIFT bits. The value of KASAN_SHADOW_OFFSET is
then chosen so that the addition results in a canonical address for the
shadow memory.

For KASAN_GENERIC, this shift/add combination is ABI with the compiler,
because KASAN_SHADOW_OFFSET is used in compiler-generated inline tag
checks[1], which must only attempt to dereference canonical addresses.

However, for KASAN_SW_TAGS we have some freedom to change the algorithm
without breaking the ABI. Because TBI is enabled for kernel addresses,
the top bits of shadow memory addresses computed during tag checks are
irrelevant, and so likewise are the top bits of KASAN_SHADOW_OFFSET.
This is demonstrated by the fact that LLVM uses a logical right shift
in the tag check fast path[2] but a sbfx (signed bitfield extract)
instruction in the slow path[3] without causing any issues.

Using an arithmetic shift in kasan_mem_to_shadow() provides a number of
benefits:

1) The memory layout doesn't change but is easier to understand.
KASAN_SHADOW_OFFSET becomes a canonical memory address, and the shifted
pointer becomes a negative offset, so KASAN_SHADOW_OFFSET ==
KASAN_SHADOW_END regardless of the shift amount or the size of the
virtual address space.

2) KASAN_SHADOW_OFFSET becomes a simpler constant, requiring only one
instruction to load instead of two. Since it must be loaded in each
function with a tag check, this decreases kernel text size by 0.5%.

3) This shift and the sign extension from kasan_reset_tag() can be
combined into a single sbfx instruction. When this same algorithm change
is applied to the compiler, it removes an instruction from each inline
tag check, further reducing kernel text size by an additional 4.6%.

These benefits extend to other architectures as well. On RISC-V, where
the baseline ISA does not shifted addition or have an equivalent to the
sbfx instruction, loading KASAN_SHADOW_OFFSET is reduced from 3 to 2
instructions, and kasan_mem_to_shadow(kasan_reset_tag(addr)) similarly
combines two consecutive right shifts.

Link: https://github.com/llvm/llvm-project/blob/llvmorg-20-init/llvm/lib/Transforms/Instrumentation/AddressSanitizer.cpp#L1316 [1]
Link: https://github.com/llvm/llvm-project/blob/llvmorg-20-init/llvm/lib/Transforms/Instrumentation/HWAddressSanitizer.cpp#L895 [2]
Link: https://github.com/llvm/llvm-project/blob/llvmorg-20-init/llvm/lib/Target/AArch64/AArch64AsmPrinter.cpp#L669 [3]
Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
Changelog v5: (Maciej)
- (u64) -> (unsigned long) in report.c

Changelog v4: (Maciej)
- Revert x86 to signed mem_to_shadow mapping.
- Remove last two paragraphs since they were just poorer duplication of
  the comments in kasan_non_canonical_hook().

Changelog v3: (Maciej)
- Fix scripts/gdb/linux/kasan.py so the new signed mem_to_shadow() is
  reflected there.
- Fix Documentation/arch/arm64/kasan-offsets.sh to take new offsets into
  account.
- Made changes to the kasan_non_canonical_hook() according to upstream
  discussion. Settled on overflow on both ranges and separate checks for
  x86 and arm.

Changelog v2: (Maciej)
- Correct address range that's checked in kasan_non_canonical_hook().
  Adjust the comment inside.
- Remove part of comment from arch/arm64/include/asm/memory.h.
- Append patch message paragraph about the overflow in
  kasan_non_canonical_hook().

 Documentation/arch/arm64/kasan-offsets.sh |  8 +++--
 arch/arm64/Kconfig                        | 10 +++----
 arch/arm64/include/asm/memory.h           | 14 ++++++++-
 arch/arm64/mm/kasan_init.c                |  7 +++--
 include/linux/kasan.h                     | 10 +++++--
 mm/kasan/report.c                         | 36 ++++++++++++++++++++---
 scripts/gdb/linux/kasan.py                |  3 ++
 scripts/gdb/linux/mm.py                   |  5 ++--
 8 files changed, 75 insertions(+), 18 deletions(-)
 mode change 100644 => 100755 Documentation/arch/arm64/kasan-offsets.sh

diff --git a/Documentation/arch/arm64/kasan-offsets.sh b/Documentation/arch/arm64/kasan-offsets.sh
old mode 100644
new mode 100755
index 2dc5f9e18039..ce777c7c7804
--- a/Documentation/arch/arm64/kasan-offsets.sh
+++ b/Documentation/arch/arm64/kasan-offsets.sh
@@ -5,8 +5,12 @@
 
 print_kasan_offset () {
 	printf "%02d\t" $1
-	printf "0x%08x00000000\n" $(( (0xffffffff & (-1 << ($1 - 1 - 32))) \
-			- (1 << (64 - 32 - $2)) ))
+	if [[ $2 -ne 4 ]] then
+		printf "0x%08x00000000\n" $(( (0xffffffff & (-1 << ($1 - 1 - 32))) \
+				- (1 << (64 - 32 - $2)) ))
+	else
+		printf "0x%08x00000000\n" $(( (0xffffffff & (-1 << ($1 - 1 - 32))) ))
+	fi
 }
 
 echo KASAN_SHADOW_SCALE_SHIFT = 3
diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index e9bbfacc35a6..82cbfc7d1233 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -431,11 +431,11 @@ config KASAN_SHADOW_OFFSET
 	default 0xdffffe0000000000 if ARM64_VA_BITS_42 && !KASAN_SW_TAGS
 	default 0xdfffffc000000000 if ARM64_VA_BITS_39 && !KASAN_SW_TAGS
 	default 0xdffffff800000000 if ARM64_VA_BITS_36 && !KASAN_SW_TAGS
-	default 0xefff800000000000 if (ARM64_VA_BITS_48 || (ARM64_VA_BITS_52 && !ARM64_16K_PAGES)) && KASAN_SW_TAGS
-	default 0xefffc00000000000 if (ARM64_VA_BITS_47 || ARM64_VA_BITS_52) && ARM64_16K_PAGES && KASAN_SW_TAGS
-	default 0xeffffe0000000000 if ARM64_VA_BITS_42 && KASAN_SW_TAGS
-	default 0xefffffc000000000 if ARM64_VA_BITS_39 && KASAN_SW_TAGS
-	default 0xeffffff800000000 if ARM64_VA_BITS_36 && KASAN_SW_TAGS
+	default 0xffff800000000000 if (ARM64_VA_BITS_48 || (ARM64_VA_BITS_52 && !ARM64_16K_PAGES)) && KASAN_SW_TAGS
+	default 0xffffc00000000000 if (ARM64_VA_BITS_47 || ARM64_VA_BITS_52) && ARM64_16K_PAGES && KASAN_SW_TAGS
+	default 0xfffffe0000000000 if ARM64_VA_BITS_42 && KASAN_SW_TAGS
+	default 0xffffffc000000000 if ARM64_VA_BITS_39 && KASAN_SW_TAGS
+	default 0xfffffff800000000 if ARM64_VA_BITS_36 && KASAN_SW_TAGS
 	default 0xffffffffffffffff
 
 config UNWIND_TABLES
diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
index 5213248e081b..277d56ceeb01 100644
--- a/arch/arm64/include/asm/memory.h
+++ b/arch/arm64/include/asm/memory.h
@@ -89,7 +89,15 @@
  *
  * KASAN_SHADOW_END is defined first as the shadow address that corresponds to
  * the upper bound of possible virtual kernel memory addresses UL(1) << 64
- * according to the mapping formula.
+ * according to the mapping formula. For Generic KASAN, the address in the
+ * mapping formula is treated as unsigned (part of the compiler's ABI), so the
+ * end of the shadow memory region is at a large positive offset from
+ * KASAN_SHADOW_OFFSET. For Software Tag-Based KASAN, the address in the
+ * formula is treated as signed. Since all kernel addresses are negative, they
+ * map to shadow memory below KASAN_SHADOW_OFFSET, making KASAN_SHADOW_OFFSET
+ * itself the end of the shadow memory region. (User pointers are positive and
+ * would map to shadow memory above KASAN_SHADOW_OFFSET, but shadow memory is
+ * not allocated for them.)
  *
  * KASAN_SHADOW_START is defined second based on KASAN_SHADOW_END. The shadow
  * memory start must map to the lowest possible kernel virtual memory address
@@ -100,7 +108,11 @@
  */
 #if defined(CONFIG_KASAN_GENERIC) || defined(CONFIG_KASAN_SW_TAGS)
 #define KASAN_SHADOW_OFFSET	_AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
+#ifdef CONFIG_KASAN_GENERIC
 #define KASAN_SHADOW_END	((UL(1) << (64 - KASAN_SHADOW_SCALE_SHIFT)) + KASAN_SHADOW_OFFSET)
+#else
+#define KASAN_SHADOW_END	KASAN_SHADOW_OFFSET
+#endif
 #define _KASAN_SHADOW_START(va)	(KASAN_SHADOW_END - (UL(1) << ((va) - KASAN_SHADOW_SCALE_SHIFT)))
 #define KASAN_SHADOW_START	_KASAN_SHADOW_START(vabits_actual)
 #define PAGE_END		KASAN_SHADOW_START
diff --git a/arch/arm64/mm/kasan_init.c b/arch/arm64/mm/kasan_init.c
index d541ce45daeb..dc2de12c4f26 100644
--- a/arch/arm64/mm/kasan_init.c
+++ b/arch/arm64/mm/kasan_init.c
@@ -198,8 +198,11 @@ static bool __init root_level_aligned(u64 addr)
 /* The early shadow maps everything to a single page of zeroes */
 asmlinkage void __init kasan_early_init(void)
 {
-	BUILD_BUG_ON(KASAN_SHADOW_OFFSET !=
-		KASAN_SHADOW_END - (1UL << (64 - KASAN_SHADOW_SCALE_SHIFT)));
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
+		BUILD_BUG_ON(KASAN_SHADOW_OFFSET !=
+			KASAN_SHADOW_END - (1UL << (64 - KASAN_SHADOW_SCALE_SHIFT)));
+	else
+		BUILD_BUG_ON(KASAN_SHADOW_OFFSET != KASAN_SHADOW_END);
 	BUILD_BUG_ON(!IS_ALIGNED(_KASAN_SHADOW_START(VA_BITS), SHADOW_ALIGN));
 	BUILD_BUG_ON(!IS_ALIGNED(_KASAN_SHADOW_START(VA_BITS_MIN), SHADOW_ALIGN));
 	BUILD_BUG_ON(!IS_ALIGNED(KASAN_SHADOW_END, SHADOW_ALIGN));
diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 890011071f2b..b396feca714f 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -61,8 +61,14 @@ int kasan_populate_early_shadow(const void *shadow_start,
 #ifndef kasan_mem_to_shadow
 static inline void *kasan_mem_to_shadow(const void *addr)
 {
-	return (void *)((unsigned long)addr >> KASAN_SHADOW_SCALE_SHIFT)
-		+ KASAN_SHADOW_OFFSET;
+	void *scaled;
+
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC))
+		scaled = (void *)((unsigned long)addr >> KASAN_SHADOW_SCALE_SHIFT);
+	else
+		scaled = (void *)((long)addr >> KASAN_SHADOW_SCALE_SHIFT);
+
+	return KASAN_SHADOW_OFFSET + scaled;
 }
 #endif
 
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 62c01b4527eb..50d487a0687a 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -642,11 +642,39 @@ void kasan_non_canonical_hook(unsigned long addr)
 	const char *bug_type;
 
 	/*
-	 * All addresses that came as a result of the memory-to-shadow mapping
-	 * (even for bogus pointers) must be >= KASAN_SHADOW_OFFSET.
+	 * For Generic KASAN, kasan_mem_to_shadow() uses the logical right shift
+	 * and never overflows with the chosen KASAN_SHADOW_OFFSET values (on
+	 * both x86 and arm64). Thus, the possible shadow addresses (even for
+	 * bogus pointers) belong to a single contiguous region that is the
+	 * result of kasan_mem_to_shadow() applied to the whole address space.
 	 */
-	if (addr < KASAN_SHADOW_OFFSET)
-		return;
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC)) {
+		if (addr < (unsigned long)kasan_mem_to_shadow((void *)(0UL)) ||
+		    addr > (unsigned long)kasan_mem_to_shadow((void *)(~0UL)))
+			return;
+	}
+
+	/*
+	 * For Software Tag-Based KASAN, kasan_mem_to_shadow() uses the
+	 * arithmetic shift. Normally, this would make checking for a possible
+	 * shadow address complicated, as the shadow address computation
+	 * operation would overflow only for some memory addresses. However, due
+	 * to the chosen KASAN_SHADOW_OFFSET values and the fact the
+	 * kasan_mem_to_shadow() only operates on pointers with the tag reset,
+	 * the overflow always happens.
+	 *
+	 * For arm64, the top byte of the pointer gets reset to 0xFF. Thus, the
+	 * possible shadow addresses belong to a region that is the result of
+	 * kasan_mem_to_shadow() applied to the memory range
+	 * [0xFF000000000000, 0xFFFFFFFFFFFFFFFF]. Despite the overflow, the
+	 * resulting possible shadow region is contiguous, as the overflow
+	 * happens for both 0xFF000000000000 and 0xFFFFFFFFFFFFFFFF.
+	 */
+	if (IS_ENABLED(CONFIG_KASAN_SW_TAGS) && IS_ENABLED(CONFIG_ARM64)) {
+		if (addr < (unsigned long)kasan_mem_to_shadow((void *)(0xFFUL << 56)) ||
+		    addr > (unsigned long)kasan_mem_to_shadow((void *)(~0UL)))
+			return;
+	}
 
 	orig_addr = (unsigned long)kasan_shadow_to_mem((void *)addr);
 
diff --git a/scripts/gdb/linux/kasan.py b/scripts/gdb/linux/kasan.py
index 56730b3fde0b..fca39968d308 100644
--- a/scripts/gdb/linux/kasan.py
+++ b/scripts/gdb/linux/kasan.py
@@ -8,6 +8,7 @@
 
 import gdb
 from linux import constants, mm
+from ctypes import c_int64 as s64
 
 def help():
     t = """Usage: lx-kasan_mem_to_shadow [Hex memory addr]
@@ -39,6 +40,8 @@ class KasanMemToShadow(gdb.Command):
         else:
             help()
     def kasan_mem_to_shadow(self, addr):
+        if constants.CONFIG_KASAN_SW_TAGS:
+            addr = s64(addr)
         return (addr >> self.p_ops.KASAN_SHADOW_SCALE_SHIFT) + self.p_ops.KASAN_SHADOW_OFFSET
 
 KasanMemToShadow()
diff --git a/scripts/gdb/linux/mm.py b/scripts/gdb/linux/mm.py
index 7571aebbe650..2e63f3dedd53 100644
--- a/scripts/gdb/linux/mm.py
+++ b/scripts/gdb/linux/mm.py
@@ -110,12 +110,13 @@ class aarch64_page_ops():
         self.KERNEL_END = gdb.parse_and_eval("_end")
 
         if constants.LX_CONFIG_KASAN_GENERIC or constants.LX_CONFIG_KASAN_SW_TAGS:
+            self.KASAN_SHADOW_OFFSET = constants.LX_CONFIG_KASAN_SHADOW_OFFSET
             if constants.LX_CONFIG_KASAN_GENERIC:
                 self.KASAN_SHADOW_SCALE_SHIFT = 3
+                self.KASAN_SHADOW_END = (1 << (64 - self.KASAN_SHADOW_SCALE_SHIFT)) + self.KASAN_SHADOW_OFFSET
             else:
                 self.KASAN_SHADOW_SCALE_SHIFT = 4
-            self.KASAN_SHADOW_OFFSET = constants.LX_CONFIG_KASAN_SHADOW_OFFSET
-            self.KASAN_SHADOW_END = (1 << (64 - self.KASAN_SHADOW_SCALE_SHIFT)) + self.KASAN_SHADOW_OFFSET
+                self.KASAN_SHADOW_END = self.KASAN_SHADOW_OFFSET
             self.PAGE_END = self.KASAN_SHADOW_END - (1 << (self.vabits_actual - self.KASAN_SHADOW_SCALE_SHIFT))
         else:
             self.PAGE_END = self._PAGE_END(self.VA_BITS_MIN)
-- 
2.50.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/7e314394fc5643def4cd4c6f34ebe09c85c43852.1756151769.git.maciej.wieczor-retman%40intel.com.

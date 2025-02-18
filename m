Return-Path: <kasan-dev+bncBCMMDDFSWYCBBX4D2G6QMGQE2NMQTBI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 7A404A394D9
	for <lists+kasan-dev@lfdr.de>; Tue, 18 Feb 2025 09:16:33 +0100 (CET)
Received: by mail-qv1-xf3d.google.com with SMTP id 6a1803df08f44-6e670e4ecefsf67146636d6.0
        for <lists+kasan-dev@lfdr.de>; Tue, 18 Feb 2025 00:16:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739866592; cv=pass;
        d=google.com; s=arc-20240605;
        b=hSLZYtAUr+lOZB0KcjwohU+JJ3/Xp3WaVsinZx6Ac+w3/LPD7MDrRurlx+NNnZwedt
         qZ3+vVhFNAKIW/j+/kzmwatagZViZBoQahg5u3Opj/yjQ1Gshr/be7h23vdiZve1mLze
         dLZ609SkcFsQmWZYiS+FQ+sWZXHQ27TjLNowHz/rmNE8mFGdUK6YU4G99qs06YkAC1Hs
         lo0rCt2wvtHixD7SLCuJ/xe9Nj6jXPCGZo/5CphEIjU4iyelpP++wj4FqUut2lpOVjX8
         wNLlcgrqVh0s7yBM96yxYkc8swWX7SxGExfLaSQ7i00Dccz0yG49u39RSqgYqueBWHKl
         lG0Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=puXycY1GlpyJfkGdpySE1SHhkUDm+4W5SIoqTSQo4cc=;
        fh=Vkkr7/U4O3x+vh5wf8GiF+BaULa9KnqIcGn4+fPTKec=;
        b=eHfPRVNwgcNnY/jp/+vaA+BhdeA68HObGi5i5zD7HD40uyyMGiDMRIBNqR5sqb99sx
         oHW2+UjGiX5oEKTVAymU728krO/nrXd6+t7ABnfvqpJdH7XTeOQl/bpm3qdGWJfxq7cz
         2nX2TQP3O07BNmCIit9Z25mY9o05PAblIlyb61zfkVLWy0Hcbnt1nHi4n2/n59AKk8XF
         4MbSVF9jH416SL96iuXlG/Qhh3hODJ+KxBn9SPFxP+KdJPoyDmDzJK8Z/KqAfs5Dj7b5
         7+MIKcuW6Dt1IyQ2NqksO/VzZIa7NYxDni0nS3M2QkJz0QJrWWkdzO5QvWP4r7LjTN0P
         Fcdw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=UqszCxrr;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.16 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739866592; x=1740471392; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=puXycY1GlpyJfkGdpySE1SHhkUDm+4W5SIoqTSQo4cc=;
        b=nnpBPJFtb1QgjuED0qcWNT9PjYrENLqNZ5pW79jZakVqqODTYEE1w8Z80Ftr8Ep5ZL
         R14gJo4RHuzQOz4xeki3glL7wYA07A6YPWWlQgDud3K1IvbuQlrA+PmE/4xHeuMGPiJi
         JTotwfuogmajJKo1NCWY0SS3/edfLerUHTDykSow5mrrFaabqhk0bnU30vc2ZWPYutcy
         b+4HgyHSA/yOTbvPjX7uDaeNQMYx/E+/ZN4UTq/4K97ks/TuywMRdQYVNRe5/4NNV/y8
         oaEto58CW9O4TGiOkhk/QquFMRS/rneTJ1t+wEm6L7MMectO4FqxAPMOeBKm3xfA1HOB
         yEnQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739866592; x=1740471392;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=puXycY1GlpyJfkGdpySE1SHhkUDm+4W5SIoqTSQo4cc=;
        b=WbIHi3m3HHJOy6xiK1EBMWkW1kdvwFVk2DxbVpRO0XV4YeIa3UJx9A9GYUPyRrJvrN
         BR6AJp9QCzEVqTdrSV/RDvLw+2WdmvaEZbK4jE57szkyXvyOmlwb5UUqzAuN3ODslckj
         HYD+dK3EM+PwFZqsUTFXha7cUPkLYKJFlcQAqkBmSmFPRlHotnEawgiuD2uX70NUjrT6
         ZEZ6JLcSDDT3qIPW5OXyJ4DDCmznBVWMvhbUe91DduW4QB1VAcij2yhKXpYIxzGLxZII
         onp0fvbUFq0AP4D0OBDx87lWhEsWlhZsjYEFo+bMs0Q/WzQmTl3VAVT+fIwFMluu60pB
         Ukwg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXsuyWYftiY9Hx+j09aeAGrfIkpCdhPwztofaJrbaKcm5hM/u7xj3pUsf1GUrJ3cn2gxMr23A==@lfdr.de
X-Gm-Message-State: AOJu0YzHsPAMJoAvIPZTY76b7Ymqx0B99jon5YZ2+hK3tPJevMKYJLFR
	nd0/lPRsKJPb9VoFj9mbokecxRrHGgDEDDsIROoBJoZI9Tt4wHi1
X-Google-Smtp-Source: AGHT+IF9BBZoacQzoAYKUV4nRtOILBvR2qNIZ6uDor30BRtzqXZvuxXWsupmg3HswCnrrVdIayyMYA==
X-Received: by 2002:a05:6214:e81:b0:6d1:7433:3670 with SMTP id 6a1803df08f44-6e66cc88d7fmr183817156d6.4.1739866592027;
        Tue, 18 Feb 2025 00:16:32 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVGAIOmeFW+8scqCekTvbIEkZLePjoZZjh234VtRCrqdbQ==
Received: by 2002:a0c:fcd0:0:b0:6e4:430b:7a4c with SMTP id 6a1803df08f44-6e65c24deb0ls46838856d6.2.-pod-prod-06-us;
 Tue, 18 Feb 2025 00:16:30 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXT+XXwlfzBZAUPWLpJzfx2l+/+GfWpD9F6cVLh/dbjkc2IZWbolOq1cLDU/r77sp0LZlh+lmgiN+g=@googlegroups.com
X-Received: by 2002:a05:6122:3d10:b0:51f:4154:c1b2 with SMTP id 71dfb90a1353d-5209da3cd8fmr6259449e0c.2.1739866590702;
        Tue, 18 Feb 2025 00:16:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739866590; cv=none;
        d=google.com; s=arc-20240605;
        b=XLcwOCc/L5M8KOnEGTVzTZ9jPvZ/Sn/+U1ylbpb13wpjj3lQWj9cU02KuBwNYUf19h
         7QfU99/j8bmf9vnXUshKXMPpR935V0c6I0+c8oLqVykyvsH9EJ05F4BtnB61+czUJY50
         9/bNEn8XxnGumNzebAdl27YC05UnKRawTuyAIhnNcusc+DxM+LiVnXodi9NdeUbwAW8q
         4FFD6dRFEBDTPhq18TUuTItfTII9DgJ3M7D8cz760wIKVKNPYUqIBntwlczH/jbi2sP+
         usPSfu9jr9VrnSbWZY8b2mHFo1fCYwOZIgCj0970A6w3HZTreitQOf+HwcWs7RkDF2bt
         QOZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=4UWaJK9j0uxOk7/Ht+ykZYDM3eYd2BuweApyK6vGFZk=;
        fh=t/SH+Gg/XGt5WVAQfMl2l/LCcdyTZmDfR0ct3DuRE8Y=;
        b=L7Guowt1MgQ56uP977tpV7YKHNpqxMeVsVKwGMYhdSvPodRFlm261KXy+AbsjNzvXo
         Vh5D6BrPb25eP+cd0cFnrEqXnJBTMmYsdOULboLrjRsn4xymm5eRbeOX7DJgfw5h/8Nx
         8vjbe2QLJ10YiIOx9wIuQNsuFKuRQ/p8cmsuRC3QhlejJdiEwr+AY8K48SGncXGVcSlC
         jxQQmfd5NLyV9eqRHP/+RbBFHzbi45nKdVl/fqbMDnETalhg6Wf5DN5RsGDeFUhZ83zu
         pIMIN6EVHwUuO/XK10DThmIhElScdWvF0bmpP1sYu/0uRNAFbelDBsAPK6hVsfEIy8z2
         DdYw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=UqszCxrr;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.16 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [192.198.163.16])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-520a0c06428si305270e0c.3.2025.02.18.00.16.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Tue, 18 Feb 2025 00:16:29 -0800 (PST)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 192.198.163.16 as permitted sender) client-ip=192.198.163.16;
X-CSE-ConnectionGUID: 1lCvbVaSRziy+bwtgWSrsw==
X-CSE-MsgGUID: PWdKZFwARqyar9eFdc6njg==
X-IronPort-AV: E=McAfee;i="6700,10204,11348"; a="28149926"
X-IronPort-AV: E=Sophos;i="6.13,295,1732608000"; 
   d="scan'208";a="28149926"
Received: from orviesa003.jf.intel.com ([10.64.159.143])
  by fmvoesa110.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 18 Feb 2025 00:16:28 -0800
X-CSE-ConnectionGUID: QpgCH/c2Sdyz4OBPsrUblg==
X-CSE-MsgGUID: UKqCz034Qn2XEphi0iGvRQ==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.11,199,1725346800"; 
   d="scan'208";a="119247306"
Received: from ijarvine-mobl1.ger.corp.intel.com (HELO wieczorr-mobl1.intel.com) ([10.245.245.49])
  by ORVIESA003-auth.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 18 Feb 2025 00:16:10 -0800
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
Subject: [PATCH v2 01/14] kasan: sw_tags: Use arithmetic shift for shadow computation
Date: Tue, 18 Feb 2025 09:15:17 +0100
Message-ID: <168f775c4587f3a1338271390204a9fe16b150dd.1739866028.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.47.1
In-Reply-To: <cover.1739866028.git.maciej.wieczor-retman@intel.com>
References: <cover.1739866028.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=UqszCxrr;       spf=pass
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

1) The memory layout is easier to understand. KASAN_SHADOW_OFFSET
becomes a canonical memory address, and the shifted pointer becomes a
negative offset, so KASAN_SHADOW_OFFSET == KASAN_SHADOW_END regardless
of the shift amount or the size of the virtual address space.

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

Due to signed memory-to-shadow mapping kasan_non_canonical_hook() needs
changes - specifically the first part that tries to deduce if a faulty
address came from kasan_mem_to_shadow(). Previous value of
KASAN_SHADOW_OFFSET prevented any overflows when trying to map the
entire linear address space to shadow memory so the check in
kasan_non_canonical_hook() could consist of only checking whether the
address isn't below KASAN_SHADOW_OFFSET.

The signed memory-to-shadow conversion means negative addresses will be
mapped below KASAN_SHADOW_OFFSET and positive addresses will map above
KASAN_SHADOW_OFFSET. When looking at the mapping of the entire address
space there will be an overflow when a big enough positive address will
be passed to kasan_mem_to_shadow(). Then the question of finding
addresses that couldn't come from kasan_mem_to_shadow() can be reduced
to figuring out if the address isn't above the highest overflowed value
(most positive address possible) AND below the most negative address
possible.

Link: https://github.com/llvm/llvm-project/blob/llvmorg-20-init/llvm/lib/Transforms/Instrumentation/AddressSanitizer.cpp#L1316 [1]
Link: https://github.com/llvm/llvm-project/blob/llvmorg-20-init/llvm/lib/Transforms/Instrumentation/HWAddressSanitizer.cpp#L895 [2]
Link: https://github.com/llvm/llvm-project/blob/llvmorg-20-init/llvm/lib/Target/AArch64/AArch64AsmPrinter.cpp#L669 [3]
Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
Changelog v2: (Maciej)
- Correct address range that's checked in kasan_non_canonical_hook().
  Adjust the comment inside.
- Remove part of comment from arch/arm64/include/asm/memory.h.
- Append patch message paragraph about the overflow in
  kasan_non_canonical_hook().

 arch/arm64/Kconfig              | 10 +++++-----
 arch/arm64/include/asm/memory.h | 14 +++++++++++++-
 arch/arm64/mm/kasan_init.c      |  7 +++++--
 include/linux/kasan.h           | 10 ++++++++--
 mm/kasan/report.c               | 26 ++++++++++++++++++++++----
 scripts/gdb/linux/mm.py         |  5 +++--
 6 files changed, 56 insertions(+), 16 deletions(-)

diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index fcdd0ed3eca8..fe7d79b447c3 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -426,11 +426,11 @@ config KASAN_SHADOW_OFFSET
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
index 717829df294e..e71cdf036287 100644
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
index b65a29440a0c..6836e571555c 100644
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
index 3fe77a360f1c..5766714872d3 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -645,15 +645,33 @@ void kasan_report_async(void)
  */
 void kasan_non_canonical_hook(unsigned long addr)
 {
+	unsigned long max_shadow_size = BIT(BITS_PER_LONG - KASAN_SHADOW_SCALE_SHIFT);
 	unsigned long orig_addr;
 	const char *bug_type;
 
 	/*
-	 * All addresses that came as a result of the memory-to-shadow mapping
-	 * (even for bogus pointers) must be >= KASAN_SHADOW_OFFSET.
+	 * With the default kasan_mem_to_shadow() algorithm, all addresses
+	 * returned by the memory-to-shadow mapping (even for bogus pointers)
+	 * must be within a certain displacement from KASAN_SHADOW_OFFSET.
+	 *
+	 * For Generic KASAN the displacement is unsigned so the mapping from zero
+	 * to the last kernel address needs checking.
+	 *
+	 * For Software Tag-Based KASAN, the displacement is signed, so
+	 * KASAN_SHADOW_OFFSET is the center of the range. Higher positive
+	 * addresses overflow, so the range that can't be part of
+	 * memory-to-shadow mapping is above the biggest positive address
+	 * mapping and below the lowest possible one.
 	 */
-	if (addr < KASAN_SHADOW_OFFSET)
-		return;
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC)) {
+		if (addr < KASAN_SHADOW_OFFSET ||
+		    addr >= KASAN_SHADOW_OFFSET + max_shadow_size)
+			return;
+	} else {
+		if (addr < KASAN_SHADOW_OFFSET - max_shadow_size / 2 &&
+		    addr >= KASAN_SHADOW_OFFSET + max_shadow_size / 2)
+			return;
+	}
 
 	orig_addr = (unsigned long)kasan_shadow_to_mem((void *)addr);
 
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
2.47.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/168f775c4587f3a1338271390204a9fe16b150dd.1739866028.git.maciej.wieczor-retman%40intel.com.

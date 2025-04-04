Return-Path: <kasan-dev+bncBCMMDDFSWYCBBWNWX67QMGQER7LXN7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1038.google.com (mail-pj1-x1038.google.com [IPv6:2607:f8b0:4864:20::1038])
	by mail.lfdr.de (Postfix) with ESMTPS id 9A1F3A7BD56
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Apr 2025 15:15:07 +0200 (CEST)
Received: by mail-pj1-x1038.google.com with SMTP id 98e67ed59e1d1-30364fc706fsf1991518a91.3
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Apr 2025 06:15:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1743772506; cv=pass;
        d=google.com; s=arc-20240605;
        b=TD5Fbz1B9JQ9R9zoqOZx4VUQkFqbe41PfgZP21dh6tO5on+UqwyuEJPi17ne0N4yxr
         0sGnik10rjNYldHhLTlRNFcBVQtUKoOrTghNADfsS/fYC/bBj2OBwF7H9A3jp/VBAFsE
         w0XykHBy5YUy7zfPsbavzb7uXr4myppbqzTqMSYm2qLIrMrVRKBNGv1PpR6T2nEsmjGW
         hxTSQ4BqQVG8rbdhAdNB9aRzKCoz3CCLGsXXypFTaSAY+llPkoJ8ZMVAowbXRsKY/7xI
         YByTBXdy6WXfBdu1rvrjfJR5V5fJhwwE97vjdfnTYEudpkL3hcAYe+Jj6rq6YvqFne0A
         l9fg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=REK1fUwLPS9yg+GTzSy8quVDMOVbuSwYFf6beOvKxsY=;
        fh=sZB9pBwqL8Wo284ydztt8/5blfrlrvpsWd8yFb6f9lM=;
        b=BbYeHA64UUB1renXOMeqZR7IMYGnv63uMzc8m4ymGJK8HvXKwbfFoZoLwiItODjdkp
         jEineNYqz9KdiXCW4WRRg8wVx7miyQJ6RVKduqV5gbF7GrHLA+W6OfoNqcfw6NYFNlNJ
         23Jg02qCcUxeEsjEIDdqdPpeBvYyG2Z3nXS2PMbC11iMR+7eZWxdNWUPV4oyg7nPzeGz
         bb0aIVPTAlTuI14RjHLSVn82QxY4waS/XZxsC47RZsNHXTOv3UVx6Y4dJJoV8s+s36fm
         i5bEyQv42vol4HpWQiLzI8querwloI0YwzkQv6l1x87p/mrAZr8PaKv0yPEOVNJnpnvq
         F+Sg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=CYxHg1CJ;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1743772506; x=1744377306; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=REK1fUwLPS9yg+GTzSy8quVDMOVbuSwYFf6beOvKxsY=;
        b=NWsc+AKJ7sBFynM76KMk5/9EjNi6NykH+e+NS0Mr2GJYRyo+4Ia1qC9gxNHiHK7K6K
         Y8LP91YNrO2fqzcVx/u5zI0tmcZWJUncU6JmpM7XNVUtUSYndXGfaCSzzOfLI86WoJxF
         t4NjrpX2jKUwhNnjEmk1boCzztd8lE6+pjqOJl3bHbuvJKcxe3mbwEkG05ZvM0eT1my8
         far01ipnDBWMCOZC0mv03LzVKtibMaYF8kUp7l47rRzuCuO2lGuiiOASknzCVSWrJ44U
         z0pN+YJWona8J6ojlelsbGdzzlRFS30kv7acmUSIk9+PKhmphz3U93wr4bv/Qx2h886z
         XyNw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1743772506; x=1744377306;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=REK1fUwLPS9yg+GTzSy8quVDMOVbuSwYFf6beOvKxsY=;
        b=TrC8FFvRqWtqTTxuFEQ+sslwq+FvTdgKfwp55k3o+YygRhNAy/Xj/C7Fwk3jO29ogU
         Yj03+Khf9XQDu9zUDTLxGrYLl1/p5Iqe6Ut+M/XA7fdq7E5wpQeA3D/I9IJ5FhdZftro
         SrTGaXLbwo2cT3R8U6sB/tK4CLYeSSUTqO9bwiUUwve3G5lXv6oCrLUxSIkgr9yYFBIO
         TcTr8qjHCx8SncnyFmaK9o0bcrRELAsmHECzXU2AYA2FG2FwKOq4k16oBpzeve68xOx6
         hAVmO9CgB/mlG59KedbFQj95NfQozVvWgr7dAsz22niZRp0MZQwYL//oxd2LfPKopZ8c
         cFog==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVQ1SZ5+2LJLjkuKM11DCYhUU4d48kou09YjCMjFekglHqZH6Y5bDpDqSpsm1dj63bKGDaX1A==@lfdr.de
X-Gm-Message-State: AOJu0YwNMkea7s2HUI6o0EeZv9HaBKvlLEuuU39dwqyiHu29uUU06D88
	4500oWVZB6kGTNwvzuML8ILH6nECEWPlDal64Q2cqD/EByxZCBeS
X-Google-Smtp-Source: AGHT+IHwgN/2KOPA84uEnaXiD76rp0Fukztb8Erl1T6nmjk5YVJ8YXsaGGqHnlT3T+wqedYGqPxs0Q==
X-Received: by 2002:a17:90a:d643:b0:2f4:49d8:e6f6 with SMTP id 98e67ed59e1d1-306a4822fe2mr4632082a91.3.1743772505685;
        Fri, 04 Apr 2025 06:15:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARLLPAJFrWLH+QOIBSKe50Ot41KqSRb0ddEilYwNF2o5rAqlGA==
Received: by 2002:a17:90b:4d0d:b0:2fa:5303:b1e3 with SMTP id
 98e67ed59e1d1-30579fa1f6als2512810a91.1.-pod-prod-01-us; Fri, 04 Apr 2025
 06:15:04 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCV/Zyvr/NvW62osFLIDF8W1wFpaKT+TgrtWtHGEwYyInVYnl/Tk5VzRJwv/ryMOwMBSkU9Xark4plU=@googlegroups.com
X-Received: by 2002:a05:6a20:7f9f:b0:1f5:7f2e:5c3c with SMTP id adf61e73a8af0-2010447b4a6mr5269642637.1.1743772504253;
        Fri, 04 Apr 2025 06:15:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1743772504; cv=none;
        d=google.com; s=arc-20240605;
        b=hw2DaZ7vqiD/wWYrDbHOZGNE+K/4eLaq6YeKvmAhV9WU/pnQU48bvZv5FNiVmWQy9e
         8UFxKrwATodc6FVbBViU3EPut76eb7eQIJCKLtjuja4jXo/a7XKodZ93UaTeZ5CnjofA
         BEaAvXappIYziFZbTSTVFruHkYIT7OyHx+lt6B9MeLqCYUOmrYEdkCHvKNjfFuIsgMvL
         sVaGK7/WUNUOsjj6bjwaW5YdVP0npUIB/2eiyK7gta4eglw2POeCxt5i5Sj9YC1Jyhim
         WDlcf3d4f3WiKhqwfIOZ5u8ytlUTQymSqNRHpOpb3gk/TXSEUClqNtF1W9b+zYNl+d/r
         BiyQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=ihdcaXotD4FXvEuiFCQbYKqP3O7bZOZ0FEbpCWYNaAI=;
        fh=J7nw2tc4gzRvdzI0P/GwtR3jWmwmM/GxmLt8uthQMV0=;
        b=ERYnZ25ntu7w+I8N/9/9EYyQcOOWFHaDncuPyQJPNO1IDzfDJEpEaEIIOE1+IWt5KW
         llZjvvqarNMPCcSXszmlqpN9Lrfsyzh3Z5qkqpqAgVGgs2mDGrEE9DGFw2IreGArdufy
         yos4gsxF6KovmhV084JQ3X6vVgQ7hHf8lVodFBFefaRWcRqv3j5dtwGtYO3nhLaExCC1
         d68A7yCvZQpvKILIES6M0ijCJyO0b1IF+2CCOyxXy5UZBo/Mo45LXTV8rnbbSaUZJzlr
         BWi+bwOKOGVLtGdpM636dQa2Wive0mw9mHYoAIo7OIO8dhjFtcVFz/GIQvEpAADz1/LM
         YTfA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@intel.com header.s=Intel header.b=CYxHg1CJ;
       spf=pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.11 as permitted sender) smtp.mailfrom=maciej.wieczor-retman@intel.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=intel.com
Received: from mgamail.intel.com (mgamail.intel.com. [198.175.65.11])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-af9bc3035b6si145857a12.2.2025.04.04.06.15.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-CHACHA20-POLY1305 bits=256/256);
        Fri, 04 Apr 2025 06:15:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of maciej.wieczor-retman@intel.com designates 198.175.65.11 as permitted sender) client-ip=198.175.65.11;
X-CSE-ConnectionGUID: r4T1F4WvSHWnGp2oADbLhA==
X-CSE-MsgGUID: 3/LaFA63Ru+wb60q2mrEPQ==
X-IronPort-AV: E=McAfee;i="6700,10204,11394"; a="55401530"
X-IronPort-AV: E=Sophos;i="6.15,188,1739865600"; 
   d="scan'208";a="55401530"
Received: from fmviesa009.fm.intel.com ([10.60.135.149])
  by orvoesa103.jf.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Apr 2025 06:15:02 -0700
X-CSE-ConnectionGUID: B+Uv8UewR2C2T90dooccjw==
X-CSE-MsgGUID: un9CLlJUT4SPzaTveK3NUg==
X-ExtLoop1: 1
X-IronPort-AV: E=Sophos;i="6.15,188,1739865600"; 
   d="scan'208";a="128156919"
Received: from opintica-mobl1 (HELO wieczorr-mobl1.intel.com) ([10.245.245.50])
  by fmviesa009-auth.fm.intel.com with ESMTP/TLS/ECDHE-RSA-AES256-GCM-SHA384; 04 Apr 2025 06:14:47 -0700
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
Subject: [PATCH v3 01/14] kasan: sw_tags: Use arithmetic shift for shadow computation
Date: Fri,  4 Apr 2025 15:14:05 +0200
Message-ID: <d411f0b3f3fe3b6e96773e704e83cd08092db042.1743772053.git.maciej.wieczor-retman@intel.com>
X-Mailer: git-send-email 2.49.0
In-Reply-To: <cover.1743772053.git.maciej.wieczor-retman@intel.com>
References: <cover.1743772053.git.maciej.wieczor-retman@intel.com>
MIME-Version: 1.0
X-Original-Sender: maciej.wieczor-retman@intel.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@intel.com header.s=Intel header.b=CYxHg1CJ;       spf=pass
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

Make changes to kasan_non_canonical_hook() - specifically the first part
that tries to deduce if a faulty address came from
kasan_mem_to_shadow().

Link: https://github.com/llvm/llvm-project/blob/llvmorg-20-init/llvm/lib/Transforms/Instrumentation/AddressSanitizer.cpp#L1316 [1]
Link: https://github.com/llvm/llvm-project/blob/llvmorg-20-init/llvm/lib/Transforms/Instrumentation/HWAddressSanitizer.cpp#L895 [2]
Link: https://github.com/llvm/llvm-project/blob/llvmorg-20-init/llvm/lib/Target/AArch64/AArch64AsmPrinter.cpp#L669 [3]
Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
---
Changelog v3: (Maciej)
- Fix scripts/gdb/linux/kasan.py so the new signed mem_to_shadow() is
  reflected there.
- Fix Documentation/arch/arm64/kasan-offsets.sh to take new offsets into
  account.
- Made changes to the kasan_non_canonical_hook() according to upstream
  discussion. Moved x86 part to separate patch later.

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
index 62dc903ecc7f..10e215d6e435 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -428,11 +428,11 @@ config KASAN_SHADOW_OFFSET
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
index 8357e1a33699..f24f11cc644a 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -681,11 +681,39 @@ void kasan_non_canonical_hook(unsigned long addr)
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
+		if (addr < (u64)kasan_mem_to_shadow((void *)(0UL)) ||
+		    addr > (u64)kasan_mem_to_shadow((void *)(~0UL)))
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
+		if (addr < (u64)kasan_mem_to_shadow((void *)(0xFFUL << 56)) ||
+		    addr > (u64)kasan_mem_to_shadow((void *)(~0UL)))
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
2.49.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/d411f0b3f3fe3b6e96773e704e83cd08092db042.1743772053.git.maciej.wieczor-retman%40intel.com.

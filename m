Return-Path: <kasan-dev+bncBCMIFTP47IJBBN7C6G2QMGQEVNIVOUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id 883B995171E
	for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 10:56:25 +0200 (CEST)
Received: by mail-pj1-x103d.google.com with SMTP id 98e67ed59e1d1-2cb600e1169sf6652262a91.1
        for <lists+kasan-dev@lfdr.de>; Wed, 14 Aug 2024 01:56:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1723625784; cv=pass;
        d=google.com; s=arc-20160816;
        b=SAox0tysOI3toucT0PNOBVuvXJbIuau/xVBu9Wzs1fZ51QVV7OBOL2RUyBw/WSbvsG
         L7NkmjeHHbc/McZsZRwTG3iXOH+Y2vb4/vpCVbe5k2yi+jw31uq6vdtsYPthlgruhyRv
         2aSLE7Z/wcblWG6iBZcRnlZusOUEPB1wtuZCA83DKfIn4STU/d8+5UovMc/uMs3ewYn+
         yqvpeOsoQ/8uUG2dARhPYjsCWOSBA4BY+mOK1Nhf3+5UxNYNYrR3TS0RxmScNDuUJNgg
         enaJyad14Uxzv4K1UCHhZI/TnRx3UIR9RT2tNTwO2mGR+J3//u2kl0I7gYTpDOSc8beM
         pYuQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=b7y3lGx8VbP4UebBt8oV2mlAbYdiP4FD1p62iRv+4Go=;
        fh=dHkF+oRH4BleyEeQP8tuy/NH9B/M6cMLcKBUcc3D6GE=;
        b=BuZp2iMqMbN9Ff8TU6B7bEggSUIow3rUlceMB5pGdhE5hf64c6BLUpjy6QS3vRCXKO
         AsXRWz5lqn6o34iXBrHs/KHfZck2RbsgS7KJMslSQTMNdVw97U1jREWyIOFV+yau0Rx3
         w7ldWK+xoMGEEyK5xUVwzNeW5mRsEF/9ytWANEdkg98LnRqFaWGzl+LpgSzzqZS6tJL7
         vIRK0CZdmYGepbN/Ca7RoG3yLaPAhun7ywYvgS433+lBqd9yxcP9kns9kDI/qW6sLhgQ
         ON9az4QhXHgjLjKPEAF2RgwpYYrkigeyYFRxs2dI3jAKERsfYqIjXJua5qct0Z508zr1
         tSzA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=TbnVqB2z;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1723625784; x=1724230584; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=b7y3lGx8VbP4UebBt8oV2mlAbYdiP4FD1p62iRv+4Go=;
        b=S9qHhvmYyg4weB1rN2kpure6CSh8dfypbzy0ickaOrsyRNm7vohfLqxJsoHIAtoaWI
         Ka1gvdFatM4j8IE5O/rplgy+ZHROo4Rj6X+5Nlv6oBxw2jJD9/aWqUqMgsgMxEwyUG40
         GD10p9tbFAPl54gWhsGB8fSD0V1d/tB4DB9GlJgE98j1ZBBfozHcrYeA3UmP8z7XxW+R
         4gbj3hpCh+u6UQ5VgMbziSXQXASzrMxBEAGsEKffQ1I9/WZVNtnVXxatTYFLF66UW2/U
         SrDZ7xkotJSe6zdLVBkaj0UWQKMK1u68Iv2a4mXjH9/ly6tHLrFYwGzgsHfC+X9tPxZs
         t2Ig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1723625784; x=1724230584;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=b7y3lGx8VbP4UebBt8oV2mlAbYdiP4FD1p62iRv+4Go=;
        b=X2HVLw/PCEhGTiSG6nH7ESwPoQZs3aQ0sgr4x4gooP4jGc+SLoCGs+eW+6p3kLnURE
         pcGMVHde1EUdgWP7vl6rkf8GP4a8Y5IwSmAOdsq9N6LSDkzgwNWWWxpj+morTQ5pHGfE
         9CuGmzwadFynQ5O4kOg4ngAq7aJciSbb0mJZX1xltjYnx1BHGmNSEdAeq7vK3mnb2PPX
         SaQeMIT/W8EKa4OgJOjoVIX769g1w9cOz7cq57elluoynDQJQeBBLJxzwJwobGo3Pxgb
         5xwA+r+dXRzz/GuXyLmlp+8iAd+BGBDRtry9S+epBTLFkluU4NaotJ2/B+vcSUuh75Nw
         hECA==
X-Forwarded-Encrypted: i=2; AJvYcCUK5DtimsOY7DzjEJKC16gi2GR5S28h7KrRXiGuVoW72jtXKtwwqYSwUfoeNzRKJUDVYc3+qvi5Rn/sGuZfL3L7k2/LHb2xxg==
X-Gm-Message-State: AOJu0YwQHlYF1j0BrnUhWjfR8kL1VxvHmG2/TdcAir3NdCywmakDJnDE
	7KDDLGxtWKV7ifwS31PklFciOZgrmVJTjcQH4NGP7vqJ/8PTUQRK
X-Google-Smtp-Source: AGHT+IGc2+chyqe4DGeM49uNLCZ++L++34OQYfI0FfmWi6j0OO+g4SHp9EPikIEo01C4YyFF8U/SAg==
X-Received: by 2002:a17:90a:cf83:b0:2c8:65cf:e820 with SMTP id 98e67ed59e1d1-2d3aaa7a002mr2202677a91.2.1723625783975;
        Wed, 14 Aug 2024 01:56:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:680c:b0:2cb:5bad:6b1a with SMTP id
 98e67ed59e1d1-2d1bb868886ls3328949a91.0.-pod-prod-05-us; Wed, 14 Aug 2024
 01:56:22 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUDu/bwsHURdQ652/c5eX02tpcxPBqTBGwwVUpVrsqu/DtTEYKbW4POqAmhgeAUvOkjerJonUxVY7JxZ5YuxuovZzZ4gkkoIVyiLA==
X-Received: by 2002:a17:90a:c908:b0:2cf:cbc7:91ec with SMTP id 98e67ed59e1d1-2d3aaabb958mr2376258a91.23.1723625782671;
        Wed, 14 Aug 2024 01:56:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1723625782; cv=none;
        d=google.com; s=arc-20240605;
        b=OalzHZK7poA00cGZhIPD8NvG03K0fpTLbyRRRmh89yy7I8fm3scjhDflTR3zANqSMF
         b4AqBRET3d+8L+qYNlHpldWtIdAlBJ7H7DUNYGfoKmUS0L6y+DpqiSqIZCbWAvbA3yow
         0Nfxxxm8j9FOIs7LfUV1ipYkPfOWjaF1r5qW1DRtaxG1uQPZhF17G959EixjShq2h/jB
         Be3XBniEhYrSbu7x+/f8mzSBZyamMhqoEqzTgWJOPdwY940dWaK/dJWNf0f8d5FI4M7/
         5PhR3N3hLqYcW8EQVt2lOE3FIC7dyYAXm6ugIdyPeLemdCvacUpEfMlgsHQkB1ut/t0f
         ToKw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=O7k+MLTxwWAputjEjU3HfIE7+9GwjR6EFArU6PwcDFo=;
        fh=U3SnU+rVC7j9He9CiL0F672iI5RquTxp4Nyj5WKr3iY=;
        b=dfgXBmlyvROW8ZsE8M/t/3ZFUv40euVYbCfbVEPuGHRgTnNvrEjx7gFf8wVJnDGiU1
         Qkx9yos8lAPGINmfTr223NQrPU17LCEChSFPRh8fYKO/tZjcuhU0/LGLsHmrIJRaVfqk
         6vpljUeiC6cLaXcYT30jKTwZNhDidwUWMyeqfpM04ujWyPeo0BguleVp0SZwaCWYEngY
         JFou7yX6/f+1eHG44t3tvHILoeNztkSH7N7CiEtLS1tnjv0WedxIK9ujOr8IdFvk1McU
         3FX7GBCWVj7E+bm2ZCo0Sqg2W2WoOx5/rKWc0jmcXelqwcHHVbaSiBhwx+lsn81FR8m5
         QWVw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b=TbnVqB2z;
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x42e.google.com (mail-pf1-x42e.google.com. [2607:f8b0:4864:20::42e])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2d396a949f8si302706a91.0.2024.08.14.01.56.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 14 Aug 2024 01:56:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::42e as permitted sender) client-ip=2607:f8b0:4864:20::42e;
Received: by mail-pf1-x42e.google.com with SMTP id d2e1a72fcca58-710bdddb95cso3850798b3a.3
        for <kasan-dev@googlegroups.com>; Wed, 14 Aug 2024 01:56:22 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWQOA9B167r+us9Rpia1gtozX3o9YN4/Yzunbr4kuTHs4uqaefoUPGEL5MRMg0zsLXx8P0yZRgVis54P7QuRuyLs1eBGdTlBqPAUg==
X-Received: by 2002:a05:6a21:9206:b0:1c3:b1e2:f826 with SMTP id adf61e73a8af0-1c8eaf5ab1bmr2775585637.35.1723625782207;
        Wed, 14 Aug 2024 01:56:22 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-201cd14a7b8sm25439615ad.100.2024.08.14.01.56.20
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 14 Aug 2024 01:56:21 -0700 (PDT)
From: "'Samuel Holland' via kasan-dev" <kasan-dev@googlegroups.com>
To: Palmer Dabbelt <palmer@dabbelt.com>,
	linux-riscv@lists.infradead.org,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com
Cc: llvm@lists.linux.dev,
	linux-kernel@vger.kernel.org,
	Alexandre Ghiti <alexghiti@rivosinc.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org,
	Samuel Holland <samuel.holland@sifive.com>
Subject: [RFC PATCH 1/7] kasan: sw_tags: Use arithmetic shift for shadow computation
Date: Wed, 14 Aug 2024 01:55:29 -0700
Message-ID: <20240814085618.968833-2-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20240814085618.968833-1-samuel.holland@sifive.com>
References: <20240814085618.968833-1-samuel.holland@sifive.com>
MIME-Version: 1.0
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b=TbnVqB2z;       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::42e as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Samuel Holland <samuel.holland@sifive.com>
Reply-To: Samuel Holland <samuel.holland@sifive.com>
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

Link: https://github.com/llvm/llvm-project/blob/llvmorg-20-init/llvm/lib/Transforms/Instrumentation/AddressSanitizer.cpp#L1316 [1]
Link: https://github.com/llvm/llvm-project/blob/llvmorg-20-init/llvm/lib/Transforms/Instrumentation/HWAddressSanitizer.cpp#L895 [2]
Link: https://github.com/llvm/llvm-project/blob/llvmorg-20-init/llvm/lib/Target/AArch64/AArch64AsmPrinter.cpp#L669 [3]
Signed-off-by: Samuel Holland <samuel.holland@sifive.com>
---

 arch/arm64/Kconfig              | 10 +++++-----
 arch/arm64/include/asm/memory.h |  8 ++++++++
 arch/arm64/mm/kasan_init.c      |  7 +++++--
 include/linux/kasan.h           | 10 ++++++++--
 scripts/gdb/linux/mm.py         |  5 +++--
 5 files changed, 29 insertions(+), 11 deletions(-)

diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index a2f8ff354ca6..7df218cca168 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -402,11 +402,11 @@ config KASAN_SHADOW_OFFSET
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
index 54fb014eba05..3af8d1e721af 100644
--- a/arch/arm64/include/asm/memory.h
+++ b/arch/arm64/include/asm/memory.h
@@ -82,6 +82,10 @@
  * the mapping. Note that KASAN_SHADOW_OFFSET does not point to the start of
  * the shadow memory region.
  *
+ * For KASAN_GENERIC, addr is treated as unsigned. For KASAN_SW_TAGS, addr is
+ * treated as signed, so in that case KASAN_SHADOW_OFFSET points to the end of
+ * the shadow memory region.
+ *
  * Based on this mapping, we define two constants:
  *
  *     KASAN_SHADOW_START: the start of the shadow memory region;
@@ -100,7 +104,11 @@
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
index 70d6a8f6e25d..41f57e10ba03 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -58,8 +58,14 @@ int kasan_populate_early_shadow(const void *shadow_start,
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
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240814085618.968833-2-samuel.holland%40sifive.com.

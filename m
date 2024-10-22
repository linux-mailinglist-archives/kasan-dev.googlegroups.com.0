Return-Path: <kasan-dev+bncBCMIFTP47IJBB54N3S4AMGQEYVTEPXY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id C4D5A9A95C8
	for <lists+kasan-dev@lfdr.de>; Tue, 22 Oct 2024 03:59:20 +0200 (CEST)
Received: by mail-qt1-x83e.google.com with SMTP id d75a77b69052e-460d76f1d7esf33382371cf.2
        for <lists+kasan-dev@lfdr.de>; Mon, 21 Oct 2024 18:59:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1729562359; cv=pass;
        d=google.com; s=arc-20240605;
        b=X0gs7nUpEbdI8TXThYct2IvcBaujMX2dIPk+Lk1tpA9CpCQ5B/H1k+ezznhgQQc6yj
         xHesbp2hrJEE+FMUkftNVI7cm+barTYBIi+Sc7zgV0wgtX/2lARWRXq60Td6ta1vNU1c
         rsLvX+Y+lhkeWb2HoekRpXbyVYEiQXXO5qTuLYDz4s5/KAUASGpNmulg4YteofT3Omgo
         0iuaIS5f87W+wAZPpmx6etFrT22GZFza2HDQB5D5zA119it9nQdV6fDFTuMd8w3zqt5p
         WwAXrYEgf6knaEgt3fFvsL/GTfQPtvveazPtUxc01JgQ+o0QgJ69uGKZntgxJu2Z4anW
         CpuA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=FvR5yc/dJbO6iPMrdm07cF5gmWRFhS+YQHGHSMNpCNU=;
        fh=XCbZ7r5OQGnYAmdOxSU5SCQ1NO0ArtoaqMrylAFBHHA=;
        b=guTTLqxbMjqfRPs1q0t9OrTLynp7xZ+YMDYam6kJrjuHM+2Rqr4QloMGIY1ViFKE2v
         cbz7ldyMIbiGD49j8SXzUNOguZ3H1+1j1GqrVBwcVVP6k6K1fhtcqUdwqat3VMN/aVQ1
         fZJW1Afe0siFuEloCgwuA8mU0vruCCizvxFLXJobdBEySy/YriuBu+h38ypwM9oSYvxS
         Y1m8zYIwa1ThTMp0mpvTXmDsdjWdEnNZqkytCAl8zoswg3LxrxBfZu6kwgk1lTQpTltw
         eT7T3IVD0LvSvC8pyfW6bNassPntyGRhqW6adFZCcQz/GGKWEE4B0xTqjErjfyBzYvL/
         lSYw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b="BvfMXu/y";
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::42d as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1729562359; x=1730167159; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=FvR5yc/dJbO6iPMrdm07cF5gmWRFhS+YQHGHSMNpCNU=;
        b=tRK84sxXQB65EC6jQfidn43yjydmOkBLOERnJGEAnbzuNekidOqBjLZ/wajoNT0fSH
         ZG/CzaqkdwGAzuzwxQmnUVPAl0jJHm8/Hji/r7oiwoobpEu1uDdewNhVBNHHy28u8AM5
         aJnvbbty84YNFsaz5jm+q11joK40kIFskC1YPhBgDv/J655rER57j+AGTj4hNkTFlqDh
         TkUU4REbl7x17BjscM/fRcghR6DxRpH7RWgugiExXYLmId+yg+i1+YpVWgnbgysfmoce
         OfR8Ov1AaYJNVJ0LzOg/IXvjXg7NjpX9YUwvGrs5OX4ASyfgyKZmWKPwU6li3PyXcxUZ
         kpQw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1729562359; x=1730167159;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=FvR5yc/dJbO6iPMrdm07cF5gmWRFhS+YQHGHSMNpCNU=;
        b=ewMoWEhNPdTMXoh9vguNYtKup6nZ7dBfoOcd3P6r2f6KBp3ifb5Rw0JBPx599CCUMw
         8UQdOv6npM/V9sP0SEuo7n/tesuICbiqtnb5pCIuSlzEhcotrKMgshAPF2hEA5FRz6I4
         Y9K4Pi6eGdjDev10i8/g4nNm0FSFO6MG6N8JCR5+GV3CjwAgM2FjrYdUbErJUezgncCv
         F6l3kyz5OJh5HYejEr7ZB0Phgv7kbDoNGqoyrS6b7G6rREgeR7U2otEAZ6RYeJ3XBN57
         oZq5sTlgMdXs/3Iex0z1oD9BGP61Y9P2VXG2mi6GsaBWDhrp1Jfp2uyKRdg4sZF44IV6
         /n0A==
X-Forwarded-Encrypted: i=2; AJvYcCVf5oRkn+jyt2k7HRxRNkoVg5RHIYN370MGgWXczzshtD2SLX6/LnwiuvkstfyK/hEgZz9i1w==@lfdr.de
X-Gm-Message-State: AOJu0Ywey+vMFt6PeDfpVqzG/lwOCTTuRvaQEva9UcHcnNE1GD8i8O36
	EQhlq02hLF7H6cWRNDGzwiCJDk6Uhto3hVkrH5zJ7Urp8hW90Xps
X-Google-Smtp-Source: AGHT+IEBeTZTZaHDCtWR2ChJTBKUSIs4aEsapyL/8ZNovRMGFhyxI9hSdyT5URxSTZUtsxE1/img7w==
X-Received: by 2002:a05:622a:5b8b:b0:460:ae0f:4708 with SMTP id d75a77b69052e-460aece75efmr180024241cf.1.1729562359500;
        Mon, 21 Oct 2024 18:59:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1ba5:b0:460:ef94:c47d with SMTP id
 d75a77b69052e-460ef94c5f9ls19052291cf.2.-pod-prod-05-us; Mon, 21 Oct 2024
 18:59:19 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVRbaDv3HzqJg2p0BGq/oI3+yabiSq+4s8XLf8JTYxbUVP0t0uB8J6VNX/B5DVMPkc7mKsFNavr4Ms=@googlegroups.com
X-Received: by 2002:a05:622a:114a:b0:460:a877:4c7e with SMTP id d75a77b69052e-460aed4c42cmr204969511cf.23.1729562358800;
        Mon, 21 Oct 2024 18:59:18 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1729562358; cv=none;
        d=google.com; s=arc-20240605;
        b=jJd7cYaqcBMcpj7B3TbpSPjdKU4QOU+m5kw4WQv0QI0uEYN/rO1EwVpqLAm8+v82z3
         PVdlBddi2DWlVajf+zBgpukZKQwzHCSINA0UXIWXpQgoRCFukwe6hs6VV6KWNamKFdb8
         RGEdyjr72AF638bHlECXMBPPBLSOTJt3odJ2Fi4ZjDGpe7Jmc+JWi8jtihpsJXo+Ae3N
         gGIrrGu+lKh7N+8HX/y0TGs6oXAzm63YI/XJfUozgKdHs2iJWwVjQEKPgbPb4/4NaSvH
         MQbApaHv/mXgcDuyXc+bAHI8tMGFCHPTSkBYBJuVrIHX/rjJhinTBBHU43e0O/pQmFIf
         c/+w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=zwUiyMUd8hSbAOwVDn06T0GWpMaINHNufJwGBjiF7oM=;
        fh=0x59o/htkvWBWt+BPcdb+oCZGxuyfFbiSlsiks52Uco=;
        b=CAjjrTiGJ9QQFN4l5m4nCjkYuXRdj5JpK2pXCHRtB//LMtQiiTuNn+R3AlBj4IpSL8
         5OLml6oevRkz1RpazfLrzlOx0Z2tIZnMxqKkNuMEmyE2ERaK6DZW2GW/bGy8ZjnNIl93
         oIUyl5+Gh9LjMzmlQu7ItKYbca9wDKCVWLdmTH1lnOLJWIUcyNLLVVkpoYyb7gVgVKS1
         y9qZz2Oau46aR6zBks5LQglzuemnvg4Bglerg78vPhFHUOOcms6DJkiuzSsbfc70bZ8S
         KgOD3lq1hmV6plFshHoQ5R9MuwTeVJw1trUYfKXTg/DXXrj8rxl6yRrYlVq/FSqJXs9c
         IPTA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@sifive.com header.s=google header.b="BvfMXu/y";
       spf=pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::42d as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sifive.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x42d.google.com (mail-pf1-x42d.google.com. [2607:f8b0:4864:20::42d])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-460f0472ee1si1306761cf.0.2024.10.21.18.59.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 21 Oct 2024 18:59:18 -0700 (PDT)
Received-SPF: pass (google.com: domain of samuel.holland@sifive.com designates 2607:f8b0:4864:20::42d as permitted sender) client-ip=2607:f8b0:4864:20::42d;
Received: by mail-pf1-x42d.google.com with SMTP id d2e1a72fcca58-71eb1d0e3c2so1950598b3a.2
        for <kasan-dev@googlegroups.com>; Mon, 21 Oct 2024 18:59:18 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVFipkLOpTWrmErQM2Q+8hE/cTptU7TIdJuWBoYTpmRpUnMbopiLh3ozHtBeiFEk2/VHRYg/9Cwmvg=@googlegroups.com
X-Received: by 2002:a05:6a00:3d08:b0:71e:1314:899a with SMTP id d2e1a72fcca58-71ea31e4c76mr18906065b3a.20.1729562358073;
        Mon, 21 Oct 2024 18:59:18 -0700 (PDT)
Received: from sw06.internal.sifive.com ([4.53.31.132])
        by smtp.gmail.com with ESMTPSA id d2e1a72fcca58-71ec132ffdcsm3600710b3a.46.2024.10.21.18.59.16
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 21 Oct 2024 18:59:17 -0700 (PDT)
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
	Catalin Marinas <catalin.marinas@arm.com>,
	linux-kernel@vger.kernel.org,
	linux-mm@kvack.org,
	Alexandre Ghiti <alexghiti@rivosinc.com>,
	Will Deacon <will@kernel.org>,
	Evgenii Stepanov <eugenis@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-arm-kernel@lists.infradead.org,
	Samuel Holland <samuel.holland@sifive.com>
Subject: [PATCH v2 1/9] kasan: sw_tags: Use arithmetic shift for shadow computation
Date: Mon, 21 Oct 2024 18:57:09 -0700
Message-ID: <20241022015913.3524425-2-samuel.holland@sifive.com>
X-Mailer: git-send-email 2.45.1
In-Reply-To: <20241022015913.3524425-1-samuel.holland@sifive.com>
References: <20241022015913.3524425-1-samuel.holland@sifive.com>
MIME-Version: 1.0
X-Original-Sender: samuel.holland@sifive.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@sifive.com header.s=google header.b="BvfMXu/y";       spf=pass
 (google.com: domain of samuel.holland@sifive.com designates
 2607:f8b0:4864:20::42d as permitted sender) smtp.mailfrom=samuel.holland@sifive.com;
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

Changes in v2:
 - Improve the explanation for how KASAN_SHADOW_END is derived
 - Update the range check in kasan_non_canonical_hook()

 arch/arm64/Kconfig              | 10 +++++-----
 arch/arm64/include/asm/memory.h | 17 +++++++++++++++--
 arch/arm64/mm/kasan_init.c      |  7 +++++--
 include/linux/kasan.h           | 10 ++++++++--
 mm/kasan/report.c               | 22 ++++++++++++++++++----
 scripts/gdb/linux/mm.py         |  5 +++--
 6 files changed, 54 insertions(+), 17 deletions(-)

diff --git a/arch/arm64/Kconfig b/arch/arm64/Kconfig
index fd9df6dcc593..6a326908c941 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -418,11 +418,11 @@ config KASAN_SHADOW_OFFSET
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
index 0480c61dbb4f..a93fc9dc16f3 100644
--- a/arch/arm64/include/asm/memory.h
+++ b/arch/arm64/include/asm/memory.h
@@ -80,7 +80,8 @@
  * where KASAN_SHADOW_SCALE_SHIFT is the order of the number of bits that map
  * to a single shadow byte and KASAN_SHADOW_OFFSET is a constant that offsets
  * the mapping. Note that KASAN_SHADOW_OFFSET does not point to the start of
- * the shadow memory region.
+ * the shadow memory region, since not all possible addresses have shadow
+ * memory allocated for them.
  *
  * Based on this mapping, we define two constants:
  *
@@ -89,7 +90,15 @@
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
@@ -100,7 +109,11 @@
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
index 00a3bf7c0d8f..03b440658817 100644
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
 
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index b48c768acc84..c08097715686 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -644,15 +644,29 @@ void kasan_report_async(void)
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
+	 * For Generic KASAN, the displacement is unsigned, so
+	 * KASAN_SHADOW_OFFSET is the smallest possible shadow address. For
+	 * Software Tag-Based KASAN, the displacement is signed, so
+	 * KASAN_SHADOW_OFFSET is the center of the range.
 	 */
-	if (addr < KASAN_SHADOW_OFFSET)
-		return;
+	if (IS_ENABLED(CONFIG_KASAN_GENERIC)) {
+		if (addr < KASAN_SHADOW_OFFSET ||
+		    addr >= KASAN_SHADOW_OFFSET + max_shadow_size)
+			return;
+	} else {
+		if (addr < KASAN_SHADOW_OFFSET - max_shadow_size / 2 ||
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
2.45.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20241022015913.3524425-2-samuel.holland%40sifive.com.

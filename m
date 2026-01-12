Return-Path: <kasan-dev+bncBAABBAW6STFQMGQETQZEPLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 54637D1458D
	for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 18:27:31 +0100 (CET)
Received: by mail-ed1-x53a.google.com with SMTP id 4fb4d7f45d1cf-64ba13b492asf8299307a12.1
        for <lists+kasan-dev@lfdr.de>; Mon, 12 Jan 2026 09:27:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1768238851; cv=pass;
        d=google.com; s=arc-20240605;
        b=ezRjtboGifug98Ex708FEoWFc8f/9PIZG13p54DXfsvnaj+fgq8mvTDKyEohHQNEhS
         vxlQk7+oohdnOdBz1KOqn7Xpj0Z/GnQCxSQMNvAOkqqaJWeTPHYWw1gL1jnmOhhhhr2w
         FEKtsS7FElW38m8clQTkhXgWCTu1qvNLe6f3UioPHx/PVUzBcCN1D9m2OMbvPUim7EJI
         FQhT3XeYnmmwj9Fme7FcjnAtWP+6tKliiCRDDvfR6mI1aTftJD44UYHv6LeHsxIV4Fgb
         Ft48now6dnyWLQcYR+LzFNpFlk5hdOtadIdoydexe2u29Uj47FPyjBUiudHRn0+RtOeo
         WvtA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :references:in-reply-to:message-id:subject:cc:from:to:date
         :dkim-signature;
        bh=moD4yfel/AUe8lk4rBsVOFTO0uCQLwrh2FBNtPQaAf8=;
        fh=kX3uluQ+BSK1T1EuimSB+Si4+NeUTh3H8U3M+eD3KH4=;
        b=D9AzQ+ziyrzfjC+I7rib6QxqgdlwxxlSRQk+PcuULoJgmE3JeZUNXIY8x4TPbWZT6d
         EovhFv+GgTFf58LrMYsBxNlYr2o3pjnJeOgoiLZ5r7dkWIJ+YmtuP34ecvTXnLPJU+Kc
         DButXWLr3CRYuyhnxwo7JSLJAtlReijSHS30BCxTxwGhKmTiRDPi4rDeCtw1mpRGNKee
         Gvn0MpuHAX5sOi8xS3l1pDgeKcb4YQNOA9zy/cYo5ydMxEApA3AT8EWgiRRB65Co4mPh
         fXIBG59NPrm3DpsPC4fBonBLLrnF/FxixTuKumrVnY46xR+hoEgAq03a8SMFSt1btSrG
         NO1g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=LjxjrDuC;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.22 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1768238851; x=1768843651; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=moD4yfel/AUe8lk4rBsVOFTO0uCQLwrh2FBNtPQaAf8=;
        b=C7Gs7GOD58043sNe5+4gYo0l1WASXd/fSDvETniEt7+qq58bcXatgN2y047J5Kk85L
         TLMTZQD7upY48KVBKwf3cvMf/IcyaAQZ7ijxA8ktJN166l/0g1Mqf3O/aWEGYbjGwpQy
         SVkYsT5yuuScd/tBdnX7tE6GwQbK0QhdZLU+blXIYV19haGwfnKuWjolwp3ZedD4IczP
         gAZa0LdKV0R3/+izbyWgiZD/oeRTs+EOXoJkrIP/MSICnnKL3SHZuTMpALGpIz66Rav2
         RSraMUJv1tGOyBP6kLkz+JNs7THkq+n8mvS0amLCU5QqBh9rSZcpA1kiNkrItfARRsHq
         eVTw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1768238851; x=1768843651;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=moD4yfel/AUe8lk4rBsVOFTO0uCQLwrh2FBNtPQaAf8=;
        b=ACyGVR/uFgq6ieMc0raJyiDUsgBQnJvsaGnlIbriJRcPfOeWbKGEYCq//j4HEKT8W6
         yx6t2xJn4tsQKfLs1oj1cyI4M77vs2Kvw8TcFJmNUMLkz6hTdUT/VFuyJi35p1VwvzCT
         yVpcGkncORrQ08W+4engWqQbQaB9Uw2g2XOH62JEdwBTSjJ2b9dmoC9WjJ5SqvK48vSs
         LciYSbTAzDOlEsQdsWcCN+c0BDqkVpWyIT/n+nexlanxgijuilvvriqoFJv02KYNgmwe
         7+0ccZ1AqPiMoM68W3c5lr4x0ud/IzVT3Oz23CQphPsBDzl9xbv8kITE6fSzsf5VmRrj
         wB1A==
X-Forwarded-Encrypted: i=2; AJvYcCVXGg40+gNmnjDw/2LLiOjJ74cJ1Qjoo0/fPlvLDZ8se8jvzo55FISfYtOIY/4fiu8J9hOUsA==@lfdr.de
X-Gm-Message-State: AOJu0YwGIwMGUJPCXi/nRl4jd5JmjI+sEP6dVOfUF9S3mY042ImZHVIx
	7JTxBwPHg1qsckTOa0MHqhdmC10r7ZfKKTQz9AKQcgyB0jSaVgeaceaB
X-Google-Smtp-Source: AGHT+IFcwEmj6MtC4VJ7IZpI0rY3v7Aa565jmPN5TJzXHv0jVbXVdahsbB/CNybxOSzIZ9yF7zHw2Q==
X-Received: by 2002:a05:6402:1441:b0:64d:f39:3fdb with SMTP id 4fb4d7f45d1cf-65097decaf2mr19056237a12.13.1768238850667;
        Mon, 12 Jan 2026 09:27:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+H2zwBL0VMm7M6OvJsaL54+J/hxQQHQHMasnEGPqCFvpw=="
Received: by 2002:aa7:c487:0:b0:64d:faf4:f73e with SMTP id 4fb4d7f45d1cf-650743340b5ls5909304a12.0.-pod-prod-05-eu;
 Mon, 12 Jan 2026 09:27:29 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXmd34+o0QN2uKYmWzkpFDWWUaWkgtF33/S5DkJb9aCsSUGOeIcHp46a7k1zyiMyNzflMfsD7qe7uw=@googlegroups.com
X-Received: by 2002:a17:907:7f93:b0:b7d:22b1:2145 with SMTP id a640c23a62f3a-b84451e7a91mr1518090666b.23.1768238848815;
        Mon, 12 Jan 2026 09:27:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1768238848; cv=none;
        d=google.com; s=arc-20240605;
        b=YkcGmpVKGn78zz7N/FApy1bG1VXQobktV7PpnryL8JJCdEtaTpfbYXU2hipaJQSf0h
         GPBL7CYTFL2Wpm0eWpcmi3jx1PPtUEVYRlptsVSzkZLwAimCL1yJXU9mNTkpiBomtQiv
         90TVNrUv6Adl05sKvQx6AX2BGiwL640/nPH+MQMr2qaibyeNKyRZJba84lyhIYr3Moqb
         bL7HgSRahvnfjYa001S6GjaY7StqmbUEe/0YEpjLxvt9dKOqrejYwob+NjT1ELTHUGke
         rQ62378aU0BAKfQj3+hZluSAPE9skfKsTB0mOldvcC0WHrJSLDsKzROtOLt3Xwz4VA1L
         BGgA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=JiMOOEA6qNaiQDDGgdthf6TZH3O0GT1Wjo585EHcW4E=;
        fh=cnqandUeFaFr13ovu1fylENTYAQWu7WkMuJGMPV4oJc=;
        b=gxfqYyZ+3PHuS1ignVHTty86LFaxbs7SUKnPNiVvZx4364ntf2ffnVqBOBgWIY9ynt
         cHsLSsuthkCMM/CJHeWJKG3nPYZaH5dgZrP7jk+V2o7IWrunca1o3Ui3pOnd1UOyDoBM
         CSg066WXYG2Bi57cGonGiRu+DyQrllB+KdCes3LzePpqaADy5VlyeT633Fsd+7rfOEV7
         8Ysj8AvRy3o2ytphVr6Kz7juzvuUBGVxbESY2QYXGBsx+LvJLhKQVFlr5Djnjjj68GdI
         hXlCN2TEXqMpjeugAq7rdsxqWsdeORIOR6433SWcMuL0usScqYRjdUbpQP6v7SCVXweg
         z3tA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=LjxjrDuC;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.22 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-4322.protonmail.ch (mail-4322.protonmail.ch. [185.70.43.22])
        by gmr-mx.google.com with ESMTPS id a640c23a62f3a-b8440cf7e61si41725966b.2.2026.01.12.09.27.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 12 Jan 2026 09:27:28 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.22 as permitted sender) client-ip=185.70.43.22;
Date: Mon, 12 Jan 2026 17:27:22 +0000
To: Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, Jonathan Corbet <corbet@lwn.net>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrew Morton <akpm@linux-foundation.org>, Jan Kiszka <jan.kiszka@siemens.com>, Kieran Bingham <kbingham@kernel.org>, Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Bill Wendling <morbo@google.com>, Justin Stitt <justinstitt@google.com>
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: m.wieczorretman@pm.me, Samuel Holland <samuel.holland@sifive.com>, Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>, linux-arm-kernel@lists.infradead.org, linux-doc@vger.kernel.org, linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, linux-mm@kvack.org, llvm@lists.linux.dev
Subject: [PATCH v8 01/14] kasan: sw_tags: Use arithmetic shift for shadow computation
Message-ID: <4f31939d55d886f21c91272398fe43a32ea36b3f.1768233085.git.m.wieczorretman@pm.me>
In-Reply-To: <cover.1768233085.git.m.wieczorretman@pm.me>
References: <cover.1768233085.git.m.wieczorretman@pm.me>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 70a6fe20ee18bc60426e6e68f454786f4fa58ddd
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=LjxjrDuC;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.22 as
 permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
X-Original-From: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
Reply-To: Maciej Wieczor-Retman <m.wieczorretman@pm.me>
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

However, for KASAN_SW_TAGS there is some freedom to change the algorithm
without breaking the ABI. Because TBI is enabled for kernel addresses,
the top bits of shadow memory addresses computed during tag checks are
irrelevant, and so likewise are the top bits of KASAN_SHADOW_OFFSET.
This is demonstrated by the fact that LLVM uses a logical right shift in
the tag check fast path[2] but a sbfx (signed bitfield extract)
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
Co-developed-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Acked-by: Catalin Marinas <catalin.marinas@arm.com>
---
Changelog v7: (Maciej)
- Change UL to ULL in report.c to fix some compilation warnings.

Changelog v6: (Maciej)
- Add Catalin's acked-by.
- Move x86 gdb snippet here from the last patch.

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
 scripts/gdb/linux/kasan.py                |  5 +++-
 scripts/gdb/linux/mm.py                   |  5 ++--
 8 files changed, 76 insertions(+), 19 deletions(-)

diff --git a/Documentation/arch/arm64/kasan-offsets.sh b/Documentation/arch/arm64/kasan-offsets.sh
index 2dc5f9e18039..ce777c7c7804 100644
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
index 93173f0a09c7..c1b7261cdb96 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -434,11 +434,11 @@ config KASAN_SHADOW_OFFSET
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
index 9d54b2ea49d6..f127fbf691ac 100644
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
index abeb81bf6ebd..937f6eb8115b 100644
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
index 9c6ac4b62eb9..0f65e88cc3f6 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -62,8 +62,14 @@ int kasan_populate_early_shadow(const void *shadow_start,
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
index 62c01b4527eb..b5beb1b10bd2 100644
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
+		if (addr < (unsigned long)kasan_mem_to_shadow((void *)(0ULL)) ||
+		    addr > (unsigned long)kasan_mem_to_shadow((void *)(~0ULL)))
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
+		if (addr < (unsigned long)kasan_mem_to_shadow((void *)(0xFFULL << 56)) ||
+		    addr > (unsigned long)kasan_mem_to_shadow((void *)(~0ULL)))
+			return;
+	}
 
 	orig_addr = (unsigned long)kasan_shadow_to_mem((void *)addr);
 
diff --git a/scripts/gdb/linux/kasan.py b/scripts/gdb/linux/kasan.py
index 56730b3fde0b..4b86202b155f 100644
--- a/scripts/gdb/linux/kasan.py
+++ b/scripts/gdb/linux/kasan.py
@@ -7,7 +7,8 @@
 #
 
 import gdb
-from linux import constants, mm
+from linux import constants, utils, mm
+from ctypes import c_int64 as s64
 
 def help():
     t = """Usage: lx-kasan_mem_to_shadow [Hex memory addr]
@@ -39,6 +40,8 @@ class KasanMemToShadow(gdb.Command):
         else:
             help()
     def kasan_mem_to_shadow(self, addr):
+        if constants.CONFIG_KASAN_SW_TAGS and not utils.is_target_arch('x86'):
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
2.52.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/4f31939d55d886f21c91272398fe43a32ea36b3f.1768233085.git.m.wieczorretman%40pm.me.

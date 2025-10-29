Return-Path: <kasan-dev+bncBAABBNWLRHEAMGQEGCBBQMA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id D7F7CC1CE57
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 20:06:31 +0100 (CET)
Received: by mail-wr1-x43f.google.com with SMTP id ffacd0b85a97d-42814749a6fsf105833f8f.2
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Oct 2025 12:06:31 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761764791; cv=pass;
        d=google.com; s=arc-20240605;
        b=MllNmqlZPmAAGG7zRqWsKtXzOvCKbBEO+K9pK9vkdRIJ4a9gh/JeeBOgrqDl07Tm2h
         QkpefjC8mAqv7n21ShGG5/Lm1uHGuSUuwMGKvvb4TY9R4pGEmBjD4e9mfEBwNU/mFgFf
         eMLjt0joJ3hSCQUaNG68NYcAFrAZvQsOY5npkrqewlqSvtEkYNlFOIb/XwlvlblC+8Kt
         FXQwGeahCBWHxSVzu1sGRZ4rgDCeYf48CgWovH3GvuyaZqepqJdU6wSUMrgiAUEt4NBz
         1s9AYXB+uTt5KhvRO/qX/iU1yKc5QLYs0vjTTBmTxZsLBIUxVxxMt93pYFX3chow9sFn
         8vBw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :references:in-reply-to:message-id:subject:cc:from:to:date
         :dkim-signature;
        bh=GOdjGETEZMbGCSrpV33KY0d2RrmU6ic+ZhAjYZ+t+pU=;
        fh=IUnPuW42xsXydof2jH/hnn9h51thqCRIlTiBWR63Np0=;
        b=Ep9Qg1E4P4yf+wqMmrUenwgLmfRM2NblnyAoRkwoEOaQffAmDHT/SwldPamiSeR1h2
         ZSYmoVJpOBNcl492a/SKfofbEQLCjbUSE9OowY6KozI2NUw7THwYMeQmrZPeoElYzpkZ
         SfodQjlLm5aDqo3oN1aVvFAiwsxJg8GKA7NXNTH+iYUguYkz1RN+swydVlJVn2F6dN/W
         gJt8dgfNynm0zv84vrKYAELgAJtu4toH9Ho9ETk5XLG+TQGISa3LvEwfxt1YTX5C3R+M
         KuyQ+5DR+9VXInKx4RrrYNuKya7GVtiTnP6Bx5rQU/Rl0idCq6qypwNQnt/fQF+vgU6/
         SH2A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=H4tX2CgX;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.28 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761764791; x=1762369591; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=GOdjGETEZMbGCSrpV33KY0d2RrmU6ic+ZhAjYZ+t+pU=;
        b=N7wL6aMDwjbDyv4XOVac7/+ShwrsgQyVFxPwPDDLVGykjUkV8QqBTnovGtbQ1/37Zq
         M/A3uNC93R1rH4m6oW33U7cSpHx2/RH/KtwKbX1llSsyszGoeFYb9aj2Ci37dqXitb01
         XfqupEr7mtbQrYCibkw/F1tQN/CoOV6oCAgCgFZbyrjlwBroDfAJWru/4SEpIfiA++tL
         xpwXysI7yUmJxOfN7ss0rfVKtz56QcW9HU4y53G+jhJsPt9kIcE5rdykwO+AizY5cFZr
         Fbd7iDZqQnnUHbLEOM2tHFhvclEDFu+JyMfws/wGtEVp2ysmG8YgO5TFuP1D1eF3pSUS
         y/nA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761764791; x=1762369591;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=GOdjGETEZMbGCSrpV33KY0d2RrmU6ic+ZhAjYZ+t+pU=;
        b=KGn/Prl4IA4JfubkenBY7BcuLQ9W9WrgQnSxamPzRfq4LbazxtXkfMulz1KTiTfLRM
         kMUL2GxWLPs/zlRYSv38vD4DFX4+4f8kPyaVQZKD4KTkooeY0sVdru6eBMD1GnoLEtoe
         kb7y++6WMd93O1GAWVo/bsVafpo8XtlUZmNB28imSC8/MkjRu4t5ikReqbnmgVcBFT7L
         II64NDVwcqSa0Sst08OzjKul2PJSpucncpf/oFK5fw6AY2dd5qsmpC2n1TkW0uavGgJU
         KfwrC1MyLkIlIMyebrDKK/XGWLSGrZJgtDfP9R05+F7qLl+HIoUcX9jXgvykTVMQQSF2
         Igew==
X-Forwarded-Encrypted: i=2; AJvYcCX3MRdO/OVBZPMJdj/Z36karRUbVu0pnzYXO5CaVi59VhMOZxDa1ODo/epPakW/IoOsSQzU8g==@lfdr.de
X-Gm-Message-State: AOJu0YyP6isoSfnnuEpYEmAoWhym7Pspi/j7b1Myvpi9CMPjXaYeuOIk
	M6phk+qa6AIoSWYPDOvFmbeVquxOXpu0TBjd1tTfI6OINAXywVTycRm/
X-Google-Smtp-Source: AGHT+IHCJK39mjx2YrQoeta/qgVvo0D7iYr5HFI6msktlXDApNom1VKjYXtaDAXD3DQhH1b02656Kw==
X-Received: by 2002:a05:6000:240c:b0:3f1:2671:6d9e with SMTP id ffacd0b85a97d-429b4c73bc7mr565151f8f.1.1761764790915;
        Wed, 29 Oct 2025 12:06:30 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+Zfji6YPUjPFzmZJlliWRmrs2NBol/h1J0KE/a579iNgA=="
Received: by 2002:a05:600c:a110:b0:475:ddad:7664 with SMTP id
 5b1f17b1804b1-477279e2490ls128735e9.2.-pod-prod-08-eu; Wed, 29 Oct 2025
 12:06:29 -0700 (PDT)
X-Received: by 2002:a05:600c:3ba5:b0:45d:d97c:236c with SMTP id 5b1f17b1804b1-4772686ed27mr4456295e9.21.1761764788537;
        Wed, 29 Oct 2025 12:06:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761764788; cv=none;
        d=google.com; s=arc-20240605;
        b=SVpkQQRmzeuICrycKkbPAY0PfbfHwGOiuRO1LMtuzKhGL20ZLMFBESRlHL7WJogGPF
         5UNC8IxsUNLLMpI2LA9oYiYyLTJI0F5GuB3iqgRhrmWzzvP/PjW/gn8qPIMSSL0hXdua
         on24ada1oYFWkBO3fuXX5B3wH9FvrGW9UNk+YPAY9aAvNor/qUMGuTQMc3TR68Hc1hMf
         ChaBfkuwfHCDYftvih9LuNeij84YAkZKPP7HQBfNUtV8DF94IVfgEk9Ka544tlS5l3Yo
         OnrX0tOByXdUleFJ/Q/LjUm3GVnUdng8VsanCEsCVs5lUl036DCNVnnQjVEXOx0dg4cY
         Bb3A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=jxLQWxZR1uUIJx1zLFGYnHCjTfyYOaAydFAYRdFzgVE=;
        fh=F9cNJe7/uLron8lsbb2s7B83ncoMqIuz1w+0GaoUZzI=;
        b=fX+p3KcVGemHLkApz+8FrUjeepze/nKgArTtMNSZSmj7rl0uNmgLVZ/GotFSUO/2fi
         GRvq3MowZwUF7VrxlEZgZRPFRIznJoq6BgrX5cQUgo7dAV8TWo3rPOqYj03tcPvjy4h1
         qZsBD7M8udIr7UQ4GgIgR/uI20327pC/RjrKNhw3ITVeFmLjhYzHtcd/7RzPiYLIRGNZ
         0vvE0kG/mFP7dXNVunk6Dln6eWZitlU5V9oeujyr7xqWMPD8y5kaRXfaJfvrKSCn2agS
         V3+b3Sph7/Wfjt9yLXRo+U4ukxiCJA6+CIx+tmE2Ru3rNwZ61rbNqd+waUa+vgDhheji
         nEvQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=H4tX2CgX;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.28 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-10628.protonmail.ch (mail-10628.protonmail.ch. [79.135.106.28])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-42995ff8f70si409724f8f.5.2025.10.29.12.06.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Oct 2025 12:06:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.28 as permitted sender) client-ip=79.135.106.28;
Date: Wed, 29 Oct 2025 19:06:17 +0000
To: xin@zytor.com, peterz@infradead.org, kaleshsingh@google.com, kbingham@kernel.org, akpm@linux-foundation.org, nathan@kernel.org, ryabinin.a.a@gmail.com, dave.hansen@linux.intel.com, bp@alien8.de, morbo@google.com, jeremy.linton@arm.com, smostafa@google.com, kees@kernel.org, baohua@kernel.org, vbabka@suse.cz, justinstitt@google.com, wangkefeng.wang@huawei.com, leitao@debian.org, jan.kiszka@siemens.com, fujita.tomonori@gmail.com, hpa@zytor.com, urezki@gmail.com, ubizjak@gmail.com, ada.coupriediaz@arm.com, nick.desaulniers+lkml@gmail.com, ojeda@kernel.org, brgerst@gmail.com, elver@google.com, pankaj.gupta@amd.com, glider@google.com, mark.rutland@arm.com, trintaeoitogc@gmail.com, jpoimboe@kernel.org, thuth@redhat.com, pasha.tatashin@soleen.com, dvyukov@google.com, jhubbard@nvidia.com, catalin.marinas@arm.com, yeoreum.yun@arm.com, mhocko@suse.com, lorenzo.stoakes@oracle.com, samuel.holland@sifive.com, vincenzo.frascino@arm.com, bigeasy@linutronix.de, surenb@google.com,
	ardb@kernel.org, Liam.Howlett@oracle.com, nicolas.schier@linux.dev, ziy@nvidia.com, kas@kernel.org, tglx@linutronix.de, mingo@redhat.com, broonie@kernel.org, corbet@lwn.net, andreyknvl@gmail.com, maciej.wieczor-retman@intel.com, david@redhat.com, maz@kernel.org, rppt@kernel.org, will@kernel.org, luto@kernel.org
From: "'Maciej Wieczor-Retman' via kasan-dev" <kasan-dev@googlegroups.com>
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, x86@kernel.org, linux-kbuild@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, linux-doc@vger.kernel.org, m.wieczorretman@pm.me
Subject: [PATCH v6 03/18] kasan: sw_tags: Use arithmetic shift for shadow computation
Message-ID: <ab71a0af700c8b83b51a7174fb6fd297e9b5f1ee.1761763681.git.m.wieczorretman@pm.me>
In-Reply-To: <cover.1761763681.git.m.wieczorretman@pm.me>
References: <cover.1761763681.git.m.wieczorretman@pm.me>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: d92e0c1a55128f8d1bfda37556d8adda3911f1d0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=H4tX2CgX;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 79.135.106.28 as
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
Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
Acked-by: Catalin Marinas <catalin.marinas@arm.com>
---
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
index 6663ffd23f25..ac50ba2d760b 100644
--- a/arch/arm64/Kconfig
+++ b/arch/arm64/Kconfig
@@ -433,11 +433,11 @@ config KASAN_SHADOW_OFFSET
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
index f1505c4acb38..7bbebde59a75 100644
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
index b00849ea8ffd..952ade776e51 100644
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
2.51.0


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/ab71a0af700c8b83b51a7174fb6fd297e9b5f1ee.1761763681.git.m.wieczorretman%40pm.me.

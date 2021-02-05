Return-Path: <kasan-dev+bncBDX4HWEMTEBRBP6N6WAAMGQENG5ZIRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id 581E7310D43
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Feb 2021 16:39:44 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id o8sf5703404ljp.15
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Feb 2021 07:39:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612539584; cv=pass;
        d=google.com; s=arc-20160816;
        b=W2zxSRht6ek2pCCnB0X7WIVRkBUJbdAzDmlVLVxEstasSNd1aJGuP2kzk8BLCKfwky
         DEuJ2XvRpEbpehKy3XFNGnhHYRjPy7Du2/g8Pznf2wlwCA2WC9vJAcpI9/XlvJR3ad6Q
         2xrePCbJE0SeNgwi71PMDw5I6URzgw2AyIF0dO7VCewGmqVF1nfyqJHuqUXE16QAHRQE
         Yvg+P7UE+Ikub0Dj/y1H4enP3bXMSV2+PCTkYG4D7VLiHbLqS8B1vV9Bw8tIzdLfeBks
         dorI3DeyYTJWI7xbQBDKgpJl5Jm7OFQfjXvWiaxgeuTtvBmw1Jhaq+rdCcH0ls0WVnUH
         aHew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=YJw2+KOxoCDXYtyYc57PNnMXsHecmkhssM1XavzIxWk=;
        b=D1BfMe00nlOvqbaD6NSThYfHMFC5k+61C9enEYqo9KYKIPvhTCCdNy7aIIM+eXpjfZ
         H6SV2VxGFq2bnNCZr6y0IYoJ7Ko7VDN/te/ajJUdfX6t/gnMaw578PhflafvPZkUld7j
         z8zih1yzRjJUZkTYaWOkKmh4lYPNA7A4G+JZwb22YDLdNhvDj9YT31sl6r8INN2FohtU
         BJ35oJFRHryBMb2aD62GmKKEqtbScgToQbbvH2d1AqzVOM7+93jkRh8m7q/p4WBU6UPv
         xpQTXm22iIub6Tmul5Zs7oXGWn9bs+gxtrMA+HQdzf9CPkILSpFUgAC1A0BOxOOk1i1K
         iftA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=konF6v6B;
       spf=pass (google.com: domain of 3vmydyaokcqkjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3vmYdYAoKCQkjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=YJw2+KOxoCDXYtyYc57PNnMXsHecmkhssM1XavzIxWk=;
        b=idAv9EbvUgXo8+haWkk0BgFUr2+DJkj2qD6xBp7kZt2fAFySvXTSdWum/hp1s8Kqgq
         4sY6/IruNFlJSUWvxWlcfXjQQbuPwm0B4phUd4gGY25gj4dzjFPGYVq0jpVsQG64PN34
         WNEJOEfvvmnX4LyB9UV+2uICoe0NQtx+HNhc9Nad6BDvexNFtcZZdNg0Sdi36GUVKv7J
         sDAYJwj+TCBhQrBoeWh4VaLr1NewvgH/FnOtow1cM+Vn8nKJk0ZG0Qtxoi2YIA/YTfN1
         I/HELYRdnnht0RuoR6VWcCyGufsH46XEJA0lvOzpe3ZQXjVhzrfQtv83B3nFUXsf8o9z
         Vong==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YJw2+KOxoCDXYtyYc57PNnMXsHecmkhssM1XavzIxWk=;
        b=cETGhAsfkSMbzq8rpc1PU207hCVFaUZdrFEOoNus+EhSxTTUTpieZPEX60g65Qh57i
         RMkDz2fXfVdFoMHBVSQRmbXf6q6+2Qcc8VY50MnN3NtZL/KQH0uTM3Q/OiiztG/Q0wVo
         FNJmCGh1rpdxAc1TTc4+3RqJurkyPKA88dzLyOR6Uw81N7XWQI2YTp0So85OZBhdhk/L
         bme7G0lpiIPga19yLN0e2shjdAtfmjIw4d7y1MoY3LG547cyJPKn7/J2njpxGi2RRFrf
         zBfSEH936C+T+TDME96tgzP+9/4n+Nc42TmiHognrEZXp3stjctJ1ghjL4bfgFbFCGT0
         uIFQ==
X-Gm-Message-State: AOAM533L4V9Uhe2ey5hSvUbJcGu5s7+V1mndu/SJrclAWbgF1TNjgRl+
	FtelALa9df0pAMst7vrNC9g=
X-Google-Smtp-Source: ABdhPJwFdPJqY2eDrANeyk+0IIWXZIYgoYVhNMg8IaqmDXtPLVlHVwOYxqwNULA7ZbQMnWKrLvlghQ==
X-Received: by 2002:ac2:4154:: with SMTP id c20mr2934327lfi.145.1612539583880;
        Fri, 05 Feb 2021 07:39:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5519:: with SMTP id j25ls2642367lfk.2.gmail; Fri, 05 Feb
 2021 07:39:43 -0800 (PST)
X-Received: by 2002:a05:6512:3253:: with SMTP id c19mr2688517lfr.245.1612539582926;
        Fri, 05 Feb 2021 07:39:42 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612539582; cv=none;
        d=google.com; s=arc-20160816;
        b=oU5Yb/GVyWx9Ru04InjgNeAM7/7f7hWu54pTfGGclGNnOVIHmm5Sm94XCqUMAVM1Bk
         Qd0fjUlf5u16IJtqGvNiXyLw1nsjbEc0Ra3twDXZsgWtwnSWwbns6JKhb7eHk5pt3mET
         OkQ3AYImgmFa1PsvT4Xgm4myqSHX1mpGKGZpjW+cwXtnpphEpMZy3/aXeMFBbn3vrpM/
         MfWkW48QJfGf0HoLOGKu0BE2IU7nDMl29359rOwFCvL9/YGg+wPtuVnBdIOvo+1f3FGN
         U9jdLqVZ0FQ0yOmepH88hyPf+6V3b3nEvcIwUvhw7mekYeRI+nLCNSfqo9mKIjWJ3DWQ
         fdjA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=PREZUncIqPTZICTNMYAhqfkQODhaZIF+0hFoo18paHE=;
        b=olgFk1+a0ff09S6LHmCYkpOLlvwhaYPdij1AKSj+9t+ierKKR8Egtn/bvZpTlotY7p
         8501t0D7Y3IIb/LF6vFRmBXuenljAtGruAZEAzajRFrMgYEsEgSZAqaALh7QqlwlKoV6
         dEOiW9mxhulogPEnBxLGLKlHDKNRkR2Pqxq3zIgzW9FDSgsV1jkdo3CqWP/sOeQuh5pO
         BeKRAIf3aYh1D3eUToGAkVflnfx/Re01jGCEAI9FXwoQVHzZxSk7FtLfK6ae0AgraWn7
         /UAhJ4Ru8z2XBvEtqg5YvJD1ft4Ekpapjxzv1S8QvRMq+oizyt2PXwauitDT+WEr+vh7
         fdSg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=konF6v6B;
       spf=pass (google.com: domain of 3vmydyaokcqkjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3vmYdYAoKCQkjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id s5si521824ljg.7.2021.02.05.07.39.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Feb 2021 07:39:42 -0800 (PST)
Received-SPF: pass (google.com: domain of 3vmydyaokcqkjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id yd11so6886473ejb.9
        for <kasan-dev@googlegroups.com>; Fri, 05 Feb 2021 07:39:42 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:edb8:b79c:2e20:e531])
 (user=andreyknvl job=sendgmr) by 2002:a17:906:8611:: with SMTP id
 o17mr4584420ejx.145.1612539582294; Fri, 05 Feb 2021 07:39:42 -0800 (PST)
Date: Fri,  5 Feb 2021 16:39:11 +0100
In-Reply-To: <cover.1612538932.git.andreyknvl@google.com>
Message-Id: <a3c23942ba4352fbacf537ec7b5607b7f5c3eaaa.1612538932.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1612538932.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.365.g02bc693789-goog
Subject: [PATCH v2 10/12] arm64: kasan: simplify and inline MTE functions
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Catalin Marinas <catalin.marinas@arm.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Will Deacon <will.deacon@arm.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=konF6v6B;       spf=pass
 (google.com: domain of 3vmydyaokcqkjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3vmYdYAoKCQkjwm0n7tw4upxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

This change provides a simpler implementation of mte_get_mem_tag(),
mte_get_random_tag(), and mte_set_mem_tag_range().

Simplifications include removing system_supports_mte() checks as these
functions are onlye called from KASAN runtime that had already checked
system_supports_mte(). Besides that, size and address alignment checks
are removed from mte_set_mem_tag_range(), as KASAN now does those.

This change also moves these functions into the asm/mte-kasan.h header
and implements mte_set_mem_tag_range() via inline assembly to avoid
unnecessary functions calls.

Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
Co-developed-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 arch/arm64/include/asm/cache.h     |  1 -
 arch/arm64/include/asm/kasan.h     |  1 +
 arch/arm64/include/asm/mte-def.h   |  2 +
 arch/arm64/include/asm/mte-kasan.h | 65 ++++++++++++++++++++++++++----
 arch/arm64/include/asm/mte.h       |  2 -
 arch/arm64/kernel/mte.c            | 46 ---------------------
 arch/arm64/lib/mte.S               | 16 --------
 7 files changed, 60 insertions(+), 73 deletions(-)

diff --git a/arch/arm64/include/asm/cache.h b/arch/arm64/include/asm/cache.h
index 77cbbe3625f2..a074459f8f2f 100644
--- a/arch/arm64/include/asm/cache.h
+++ b/arch/arm64/include/asm/cache.h
@@ -6,7 +6,6 @@
 #define __ASM_CACHE_H
 
 #include <asm/cputype.h>
-#include <asm/mte-kasan.h>
 
 #define CTR_L1IP_SHIFT		14
 #define CTR_L1IP_MASK		3
diff --git a/arch/arm64/include/asm/kasan.h b/arch/arm64/include/asm/kasan.h
index 0aaf9044cd6a..12d5f47f7dbe 100644
--- a/arch/arm64/include/asm/kasan.h
+++ b/arch/arm64/include/asm/kasan.h
@@ -6,6 +6,7 @@
 
 #include <linux/linkage.h>
 #include <asm/memory.h>
+#include <asm/mte-kasan.h>
 #include <asm/pgtable-types.h>
 
 #define arch_kasan_set_tag(addr, tag)	__tag_set(addr, tag)
diff --git a/arch/arm64/include/asm/mte-def.h b/arch/arm64/include/asm/mte-def.h
index 2d73a1612f09..cf241b0f0a42 100644
--- a/arch/arm64/include/asm/mte-def.h
+++ b/arch/arm64/include/asm/mte-def.h
@@ -11,4 +11,6 @@
 #define MTE_TAG_SIZE		4
 #define MTE_TAG_MASK		GENMASK((MTE_TAG_SHIFT + (MTE_TAG_SIZE - 1)), MTE_TAG_SHIFT)
 
+#define __MTE_PREAMBLE		ARM64_ASM_PREAMBLE ".arch_extension memtag\n"
+
 #endif /* __ASM_MTE_DEF_H  */
diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/asm/mte-kasan.h
index 8ad981069afb..13be3afc37ac 100644
--- a/arch/arm64/include/asm/mte-kasan.h
+++ b/arch/arm64/include/asm/mte-kasan.h
@@ -11,11 +11,14 @@
 
 #include <linux/types.h>
 
+#ifdef CONFIG_ARM64_MTE
+
 /*
- * The functions below are meant to be used only for the
- * KASAN_HW_TAGS interface defined in asm/memory.h.
+ * These functions are meant to be only used from KASAN runtime through
+ * the arch_*() interface defined in asm/memory.h.
+ * These functions don't include system_supports_mte() checks,
+ * as KASAN only calls them when MTE is supported and enabled.
  */
-#ifdef CONFIG_ARM64_MTE
 
 static inline u8 mte_get_ptr_tag(void *ptr)
 {
@@ -25,9 +28,54 @@ static inline u8 mte_get_ptr_tag(void *ptr)
 	return tag;
 }
 
-u8 mte_get_mem_tag(void *addr);
-u8 mte_get_random_tag(void);
-void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag);
+/* Get allocation tag for the address. */
+static inline u8 mte_get_mem_tag(void *addr)
+{
+	asm(__MTE_PREAMBLE "ldg %0, [%0]"
+		: "+r" (addr));
+
+	return mte_get_ptr_tag(addr);
+}
+
+/* Generate a random tag. */
+static inline u8 mte_get_random_tag(void)
+{
+	void *addr;
+
+	asm(__MTE_PREAMBLE "irg %0, %0"
+		: "+r" (addr));
+
+	return mte_get_ptr_tag(addr);
+}
+
+/*
+ * Assign allocation tags for a region of memory based on the pointer tag.
+ * Note: The address must be non-NULL and MTE_GRANULE_SIZE aligned and
+ * size must be non-zero and MTE_GRANULE_SIZE aligned.
+ */
+static inline void mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
+{
+	u64 curr, end;
+
+	if (!size)
+		return;
+
+	curr = (u64)__tag_set(addr, tag);
+	end = curr + size;
+
+	do {
+		/*
+		 * 'asm volatile' is required to prevent the compiler to move
+		 * the statement outside of the loop.
+		 */
+		asm volatile(__MTE_PREAMBLE "stg %0, [%0]"
+			     :
+			     : "r" (curr)
+			     : "memory");
+
+		curr += MTE_GRANULE_SIZE;
+	} while (curr != end);
+}
 
 void mte_enable_kernel_sync(void);
 void mte_enable_kernel_async(void);
@@ -47,13 +95,14 @@ static inline u8 mte_get_mem_tag(void *addr)
 {
 	return 0xFF;
 }
+
 static inline u8 mte_get_random_tag(void)
 {
 	return 0xFF;
 }
-static inline void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
+
+static inline void mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
 {
-	return addr;
 }
 
 static inline void mte_enable_kernel_sync(void)
diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
index 237bb2f7309d..43169b978cd3 100644
--- a/arch/arm64/include/asm/mte.h
+++ b/arch/arm64/include/asm/mte.h
@@ -8,8 +8,6 @@
 #include <asm/compiler.h>
 #include <asm/mte-def.h>
 
-#define __MTE_PREAMBLE		ARM64_ASM_PREAMBLE ".arch_extension memtag\n"
-
 #ifndef __ASSEMBLY__
 
 #include <linux/bitfield.h>
diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
index 7763ac1f2917..8b27b70e1aac 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -19,7 +19,6 @@
 #include <asm/barrier.h>
 #include <asm/cpufeature.h>
 #include <asm/mte.h>
-#include <asm/mte-kasan.h>
 #include <asm/ptrace.h>
 #include <asm/sysreg.h>
 
@@ -88,51 +87,6 @@ int memcmp_pages(struct page *page1, struct page *page2)
 	return ret;
 }
 
-u8 mte_get_mem_tag(void *addr)
-{
-	if (!system_supports_mte())
-		return 0xFF;
-
-	asm(__MTE_PREAMBLE "ldg %0, [%0]"
-	    : "+r" (addr));
-
-	return mte_get_ptr_tag(addr);
-}
-
-u8 mte_get_random_tag(void)
-{
-	void *addr;
-
-	if (!system_supports_mte())
-		return 0xFF;
-
-	asm(__MTE_PREAMBLE "irg %0, %0"
-	    : "+r" (addr));
-
-	return mte_get_ptr_tag(addr);
-}
-
-void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
-{
-	void *ptr = addr;
-
-	if ((!system_supports_mte()) || (size == 0))
-		return addr;
-
-	/* Make sure that size is MTE granule aligned. */
-	WARN_ON(size & (MTE_GRANULE_SIZE - 1));
-
-	/* Make sure that the address is MTE granule aligned. */
-	WARN_ON((u64)addr & (MTE_GRANULE_SIZE - 1));
-
-	tag = 0xF0 | tag;
-	ptr = (void *)__tag_set(ptr, tag);
-
-	mte_assign_mem_tag_range(ptr, size);
-
-	return ptr;
-}
-
 void mte_init_tags(u64 max_tag)
 {
 	static bool gcr_kernel_excl_initialized;
diff --git a/arch/arm64/lib/mte.S b/arch/arm64/lib/mte.S
index 9e1a12e10053..351537c12f36 100644
--- a/arch/arm64/lib/mte.S
+++ b/arch/arm64/lib/mte.S
@@ -149,19 +149,3 @@ SYM_FUNC_START(mte_restore_page_tags)
 
 	ret
 SYM_FUNC_END(mte_restore_page_tags)
-
-/*
- * Assign allocation tags for a region of memory based on the pointer tag
- *   x0 - source pointer
- *   x1 - size
- *
- * Note: The address must be non-NULL and MTE_GRANULE_SIZE aligned and
- * size must be non-zero and MTE_GRANULE_SIZE aligned.
- */
-SYM_FUNC_START(mte_assign_mem_tag_range)
-1:	stg	x0, [x0]
-	add	x0, x0, #MTE_GRANULE_SIZE
-	subs	x1, x1, #MTE_GRANULE_SIZE
-	b.gt	1b
-	ret
-SYM_FUNC_END(mte_assign_mem_tag_range)
-- 
2.30.0.365.g02bc693789-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a3c23942ba4352fbacf537ec7b5607b7f5c3eaaa.1612538932.git.andreyknvl%40google.com.

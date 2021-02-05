Return-Path: <kasan-dev+bncBDX4HWEMTEBRBU4D62AAMGQEVCSESOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id E83E7310EC7
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Feb 2021 18:35:16 +0100 (CET)
Received: by mail-yb1-xb3a.google.com with SMTP id v7sf7794970ybl.15
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Feb 2021 09:35:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612546516; cv=pass;
        d=google.com; s=arc-20160816;
        b=pZIsmbGfpsifxPYQxsbqpsotBHdxBijsku8b+PG9HIHCnKqUvsOrQ6aiUS0hn2oHaQ
         GwYf8bG9EmBnK+3UYc4gkg1AJ8PwQHRXpIfq97pqyPt+/z0mJjM66wkcCf98AtFKga0T
         Rm8473hNK6tWIa4cmApTICvLfkLaSWoCEDipBvWMQZgYvkPK3p78Ygpjh7C+WehWk+qY
         1v9a0pNElklvcjGvdNoVFJEBsgZ6/cm4Ax2NbVESHguDK/28/4H+BoHIF+MgGOqpkoN0
         mUG7EvjozSx7KjO5+pSsy6UZ44llT5usOmfBUkgfyuvVesLvWr2So3O9UX2KznvDCDcr
         JCOQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=xPceGdZfAslnj0MAPCT53N4vg0uIYMmZ+5pln0MPXhA=;
        b=SB1FkdlVNj3Pew/ZRjk0YiMj7j05tVMyez/H8rO8s5jK3EYrwPogf0y+9FTICX97/Y
         Zcu+/jM86otip71hCcQxRmFWrJseL+33V9iOicQcBw3KA71OVgksKRYwqgojFtvSjTjk
         +sxCNlOYQhsKZHBVBCkoDIekJr1v70325WgffIG6nJztIL4Qv7Qw5L0VqY84/3NQ3piY
         83kwaYYrb+nH7Btzi8fWvZCG4uHAKYFuLN3pWHwvG5rmSYBALS+i1Et3Wp+HBvjYAzQR
         9cK8HyTQcWMUtV6YzNt+luU1Kwk50JhvJaGIbEpPLkJ+lEXEd0zH0HGLNy5MMw+UBSRy
         UliA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UtIaRW9v;
       spf=pass (google.com: domain of 304edyaokcvqw9zd0k69h72aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=304EdYAoKCVQw9zD0K69H72AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=xPceGdZfAslnj0MAPCT53N4vg0uIYMmZ+5pln0MPXhA=;
        b=rlExvPA3J9qqhZ2pM4BV65Y32FHmNsPX1wvmsdoN4tMj7Q4T2M2ebdDj3ruWRMmytx
         r7G9kidTwlN/N+VamczdISlSh5s1uUf1wcYo4xa2kR8KdSEl6d51d2VtkMPNzcrGUmNm
         W6xoxOBsi7rHAcp0zdZLuenMGBUk28WeQcbdmNc/EwOCkZMEXOb7Bo0vVLZ9Ubt8zdAI
         26FpKa/awM/LrHMIXrdz58svn80WV73ZvTChZ16wC1ts8PXrs4DI0neg/PWU4euWcqu7
         DV9x+VLpJfY3B55RLyO8167ngqV/1lmlMMLXLXCDUjGe/R0pPuiSYUAMN6CZnm0BaLit
         OKZg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xPceGdZfAslnj0MAPCT53N4vg0uIYMmZ+5pln0MPXhA=;
        b=NCmlCuDJvfekqr123pX/5zcMqqQ2XTgR7C++uBOuUuadglJ8DbUvQVmrunJPxwrvVE
         Jh7xFWk1XyxN6hyshsl3HyTIbKDoJbf0FGs/WuA/TWh5FregUfH20h+4iyHUIEcX86cS
         wConPgLnQovSlWiDbofT8gL5UlCLUEgGFVT8rN9mi7YOXhTRFqbXSWAGXqypHZnBOX2A
         3fMp3NCV4XXpZoA9zTjnRN/PBBmPWYjH4dBihPsv8oB4kGEBroNL+ED5sbVAuATCmPht
         7536WG4yn7U6iGhsXDS3u6Zau5i8G0GzUZ8RG22DVhQ9lTlJ9bMj2CEEAg1z5bLRalo3
         A31Q==
X-Gm-Message-State: AOAM532g+TJ8QGhoFQoZg6wMWmHhtIty4txni7Fw/jS3BjMqRIux7oY+
	dMJEyklhA8Qsl4aIAaYg/+4=
X-Google-Smtp-Source: ABdhPJxTSiEv4avq7GQz9P+RaBlhXEdizb5bwM6IcLiecW90ZHam0uNGlV9ZPBQ2Ys+41sXOPK9+Fg==
X-Received: by 2002:a25:7183:: with SMTP id m125mr7881503ybc.151.1612546515837;
        Fri, 05 Feb 2021 09:35:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:3006:: with SMTP id w6ls4644316ybw.4.gmail; Fri, 05 Feb
 2021 09:35:15 -0800 (PST)
X-Received: by 2002:a25:c607:: with SMTP id k7mr7772147ybf.285.1612546515451;
        Fri, 05 Feb 2021 09:35:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612546515; cv=none;
        d=google.com; s=arc-20160816;
        b=O82cT0g2s5jKwwodK7YyU+jbm8SNAhTG0t52+YGhevV0xxdLzPk2uphKGtm/0SlUUG
         v8B6XLKLsUCEZltVSiDVEIqzBkT6PH3uegFL8mkcxLpyaDFBhDFSUlG6/D1fKyuZPeds
         bH9fvEWfCw8n9ere2yy4maAsdzrsy6x3voAPbJBQqL/WOSNB0f81e1qH1Ehbhuve1p4/
         FWoRGtpJQq3zYWtnmd4oRZmovXlGT2F4UbAs8Z8y5swpngUZuSc84gnBv7blvCCV9aWE
         QFXLOBwOyv30Q1ZcsqvMkWruBUWb0b4fzn1EAPuLIBDiUylQi0XbKCXPRZur0tS7ds8l
         zY6w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=ctAIK4J2ixb9MMoTkFb1CmODQtYX8ZOk4P8i8+csvVc=;
        b=AN0u4tsx/77V0UQrl2Jj41ALF5I+a6yip5zj33cQWXhvsdLRDyQIgvuCY2GgZlSeMJ
         Fg2IUvWc/0z/CsahiBXEITHurvSEpZjIvVrfUuqR3eg7nF2ZjDqPRjIoR0XHjGCzaSJn
         BJKwasCCD6jqAwb0l3nh49Jd5JrBWlyXFwOjBcyIM4IDijxdvi1WdOoDPYiHH0MsjDXg
         4jEUr6Uu4amvFrwsZFWg/dWYxKIy5/t8Vll1/FUPKJ9K20vAehLpCGuvAfBkwRQZ5CaA
         QKeiWJGV9DL5UyKw9h0Ao5+PGZzdmBbjDcKngZAWJz7OYnpq9AC7DpGK5irc/wsSTusp
         tjjg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UtIaRW9v;
       spf=pass (google.com: domain of 304edyaokcvqw9zd0k69h72aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=304EdYAoKCVQw9zD0K69H72AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id c10si629983ybf.1.2021.02.05.09.35.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Feb 2021 09:35:15 -0800 (PST)
Received-SPF: pass (google.com: domain of 304edyaokcvqw9zd0k69h72aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id i19so1250817qtq.21
        for <kasan-dev@googlegroups.com>; Fri, 05 Feb 2021 09:35:15 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:edb8:b79c:2e20:e531])
 (user=andreyknvl job=sendgmr) by 2002:a0c:a819:: with SMTP id
 w25mr5283889qva.6.1612546515078; Fri, 05 Feb 2021 09:35:15 -0800 (PST)
Date: Fri,  5 Feb 2021 18:34:44 +0100
In-Reply-To: <cover.1612546384.git.andreyknvl@google.com>
Message-Id: <a26121b294fdf76e369cb7a74351d1c03a908930.1612546384.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1612546384.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.365.g02bc693789-goog
Subject: [PATCH v3 mm 10/13] arm64: kasan: simplify and inline MTE functions
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
 header.i=@google.com header.s=20161025 header.b=UtIaRW9v;       spf=pass
 (google.com: domain of 304edyaokcvqw9zd0k69h72aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=304EdYAoKCVQw9zD0K69H72AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--andreyknvl.bounces.google.com;
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
index 3748d5bb88c0..3d58489228c0 100644
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
 
 void mte_enable_kernel(void);
 void mte_init_tags(u64 max_tag);
@@ -46,13 +94,14 @@ static inline u8 mte_get_mem_tag(void *addr)
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
 
 static inline void mte_enable_kernel(void)
diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
index d02aff9f493d..9b557a457f24 100644
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
index c63b3d7a3cd9..203108d51d40 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a26121b294fdf76e369cb7a74351d1c03a908930.1612546384.git.andreyknvl%40google.com.

Return-Path: <kasan-dev+bncBDX4HWEMTEBRBBFU4GAAMGQEA3TEJAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd39.google.com (mail-io1-xd39.google.com [IPv6:2607:f8b0:4864:20::d39])
	by mail.lfdr.de (Postfix) with ESMTPS id 8780A30B0A3
	for <lists+kasan-dev@lfdr.de>; Mon,  1 Feb 2021 20:44:05 +0100 (CET)
Received: by mail-io1-xd39.google.com with SMTP id t127sf6272837iof.1
        for <lists+kasan-dev@lfdr.de>; Mon, 01 Feb 2021 11:44:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612208644; cv=pass;
        d=google.com; s=arc-20160816;
        b=TlcwhcHOpFWcZA3Cpc3b7ND5nCLZt3Ckuhc5GLFrc6QOcWHwVQyopAul4P1i+nXUtc
         d3qZRE7wTTkuhxb4i9nMbPIj2WW3ecm872MLlKSLk4/xAhU+3NAOEqeKugD38h3U46Kk
         5DubAtOWMjMOfKK7+jysyt3LDk3YU8z7W8GAe2aLWnoMAZ3NOVQHzERQ1ny5k8fWpAyU
         iUEv3bR0xVaH4TkJpJuCmrV2Fdd6taRuFOCQZJmf+mRu5MfK7dPiiMwsJHnJNYNdIvzf
         a8UvTZZoYaNgpiAYR8q9NsDKd2n5m4991x/Laa7/4oxJXGZE7Yl5lac8IZa2PQSxvn+q
         kmBg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=QjU99u9EUGvqHtWN9T+I4R2s1X9UVTAX0n4WM3bfKFY=;
        b=lgIAziWO9w5MMTGsiUi+6uUgkRd5hY18ou+Jlwd/L2a8qxrn7HsjcjM3zD/9UkZul3
         v13NpsPRQEp8bOMZPL5GUQZArAV2p/T90dSey9lavQt9oChJkEtUSWcRPwAUTe4zn3Yu
         A/nMeuab/nd+MuR5S3LBnto1yUOYg2uHHVpnhkgVh0qEHdcvL1wZYUzGuD7g+5ITX0pn
         xETSc6ivd04KrBYGa2hih+qFiDW/zuSNcQlcaHaM8KepykreI1atP22PUvEkfGvPm8rT
         ObTs+rF1RkDvjHVlnTQ34sxCfsaJAFXWRwm//MdGopt+czECgD/stsmMu8CoJDfVCpDY
         jDuA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lF7topMI;
       spf=pass (google.com: domain of 3a1oyyaokcsa6j9naugjrhckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3A1oYYAoKCSA6J9NAUGJRHCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=QjU99u9EUGvqHtWN9T+I4R2s1X9UVTAX0n4WM3bfKFY=;
        b=rlyqXPQfc6Ujrnp3a+yxaz9DS4444XcOLmNXO5AZn5fLi/Q/xEswmnFkC3rVvRXI0N
         fNH/RTYmLsWFO0DVhvbj08rLkbXMovpSyJkQ5TDX7P4pzLHYqbmNgNdu5UbdGAtuWSUE
         G3ZahuTt1Z4Q5MHd7BJiwZycDGnkwPV+7Tdq0F+bXUtZHkoUAa4DEL0F3rrxgZmnSlrN
         rZ+8Ei8YAasR8ukIdJ2gWQcCNR3xt1aazYSaG7f6wy44yKxFVu+s1wZf1/xEB0i14djK
         HbpbXZ2P099xL0gZJvEYoVb4cswjXvivM3Tc0HTFIU18cexppGLusHCLFKN+RCrR77f5
         sPSw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=QjU99u9EUGvqHtWN9T+I4R2s1X9UVTAX0n4WM3bfKFY=;
        b=XyV3eGYNvRFRljVLS/ZlqilxsOrNuACPTIoZZWPkPKg5OOdMURPVXNK6T8GgBeFxxT
         YGp9jKSJ3B/LsBWLFjWcMqLAbpUeA9GxD+gicWDCH8tifaNx/Y0wRVMbmMT23Shgkahp
         VhPSYaaCy3iFsPClu+6XSyM4yTsJBEKk6jRI9FL93ms86gqKB8iCRrKQOL4NO++p3Upt
         2HV5ucDEM4rDWdnCmjpoqTkKW9nGrysQ8AmKqmAE83J7EpWH6+MVWl2PaElUFCK4OQsc
         qu8mUOGPgvB8bsDvkp0hlped7UxJcr8cKiYHePEVW+R20Bl9k1GS6po7J5s5Dis+wkV2
         FGlQ==
X-Gm-Message-State: AOAM530LmTKZ8FbRSZsdReKhv5RJTHtHPrMzsP44hO5IA/Bi/Hbh1pQB
	uztAaviLgYta8AL/QkKcIuQ=
X-Google-Smtp-Source: ABdhPJxT57gZNpPnHoenuBjk4foROs6HBOk5PoMehEjjZN/F0buPEpoxL8sbRsiuIL4cn/qMect5Cg==
X-Received: by 2002:a6b:b58f:: with SMTP id e137mr14212410iof.131.1612208644580;
        Mon, 01 Feb 2021 11:44:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:2195:: with SMTP id j21ls4128950ila.4.gmail; Mon,
 01 Feb 2021 11:44:04 -0800 (PST)
X-Received: by 2002:a05:6e02:2142:: with SMTP id d2mr12843924ilv.249.1612208644096;
        Mon, 01 Feb 2021 11:44:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612208644; cv=none;
        d=google.com; s=arc-20160816;
        b=GbGERAPwOD+wIHeDOX0CnYakYUXB7KxRFGM/ZdH+QtMa1DTXsjRRvF79iYHf/0ZHTI
         h9rSi0tpLHZKRuni2tl0S6qYwY3ePBy/wdFTg6LVDrWgz2eLx1ZAY5yphz5ahWct1VCM
         W7sM/ANr0KcVLU45rmUOlywn/AzuGm2I7T3LxS3a5bzKfey+H3zZyPBchBUVthS3Fy/I
         hFhUU09U5/2qsiJ3wjaoCqP4g+4YXqOkLvhx//WBli4NHaafnFBriUW59vDTVcl9dB5n
         KcUI1UnFzQFhAwQmxAn8/37VWqJUSt521Az7G8DD4DENx08wILODBWOzhN3nruyu5FSe
         o77w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=Odkzh1LG/DFkpV7FBjHfcEglIWvDLvMk2053ZF0TmS8=;
        b=qZM6p0qaim62ZSgR/CQyXOaDu6/p2CfTZzO4UvlTrtk+3mCTT6/ttWUG7HTBpjj3qi
         ruqj03AVk/eveOfnwN0jvMUc7oKyjM/taBJ6wQ15GbJGL54c5irr5czKgc0piEBZh4Af
         gPsLNihk1XwXilgqN5+upo75FE6/r33cd5cYpU7vos76KNXBHSQOhSa4gUIBX4ELUO3w
         z71B7BRPq+VOFAJBFlwJSg+HdH7OyQxHOzavxivBjWvLO3vPvk8ESbyWMt9xtoPynQHR
         pFEgfFOOGYbvztnxfbLS+L2yuS2rQjLwLXmf3TEgYGkhbz/qCuom6SCCX8o13PoRV7qT
         REew==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=lF7topMI;
       spf=pass (google.com: domain of 3a1oyyaokcsa6j9naugjrhckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3A1oYYAoKCSA6J9NAUGJRHCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id o7si745186ilt.4.2021.02.01.11.44.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 01 Feb 2021 11:44:04 -0800 (PST)
Received-SPF: pass (google.com: domain of 3a1oyyaokcsa6j9naugjrhckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id t186so6266697qke.5
        for <kasan-dev@googlegroups.com>; Mon, 01 Feb 2021 11:44:04 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:5110:: with SMTP id
 g16mr16935423qvp.5.1612208643527; Mon, 01 Feb 2021 11:44:03 -0800 (PST)
Date: Mon,  1 Feb 2021 20:43:34 +0100
In-Reply-To: <cover.1612208222.git.andreyknvl@google.com>
Message-Id: <17d6bef698d193f5fe0d8baee0e232a351e23a32.1612208222.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1612208222.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.365.g02bc693789-goog
Subject: [PATCH 10/12] arm64: kasan: simplify and inline MTE functions
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, Branislav Rankov <Branislav.Rankov@arm.com>, 
	Kevin Brodsky <kevin.brodsky@arm.com>, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=lF7topMI;       spf=pass
 (google.com: domain of 3a1oyyaokcsa6j9naugjrhckkcha.8kig6o6j-9arckkchacnkqlo.8ki@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3A1oYYAoKCSA6J9NAUGJRHCKKCHA.8KIG6O6J-9ARCKKCHACNKQLO.8KI@flex--andreyknvl.bounces.google.com;
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

Co-developed-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 arch/arm64/include/asm/cache.h     |  1 -
 arch/arm64/include/asm/kasan.h     |  1 +
 arch/arm64/include/asm/mte-def.h   |  2 +
 arch/arm64/include/asm/mte-kasan.h | 64 ++++++++++++++++++++++++++----
 arch/arm64/include/asm/mte.h       |  2 -
 arch/arm64/kernel/mte.c            | 46 ---------------------
 arch/arm64/lib/mte.S               | 16 --------
 7 files changed, 60 insertions(+), 72 deletions(-)

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
index 8ad981069afb..1f090beda7e6 100644
--- a/arch/arm64/include/asm/mte-kasan.h
+++ b/arch/arm64/include/asm/mte-kasan.h
@@ -11,13 +11,16 @@
 
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
 
-static inline u8 mte_get_ptr_tag(void *ptr)
+static __always_inline u8 mte_get_ptr_tag(void *ptr)
 {
 	/* Note: The format of KASAN tags is 0xF<x> */
 	u8 tag = 0xF0 | (u8)(((u64)(ptr)) >> MTE_TAG_SHIFT);
@@ -25,9 +28,54 @@ static inline u8 mte_get_ptr_tag(void *ptr)
 	return tag;
 }
 
-u8 mte_get_mem_tag(void *addr);
-u8 mte_get_random_tag(void);
-void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag);
+/* Get allocation tag for the address. */
+static __always_inline u8 mte_get_mem_tag(void *addr)
+{
+	asm(__MTE_PREAMBLE "ldg %0, [%0]"
+		: "+r" (addr));
+
+	return mte_get_ptr_tag(addr);
+}
+
+/* Generate a random tag. */
+static __always_inline u8 mte_get_random_tag(void)
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
+static __always_inline void mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
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
@@ -47,10 +95,12 @@ static inline u8 mte_get_mem_tag(void *addr)
 {
 	return 0xFF;
 }
+
 static inline u8 mte_get_random_tag(void)
 {
 	return 0xFF;
 }
+
 static inline void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag)
 {
 	return addr;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/17d6bef698d193f5fe0d8baee0e232a351e23a32.1612208222.git.andreyknvl%40google.com.

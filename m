Return-Path: <kasan-dev+bncBAABBB4LSKQQMGQEQOS26NA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x337.google.com (mail-wm1-x337.google.com [IPv6:2a00:1450:4864:20::337])
	by mail.lfdr.de (Postfix) with ESMTPS id 5090F6CF23C
	for <lists+kasan-dev@lfdr.de>; Wed, 29 Mar 2023 20:38:00 +0200 (CEST)
Received: by mail-wm1-x337.google.com with SMTP id bi7-20020a05600c3d8700b003edecc610absf9195398wmb.7
        for <lists+kasan-dev@lfdr.de>; Wed, 29 Mar 2023 11:38:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1680115080; cv=pass;
        d=google.com; s=arc-20160816;
        b=pLqSUfvfVJmBKKetW483lvahhPrH1jX/hr2NZAO/kGIVS2a+D3ehNF/Ssbsck4ucTk
         6HXCMwqjxbDMvAcNrdMWYgNpsLSczdl2jTDH9XNFV+xTBwJI9wRpbmTW9KAdH/ob/umC
         lHNFcoJcDJaeJlngjHSKyeGr8XUhV4uZjc8Qh5pdteUsAVvFO3nDItVNvWadzsOWiLzw
         CXzOFxbjZj7Csa19AAoy0QqmbdZgT50OvakLYJ66UdcYVVxJmbHy3oPsAnrUCJhuEPEk
         dabLFz8993LLPPW00og8RftjI1E99t2kxaI2eeS5IvErYa567a8WgV4vhRUQ46yVIJWs
         ZtEg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=sLz1X6D5gwfVFslr/HNjVtN9xEh9c8CdclOU2QGlSus=;
        b=p+LOxdCdFelBt+YNTzKehAsyzfr9JeoFwHKyMcSI0oWwdd/il54fhrm/GEeXUZxjKh
         UyfC5sHLsjDHoTtRroPKfG+KjE4d+3WF1d1zzOw1iGAIP1RzvbDT/3dgjRCfeLoF1/KX
         cfXTwd+FS8c86Rqi4PaIKliBmdYFzYCznEK5Tegtx0sU4K9hRturCSkAWrc64BDoP/e5
         /nIjAIg1uXhqu2SM2nm3fwH6aGwCY4SrUvcvpB8DvgTTasAvCbSVNO4TGUNiTiR92HIr
         llzK/H85+MJxG7sXxEpPFwJiz8FEkPIN/qfQS41RelYFBVdkYNQZaEWUN8rk4GQF3RK/
         TrQg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=oP2VA3+D;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::36 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112; t=1680115080;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=sLz1X6D5gwfVFslr/HNjVtN9xEh9c8CdclOU2QGlSus=;
        b=nb2QWgjfaYLlCKRPsJ5dxx1ExaOm52yWJ77L35wS34PBr84vaRyNITquyVQgT5Ir9b
         sXblaQu7/oSnHymIDAWYgVr53+izjm+my5FjVXa2c6x2jePcXEHlXcJKE9vknPsI2Lgn
         0c8s7HI//P/oaMo+XtqOpdvhL0lOFmOy++gqcF1Gp4qCRfUN9dsl6TX655pt15jRPJd+
         7cOZw3nE8rkjNdYlHWkULc/xs3LsCV/YigzYLjOJDUviMElk/JU29h2HtYgoVVV9E2au
         /DixCwHippFUnNQkk5DsSeoCOL9WVI/90Vt5o7te2/WdkpRg0vN2QgXhLbLva6d+haCa
         h21Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112; t=1680115080;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=sLz1X6D5gwfVFslr/HNjVtN9xEh9c8CdclOU2QGlSus=;
        b=AECRoPoIoFqKpIL3LXrcwsEZdcq7osYDf00UgFEXZpgrVUJST+S13EjsoiBo6p/tqA
         yUXVsBSlRVs44YZDgEszlbgFbLPYEPnOBhUVoO16Lj9S/6g7D8X9fzrz+FI6HfUyNerz
         bhMZ0Rd5uimLusF2eZmAZpHzaN9QH7vAJz2Ms1pCXtStf9d+fxiMVPgH00OnShruAizf
         AMLaMxnW6a1uGtW7j1t6l2yrWPO+GnDww8XyZOcHIEtVgTZerO44VvtkkzcLoL1M9oKU
         CJm/3hKhJ4JPZRqSw4k87V7vJi2Id0DydK60+ikaAGUKpwNLEVIi9wEvcC+YaoJ5c0qq
         2NMQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKXkKNPDBvTvVRmVyrfVMD+tt9wdfdmFvwfheJOJfBj5iZYsLpBk
	TQjV/mIvXqOFgV6NlwNzHQE=
X-Google-Smtp-Source: AK7set92jSRZ3VrcC9xaHyr5pw/bwXwbRgRxnlZHoK3K0nn/uD3ZH3mRCHyjFxP6HZJXxSpvsX93Yw==
X-Received: by 2002:a7b:ca4a:0:b0:3ee:282d:1031 with SMTP id m10-20020a7bca4a000000b003ee282d1031mr4637252wml.7.1680115080018;
        Wed, 29 Mar 2023 11:38:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:3b18:b0:3ef:7390:7787 with SMTP id
 m24-20020a05600c3b1800b003ef73907787ls1394846wms.3.-pod-canary-gmail; Wed, 29
 Mar 2023 11:37:59 -0700 (PDT)
X-Received: by 2002:a1c:4b07:0:b0:3eb:29fe:f911 with SMTP id y7-20020a1c4b07000000b003eb29fef911mr15859958wma.13.1680115079098;
        Wed, 29 Mar 2023 11:37:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1680115079; cv=none;
        d=google.com; s=arc-20160816;
        b=kdsJo8dOc4KQU2iRmxR6ZPWV5/z0FiGnG8mFiPkNXRP38nYXFErsmuSB3CAL1QuG8i
         SU+aWWoA5mi6oWnRdzrPPxEPivk6ZJ4ztIfcUzlj+36GEyFRndlf+RCGh0WpHwXnUDmk
         WidVIaaPM1/qBIXEHGA67tQ34Ev8D6Nz5p1ODGVJ3i6EQ1VWXIB33ucRwzTeN5Ppqdc2
         SDzdhdlS+k9nYlw+pwn4vXFfhERiEvHztkd5DA3ulbS+tzEtna20rZ+2pdaePAdqRtV+
         b4ECxTMFylGgdZ2EfAXX9/0M3i7D5fU70DNOlD8oN1sdCfZeUlMLCvURkiC3+LV2AJj7
         R8Bg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=R0ZTLDK0+ErC3gsprSGJ+tiVFRHa88yHqEYRk0ERiZ0=;
        b=dUZmBiJZh4y8Ib/wI9wGmMfj9TE9GYoji3/jHFZllE/paqxiy0U0HhG2HQYemRys8F
         1Svql5wWSaovdi/B5Z3C4ba8qKvhCabWzPng0QBcGeNIvuadlUI15Bf3/Lf0dleSWo2M
         /oLCtNpxp7QwaZhHEgOvYM153mH2AgQq4Jm1y3/JyPYMxZrb9aFfyWthToVHyIZ9Yo64
         QceHOASPy+ZYMZNam8AG9Wvwj9VKE4R6IsL1U7tF6bJTjBhDrzA1dkF5rXDPo247gu3t
         FvNeTHtm/rnfsOxnkIdTWpz4/AhGeEOlhBW948XNFkT9tBDNDhloUDp7nKMnWNuGMwGp
         vbbw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=oP2VA3+D;
       spf=pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::36 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-54.mta1.migadu.com (out-54.mta1.migadu.com. [2001:41d0:203:375::36])
        by gmr-mx.google.com with ESMTPS id b13-20020a05600003cd00b002c6ec127706si1558768wrg.0.2023.03.29.11.37.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 29 Mar 2023 11:37:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of andrey.konovalov@linux.dev designates 2001:41d0:203:375::36 as permitted sender) client-ip=2001:41d0:203:375::36;
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: andrey.konovalov@linux.dev
To: Marco Elver <elver@google.com>,
	Catalin Marinas <catalin.marinas@arm.com>
Cc: Andrey Konovalov <andreyknvl@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	kasan-dev@googlegroups.com,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	Will Deacon <will@kernel.org>,
	linux-arm-kernel@lists.infradead.org,
	Peter Collingbourne <pcc@google.com>,
	Evgenii Stepanov <eugenis@google.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	linux-mm@kvack.org,
	Weizhao Ouyang <ouyangweizhao@zeku.com>,
	linux-kernel@vger.kernel.org,
	Andrey Konovalov <andreyknvl@google.com>
Subject: [PATCH v2 3/5] arm64: mte: Rename TCO routines
Date: Wed, 29 Mar 2023 20:37:46 +0200
Message-Id: <74d26337b2360733956114069e96ff11c296a944.1680114854.git.andreyknvl@google.com>
In-Reply-To: <dc432429a6d87f197eefb179f26012c6c1ec6cd9.1680114854.git.andreyknvl@google.com>
References: <dc432429a6d87f197eefb179f26012c6c1ec6cd9.1680114854.git.andreyknvl@google.com>
MIME-Version: 1.0
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: andrey.konovalov@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=oP2VA3+D;       spf=pass
 (google.com: domain of andrey.konovalov@linux.dev designates
 2001:41d0:203:375::36 as permitted sender) smtp.mailfrom=andrey.konovalov@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
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

From: Vincenzo Frascino <vincenzo.frascino@arm.com>

The TCO related routines are used in uaccess methods and
load_unaligned_zeropad() but are unrelated to both even if the naming
suggest otherwise.

Improve the readability of the code moving the away from uaccess.h and
pre-pending them with "mte".

Cc: Will Deacon <will@kernel.org>
Signed-off-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Signed-off-by: Catalin Marinas <catalin.marinas@arm.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>

---

Chages v1->v2:
- Drop __ from mte_disable/enable_tco names, as those functions are to
  be exported to KASAN code.
---
 arch/arm64/include/asm/mte-kasan.h      | 81 +++++++++++++++++++++++++
 arch/arm64/include/asm/mte.h            | 12 ----
 arch/arm64/include/asm/uaccess.h        | 66 +++-----------------
 arch/arm64/include/asm/word-at-a-time.h |  4 +-
 4 files changed, 93 insertions(+), 70 deletions(-)

diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/asm/mte-kasan.h
index 9f79425fc65a..2e98028c1965 100644
--- a/arch/arm64/include/asm/mte-kasan.h
+++ b/arch/arm64/include/asm/mte-kasan.h
@@ -13,8 +13,73 @@
 
 #include <linux/types.h>
 
+#ifdef CONFIG_KASAN_HW_TAGS
+
+/* Whether the MTE asynchronous mode is enabled. */
+DECLARE_STATIC_KEY_FALSE(mte_async_or_asymm_mode);
+
+static inline bool system_uses_mte_async_or_asymm_mode(void)
+{
+	return static_branch_unlikely(&mte_async_or_asymm_mode);
+}
+
+#else /* CONFIG_KASAN_HW_TAGS */
+
+static inline bool system_uses_mte_async_or_asymm_mode(void)
+{
+	return false;
+}
+
+#endif /* CONFIG_KASAN_HW_TAGS */
+
 #ifdef CONFIG_ARM64_MTE
 
+/*
+ * The Tag Check Flag (TCF) mode for MTE is per EL, hence TCF0
+ * affects EL0 and TCF affects EL1 irrespective of which TTBR is
+ * used.
+ * The kernel accesses TTBR0 usually with LDTR/STTR instructions
+ * when UAO is available, so these would act as EL0 accesses using
+ * TCF0.
+ * However futex.h code uses exclusives which would be executed as
+ * EL1, this can potentially cause a tag check fault even if the
+ * user disables TCF0.
+ *
+ * To address the problem we set the PSTATE.TCO bit in uaccess_enable()
+ * and reset it in uaccess_disable().
+ *
+ * The Tag check override (TCO) bit disables temporarily the tag checking
+ * preventing the issue.
+ */
+static inline void mte_disable_tco(void)
+{
+	asm volatile(ALTERNATIVE("nop", SET_PSTATE_TCO(0),
+				 ARM64_MTE, CONFIG_KASAN_HW_TAGS));
+}
+
+static inline void mte_enable_tco(void)
+{
+	asm volatile(ALTERNATIVE("nop", SET_PSTATE_TCO(1),
+				 ARM64_MTE, CONFIG_KASAN_HW_TAGS));
+}
+
+/*
+ * These functions disable tag checking only if in MTE async mode
+ * since the sync mode generates exceptions synchronously and the
+ * nofault or load_unaligned_zeropad can handle them.
+ */
+static inline void __mte_disable_tco_async(void)
+{
+	if (system_uses_mte_async_or_asymm_mode())
+		mte_disable_tco();
+}
+
+static inline void __mte_enable_tco_async(void)
+{
+	if (system_uses_mte_async_or_asymm_mode())
+		mte_enable_tco();
+}
+
 /*
  * These functions are meant to be only used from KASAN runtime through
  * the arch_*() interface defined in asm/memory.h.
@@ -138,6 +203,22 @@ void mte_enable_kernel_asymm(void);
 
 #else /* CONFIG_ARM64_MTE */
 
+static inline void mte_disable_tco(void)
+{
+}
+
+static inline void mte_enable_tco(void)
+{
+}
+
+static inline void __mte_disable_tco_async(void)
+{
+}
+
+static inline void __mte_enable_tco_async(void)
+{
+}
+
 static inline u8 mte_get_ptr_tag(void *ptr)
 {
 	return 0xFF;
diff --git a/arch/arm64/include/asm/mte.h b/arch/arm64/include/asm/mte.h
index 20dd06d70af5..c028afb1cd0b 100644
--- a/arch/arm64/include/asm/mte.h
+++ b/arch/arm64/include/asm/mte.h
@@ -178,14 +178,6 @@ static inline void mte_disable_tco_entry(struct task_struct *task)
 }
 
 #ifdef CONFIG_KASAN_HW_TAGS
-/* Whether the MTE asynchronous mode is enabled. */
-DECLARE_STATIC_KEY_FALSE(mte_async_or_asymm_mode);
-
-static inline bool system_uses_mte_async_or_asymm_mode(void)
-{
-	return static_branch_unlikely(&mte_async_or_asymm_mode);
-}
-
 void mte_check_tfsr_el1(void);
 
 static inline void mte_check_tfsr_entry(void)
@@ -212,10 +204,6 @@ static inline void mte_check_tfsr_exit(void)
 	mte_check_tfsr_el1();
 }
 #else
-static inline bool system_uses_mte_async_or_asymm_mode(void)
-{
-	return false;
-}
 static inline void mte_check_tfsr_el1(void)
 {
 }
diff --git a/arch/arm64/include/asm/uaccess.h b/arch/arm64/include/asm/uaccess.h
index 5c7b2f9d5913..30ea7b5c3ccb 100644
--- a/arch/arm64/include/asm/uaccess.h
+++ b/arch/arm64/include/asm/uaccess.h
@@ -136,55 +136,9 @@ static inline void __uaccess_enable_hw_pan(void)
 			CONFIG_ARM64_PAN));
 }
 
-/*
- * The Tag Check Flag (TCF) mode for MTE is per EL, hence TCF0
- * affects EL0 and TCF affects EL1 irrespective of which TTBR is
- * used.
- * The kernel accesses TTBR0 usually with LDTR/STTR instructions
- * when UAO is available, so these would act as EL0 accesses using
- * TCF0.
- * However futex.h code uses exclusives which would be executed as
- * EL1, this can potentially cause a tag check fault even if the
- * user disables TCF0.
- *
- * To address the problem we set the PSTATE.TCO bit in uaccess_enable()
- * and reset it in uaccess_disable().
- *
- * The Tag check override (TCO) bit disables temporarily the tag checking
- * preventing the issue.
- */
-static inline void __uaccess_disable_tco(void)
-{
-	asm volatile(ALTERNATIVE("nop", SET_PSTATE_TCO(0),
-				 ARM64_MTE, CONFIG_KASAN_HW_TAGS));
-}
-
-static inline void __uaccess_enable_tco(void)
-{
-	asm volatile(ALTERNATIVE("nop", SET_PSTATE_TCO(1),
-				 ARM64_MTE, CONFIG_KASAN_HW_TAGS));
-}
-
-/*
- * These functions disable tag checking only if in MTE async mode
- * since the sync mode generates exceptions synchronously and the
- * nofault or load_unaligned_zeropad can handle them.
- */
-static inline void __uaccess_disable_tco_async(void)
-{
-	if (system_uses_mte_async_or_asymm_mode())
-		 __uaccess_disable_tco();
-}
-
-static inline void __uaccess_enable_tco_async(void)
-{
-	if (system_uses_mte_async_or_asymm_mode())
-		__uaccess_enable_tco();
-}
-
 static inline void uaccess_disable_privileged(void)
 {
-	__uaccess_disable_tco();
+	mte_disable_tco();
 
 	if (uaccess_ttbr0_disable())
 		return;
@@ -194,7 +148,7 @@ static inline void uaccess_disable_privileged(void)
 
 static inline void uaccess_enable_privileged(void)
 {
-	__uaccess_enable_tco();
+	mte_enable_tco();
 
 	if (uaccess_ttbr0_enable())
 		return;
@@ -302,8 +256,8 @@ do {									\
 #define get_user	__get_user
 
 /*
- * We must not call into the scheduler between __uaccess_enable_tco_async() and
- * __uaccess_disable_tco_async(). As `dst` and `src` may contain blocking
+ * We must not call into the scheduler between __mte_enable_tco_async() and
+ * __mte_disable_tco_async(). As `dst` and `src` may contain blocking
  * functions, we must evaluate these outside of the critical section.
  */
 #define __get_kernel_nofault(dst, src, type, err_label)			\
@@ -312,10 +266,10 @@ do {									\
 	__typeof__(src) __gkn_src = (src);				\
 	int __gkn_err = 0;						\
 									\
-	__uaccess_enable_tco_async();					\
+	__mte_enable_tco_async();					\
 	__raw_get_mem("ldr", *((type *)(__gkn_dst)),			\
 		      (__force type *)(__gkn_src), __gkn_err, K);	\
-	__uaccess_disable_tco_async();					\
+	__mte_disable_tco_async();					\
 									\
 	if (unlikely(__gkn_err))					\
 		goto err_label;						\
@@ -388,8 +342,8 @@ do {									\
 #define put_user	__put_user
 
 /*
- * We must not call into the scheduler between __uaccess_enable_tco_async() and
- * __uaccess_disable_tco_async(). As `dst` and `src` may contain blocking
+ * We must not call into the scheduler between __mte_enable_tco_async() and
+ * __mte_disable_tco_async(). As `dst` and `src` may contain blocking
  * functions, we must evaluate these outside of the critical section.
  */
 #define __put_kernel_nofault(dst, src, type, err_label)			\
@@ -398,10 +352,10 @@ do {									\
 	__typeof__(src) __pkn_src = (src);				\
 	int __pkn_err = 0;						\
 									\
-	__uaccess_enable_tco_async();					\
+	__mte_enable_tco_async();					\
 	__raw_put_mem("str", *((type *)(__pkn_src)),			\
 		      (__force type *)(__pkn_dst), __pkn_err, K);	\
-	__uaccess_disable_tco_async();					\
+	__mte_disable_tco_async();					\
 									\
 	if (unlikely(__pkn_err))					\
 		goto err_label;						\
diff --git a/arch/arm64/include/asm/word-at-a-time.h b/arch/arm64/include/asm/word-at-a-time.h
index 1c8e4f2490bf..f3b151ed0d7a 100644
--- a/arch/arm64/include/asm/word-at-a-time.h
+++ b/arch/arm64/include/asm/word-at-a-time.h
@@ -55,7 +55,7 @@ static inline unsigned long load_unaligned_zeropad(const void *addr)
 {
 	unsigned long ret;
 
-	__uaccess_enable_tco_async();
+	__mte_enable_tco_async();
 
 	/* Load word from unaligned pointer addr */
 	asm(
@@ -65,7 +65,7 @@ static inline unsigned long load_unaligned_zeropad(const void *addr)
 	: "=&r" (ret)
 	: "r" (addr), "Q" (*(unsigned long *)addr));
 
-	__uaccess_disable_tco_async();
+	__mte_disable_tco_async();
 
 	return ret;
 }
-- 
2.25.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/74d26337b2360733956114069e96ff11c296a944.1680114854.git.andreyknvl%40google.com.

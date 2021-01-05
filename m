Return-Path: <kasan-dev+bncBDX4HWEMTEBRBQG72L7QKGQEFAVRDLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83f.google.com (mail-qt1-x83f.google.com [IPv6:2607:f8b0:4864:20::83f])
	by mail.lfdr.de (Postfix) with ESMTPS id 8F4FD2EB288
	for <lists+kasan-dev@lfdr.de>; Tue,  5 Jan 2021 19:28:17 +0100 (CET)
Received: by mail-qt1-x83f.google.com with SMTP id i13sf413146qtp.10
        for <lists+kasan-dev@lfdr.de>; Tue, 05 Jan 2021 10:28:17 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1609871296; cv=pass;
        d=google.com; s=arc-20160816;
        b=0jGRcm/WmCYGgJ5kdAk60WwxVCTNBYa5m1NAPoIo4Y8jRj8e3OVuTq2WmzmjJV3Ov4
         gQR6cWlU9zEWXo4jfTEPxtVnTrY5PeJZZtLLXOEjobxZSLR5G1YF2ZhxswyVPRmX8MKf
         DHuRmpsbZh5Q4DIFMdyOnX/wq8JI62nnS3Ze786N8VdHl7jBZW+a7BXA8vRtjoh1AKTC
         hd7PzlfqCimlac5dBn0zbbh1B0c7ntVsFhB+TdANJlFpwnTgDFeh2kygrBkSf806qW35
         UNfZRCfpMkA1/XmYA0XenKpV2PRfSl7kqnIFZ7Ry9h9HJPp7Ix5jusrjS4i8M4CyU6Ro
         4i+Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=4RGT2xy6uRz8B0jGuO63wgheYNuUxVMIzGCFSFQSu7A=;
        b=BHJaasXcdBTmD1ZQ1qMWDFtaXHfoe7lSfQ7U+T3u3VAfiejbmUlTkqKPrRCqdGPc3K
         J0I4RLQDsTJ1iOfgNFhQKDhMkOXd5gy9XOLWyWntRpvFfVon4B2k/d+LgrrlG0U/RlIh
         xIqCktJ6aCiz6inI928/q59WEtfOuQzZNh4yrqRiX1O6a1d7hVx/OlUS80+nrNwwtR4m
         MnatShc5uT4z4EXBjzIlN8Wkgr7pMFzdr6vdJyMbxixZlE4e6barjsaBajw3McRWkP+J
         9791tyo4Gnsm0dMDb0DEkv56F8LtNOpVIbMnSFwwglIHFa9qpFgdxyVpyv0y/ZO3hZbk
         l9cg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jO5CnAER;
       spf=pass (google.com: domain of 3v6_0xwokcfyylbpcwiltjemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3v6_0XwoKCfYYlbpcwiltjemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=4RGT2xy6uRz8B0jGuO63wgheYNuUxVMIzGCFSFQSu7A=;
        b=UCIsTM1GekedGYFzr8b0jvAJzXVWf2HXeGi6pHOfmoiOE7lx+N3Dxjh1O+7nro3uLp
         088ICFXvpGMiX/HRRi07RCBKoZlOU6bUozKtD6k4NVE1ufXJnnnM1r1sJvi17oo0pgnm
         XlFU72T7jgzIyONWYb8AYmZLycs3eCUhEfV/gmr7JjoIxGHf+LWkogaiL9pR1mpVQPyB
         bu3o9aH4l7mDH2sneE/Zj4VcCO5eZEbPfQsUBhwBDOVL6opzGnSwYxvVE4xK5r/4ybIi
         GW9aeAsWPJhl2aPzRKQVdtBM3r2gTtNSSNCWMwiaF6YQV6VwhwIt++EBl9Wto4ZptMBH
         pVGQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=4RGT2xy6uRz8B0jGuO63wgheYNuUxVMIzGCFSFQSu7A=;
        b=GdfSsR1GJ7JgvV8pLxIi9PPVX7BKJXA/NQz78QDoz6sLjhYFbX5dcsvH7+lVo/6/GB
         cmUFCJj4fKcRolhytcpGkcSQVdbnuH3je8joBFtJ16xwMifDhLY/IoMCQ7ktJ7KtZLd9
         6mA8ka3dYgTuXQ4k1IclAvP5e33HU7G4Q12S+hqiZtYbzuOO5RY2cQ0PzXuMHhgrVv7x
         semY6KKkR0RsjzYLsiR+KvRtZuW/QYR4SilgCFfx4IHxjK4QAr4H3OKA93sHOdv5RzSO
         JEOCxQ7xW2YnnjOPM3Yv5R0AP5JWvsu1GAHdGD2LZV7XCJ0vF//x5ANn9dmrGQYGXq9g
         ccxg==
X-Gm-Message-State: AOAM533IerPFqRbEQZMJwPPDHI0GXxf0UHDivcYWR11N2ryG5v6XKoFM
	xQ+iC0N8BH/+bGx2iYgA2IQ=
X-Google-Smtp-Source: ABdhPJxQTdG+dOry2xPMExzVozxrCp4SEsDNEFVxRtsxXEC71KoVla6fjw0aQlqy1i0IcbfwE8xBeQ==
X-Received: by 2002:a05:6214:727:: with SMTP id c7mr498258qvz.22.1609871296193;
        Tue, 05 Jan 2021 10:28:16 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:5ece:: with SMTP id s14ls282811qtx.4.gmail; Tue, 05 Jan
 2021 10:28:15 -0800 (PST)
X-Received: by 2002:ac8:7141:: with SMTP id h1mr734539qtp.211.1609871295762;
        Tue, 05 Jan 2021 10:28:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1609871295; cv=none;
        d=google.com; s=arc-20160816;
        b=i3ex8+1hgD0IFRAuJelfCUc5wGL+Nz+oiwF0c4Uh+s/AqOk5sKfiVF6eD6Cl316cum
         xPFFijSwk1oz/eeuy224aHVErRBmvlDtPkBwQ5BKD3TRQe1apjpZscStBcJiU7JHd9tX
         QOSlf/S98QINgW03mriab+Hgw+weqc1p/XRWeemnAJpG3rzIVBz83kwOD7NUY1MGI8dA
         EiD6JRdbUpZ7kjkP3/XPHFitDAF9zs/ktEbi6NWQ5M8jP4ztOcWkr6SpzwqYpl7EV7Qo
         ljoDmUhmLYdXiThdAh66XUUfgH08aSbXUDpoDRcJ/8ZmIwyHHcgzKkMszfcALwAE2GSn
         lHbw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=fpLOhPj99FTMaF5xDNOc2fjXP3fAJlS0mlqNObUGCRg=;
        b=m0reml5s2j9AO6g7sFekEcBMOzkJZenbbdroVwEEUStw9pLcEjlExnNCV9ES/fvWVM
         vDRUxObfO1xXYxd1/RoKOXeG8fbU9ix/y+vj+HYeX5gSWg6L9izTaSVsi5RGGGdBePch
         f+JLWG7ybqkQfuJeKhm55XdIWhhlx53sHJgJkbJCe83JyWudTm7DAqCeNLdkaoMIB7YZ
         9KeR78TMW5jn2jnRglc/v64Id6feKvSKZ1N96DXnb8Nk6RVNWv9HAeZoijGOr1AmcuBQ
         PQgocVgcF7jiKpIbLES5dxwocjMoCUgOGPn0SodGnUKayZ+qck1SikRI3EeipZPLKJzS
         Vwgw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=jO5CnAER;
       spf=pass (google.com: domain of 3v6_0xwokcfyylbpcwiltjemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3v6_0XwoKCfYYlbpcwiltjemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id c198si5950qkg.2.2021.01.05.10.28.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 05 Jan 2021 10:28:15 -0800 (PST)
Received-SPF: pass (google.com: domain of 3v6_0xwokcfyylbpcwiltjemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id x74so509523qkb.12
        for <kasan-dev@googlegroups.com>; Tue, 05 Jan 2021 10:28:15 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:f54c:: with SMTP id
 p12mr805903qvm.35.1609871295458; Tue, 05 Jan 2021 10:28:15 -0800 (PST)
Date: Tue,  5 Jan 2021 19:27:49 +0100
In-Reply-To: <cover.1609871239.git.andreyknvl@google.com>
Message-Id: <dd061dfca76dbf86af13393edacd37e0c75b6f4a.1609871239.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1609871239.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.29.2.729.g45daf8777d-goog
Subject: [PATCH 05/11] kasan, arm64: allow using KUnit tests with HW_TAGS mode
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Catalin Marinas <catalin.marinas@arm.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Will Deacon <will.deacon@arm.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, Evgenii Stepanov <eugenis@google.com>, 
	Branislav Rankov <Branislav.Rankov@arm.com>, Kevin Brodsky <kevin.brodsky@arm.com>, 
	kasan-dev@googlegroups.com, linux-arm-kernel@lists.infradead.org, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=jO5CnAER;       spf=pass
 (google.com: domain of 3v6_0xwokcfyylbpcwiltjemmejc.amkiyqyl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3v6_0XwoKCfYYlbpcwiltjemmejc.amkiYqYl-bctemmejcepmsnq.amk@flex--andreyknvl.bounces.google.com;
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

On a high level, this patch allows running KUnit KASAN tests with the
hardware tag-based KASAN mode.

Internally, this change reenables tag checking at the end of each KASAN
test that triggers a tag fault and leads to tag checking being disabled.

With this patch KASAN tests are still failing for the hardware tag-based
mode; fixes come in the next few patches.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Link: https://linux-review.googlesource.com/id/Id94dc9eccd33b23cda4950be408c27f879e474c8
---
 arch/arm64/include/asm/memory.h    |  1 +
 arch/arm64/include/asm/mte-kasan.h | 12 +++++++++
 arch/arm64/kernel/mte.c            | 12 +++++++++
 arch/arm64/mm/fault.c              | 16 +++++++-----
 lib/Kconfig.kasan                  |  4 +--
 lib/test_kasan.c                   | 42 +++++++++++++++++++++---------
 mm/kasan/kasan.h                   |  9 +++++++
 7 files changed, 75 insertions(+), 21 deletions(-)

diff --git a/arch/arm64/include/asm/memory.h b/arch/arm64/include/asm/memory.h
index 18fce223b67b..cedfc9e97bcc 100644
--- a/arch/arm64/include/asm/memory.h
+++ b/arch/arm64/include/asm/memory.h
@@ -232,6 +232,7 @@ static inline const void *__tag_set(const void *addr, u8 tag)
 
 #ifdef CONFIG_KASAN_HW_TAGS
 #define arch_enable_tagging()			mte_enable_kernel()
+#define arch_set_tagging_report_once(state)	mte_set_report_once(state)
 #define arch_init_tags(max_tag)			mte_init_tags(max_tag)
 #define arch_get_random_tag()			mte_get_random_tag()
 #define arch_get_mem_tag(addr)			mte_get_mem_tag(addr)
diff --git a/arch/arm64/include/asm/mte-kasan.h b/arch/arm64/include/asm/mte-kasan.h
index 26349a4b5e2e..3748d5bb88c0 100644
--- a/arch/arm64/include/asm/mte-kasan.h
+++ b/arch/arm64/include/asm/mte-kasan.h
@@ -32,6 +32,9 @@ void *mte_set_mem_tag_range(void *addr, size_t size, u8 tag);
 void mte_enable_kernel(void);
 void mte_init_tags(u64 max_tag);
 
+void mte_set_report_once(bool state);
+bool mte_report_once(void);
+
 #else /* CONFIG_ARM64_MTE */
 
 static inline u8 mte_get_ptr_tag(void *ptr)
@@ -60,6 +63,15 @@ static inline void mte_init_tags(u64 max_tag)
 {
 }
 
+static inline void mte_set_report_once(bool state)
+{
+}
+
+static inline bool mte_report_once(void)
+{
+	return false;
+}
+
 #endif /* CONFIG_ARM64_MTE */
 
 #endif /* __ASSEMBLY__ */
diff --git a/arch/arm64/kernel/mte.c b/arch/arm64/kernel/mte.c
index dc9ada64feed..c63b3d7a3cd9 100644
--- a/arch/arm64/kernel/mte.c
+++ b/arch/arm64/kernel/mte.c
@@ -25,6 +25,8 @@
 
 u64 gcr_kernel_excl __ro_after_init;
 
+static bool report_fault_once = true;
+
 static void mte_sync_page_tags(struct page *page, pte_t *ptep, bool check_swap)
 {
 	pte_t old_pte = READ_ONCE(*ptep);
@@ -158,6 +160,16 @@ void mte_enable_kernel(void)
 	isb();
 }
 
+void mte_set_report_once(bool state)
+{
+	WRITE_ONCE(report_fault_once, state);
+}
+
+bool mte_report_once(void)
+{
+	return READ_ONCE(report_fault_once);
+}
+
 static void update_sctlr_el1_tcf0(u64 tcf0)
 {
 	/* ISB required for the kernel uaccess routines */
diff --git a/arch/arm64/mm/fault.c b/arch/arm64/mm/fault.c
index 3c40da479899..57d3f165d907 100644
--- a/arch/arm64/mm/fault.c
+++ b/arch/arm64/mm/fault.c
@@ -302,12 +302,20 @@ static void die_kernel_fault(const char *msg, unsigned long addr,
 static void report_tag_fault(unsigned long addr, unsigned int esr,
 			     struct pt_regs *regs)
 {
-	bool is_write  = ((esr & ESR_ELx_WNR) >> ESR_ELx_WNR_SHIFT) != 0;
+	static bool reported;
+	bool is_write;
+
+	if (READ_ONCE(reported))
+		return;
+
+	if (mte_report_once())
+		WRITE_ONCE(reported, true);
 
 	/*
 	 * SAS bits aren't set for all faults reported in EL1, so we can't
 	 * find out access size.
 	 */
+	is_write = ((esr & ESR_ELx_WNR) >> ESR_ELx_WNR_SHIFT) != 0;
 	kasan_report(addr, 0, is_write, regs->pc);
 }
 #else
@@ -319,12 +327,8 @@ static inline void report_tag_fault(unsigned long addr, unsigned int esr,
 static void do_tag_recovery(unsigned long addr, unsigned int esr,
 			   struct pt_regs *regs)
 {
-	static bool reported;
 
-	if (!READ_ONCE(reported)) {
-		report_tag_fault(addr, esr, regs);
-		WRITE_ONCE(reported, true);
-	}
+	report_tag_fault(addr, esr, regs);
 
 	/*
 	 * Disable MTE Tag Checking on the local CPU for the current EL.
diff --git a/lib/Kconfig.kasan b/lib/Kconfig.kasan
index f5fa4ba126bf..3091432acb0a 100644
--- a/lib/Kconfig.kasan
+++ b/lib/Kconfig.kasan
@@ -190,11 +190,11 @@ config KASAN_KUNIT_TEST
 	  kernel debugging features like KASAN.
 
 	  For more information on KUnit and unit tests in general, please refer
-	  to the KUnit documentation in Documentation/dev-tools/kunit
+	  to the KUnit documentation in Documentation/dev-tools/kunit.
 
 config TEST_KASAN_MODULE
 	tristate "KUnit-incompatible tests of KASAN bug detection capabilities"
-	depends on m && KASAN
+	depends on m && KASAN && !KASAN_HW_TAGS
 	help
 	  This is a part of the KASAN test suite that is incompatible with
 	  KUnit. Currently includes tests that do bad copy_from/to_user
diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index f1eda0bcc780..dd3d2f95c24e 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -41,16 +41,20 @@ static bool multishot;
 
 /*
  * Temporarily enable multi-shot mode. Otherwise, KASAN would only report the
- * first detected bug and panic the kernel if panic_on_warn is enabled.
+ * first detected bug and panic the kernel if panic_on_warn is enabled. For
+ * hardware tag-based KASAN also allow tag checking to be reenabled for each
+ * test, see the comment for KUNIT_EXPECT_KASAN_FAIL().
  */
 static int kasan_test_init(struct kunit *test)
 {
 	multishot = kasan_save_enable_multi_shot();
+	hw_set_tagging_report_once(false);
 	return 0;
 }
 
 static void kasan_test_exit(struct kunit *test)
 {
+	hw_set_tagging_report_once(true);
 	kasan_restore_multi_shot(multishot);
 }
 
@@ -59,19 +63,31 @@ static void kasan_test_exit(struct kunit *test)
  * KASAN report; causes a test failure otherwise. This relies on a KUnit
  * resource named "kasan_data". Do not use this name for KUnit resources
  * outside of KASAN tests.
+ *
+ * For hardware tag-based KASAN, when a tag fault happens, tag checking is
+ * normally auto-disabled. When this happens, this test handler reenables
+ * tag checking. As tag checking can be only disabled or enabled per CPU, this
+ * handler disables migration (preemption).
  */
-#define KUNIT_EXPECT_KASAN_FAIL(test, expression) do { \
-	fail_data.report_expected = true; \
-	fail_data.report_found = false; \
-	kunit_add_named_resource(test, \
-				NULL, \
-				NULL, \
-				&resource, \
-				"kasan_data", &fail_data); \
-	expression; \
-	KUNIT_EXPECT_EQ(test, \
-			fail_data.report_expected, \
-			fail_data.report_found); \
+#define KUNIT_EXPECT_KASAN_FAIL(test, expression) do {		\
+	if (IS_ENABLED(CONFIG_KASAN_HW_TAGS))			\
+		migrate_disable();				\
+	fail_data.report_expected = true;			\
+	fail_data.report_found = false;				\
+	kunit_add_named_resource(test,				\
+				NULL,				\
+				NULL,				\
+				&resource,			\
+				"kasan_data", &fail_data);	\
+	expression;						\
+	KUNIT_EXPECT_EQ(test,					\
+			fail_data.report_expected,		\
+			fail_data.report_found);		\
+	if (IS_ENABLED(CONFIG_KASAN_HW_TAGS)) {			\
+		if (fail_data.report_found)			\
+			hw_enable_tagging();			\
+		migrate_enable();				\
+	}							\
 } while (0)
 
 static void kmalloc_oob_right(struct kunit *test)
diff --git a/mm/kasan/kasan.h b/mm/kasan/kasan.h
index c3fb9bf241d3..292dfbc37deb 100644
--- a/mm/kasan/kasan.h
+++ b/mm/kasan/kasan.h
@@ -280,6 +280,9 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 #ifndef arch_init_tags
 #define arch_init_tags(max_tag)
 #endif
+#ifndef arch_set_tagging_report_once
+#define arch_set_tagging_report_once(state)
+#endif
 #ifndef arch_get_random_tag
 #define arch_get_random_tag()	(0xFF)
 #endif
@@ -292,10 +295,16 @@ static inline const void *arch_kasan_set_tag(const void *addr, u8 tag)
 
 #define hw_enable_tagging()			arch_enable_tagging()
 #define hw_init_tags(max_tag)			arch_init_tags(max_tag)
+#define hw_set_tagging_report_once(state)	arch_set_tagging_report_once(state)
 #define hw_get_random_tag()			arch_get_random_tag()
 #define hw_get_mem_tag(addr)			arch_get_mem_tag(addr)
 #define hw_set_mem_tag_range(addr, size, tag)	arch_set_mem_tag_range((addr), (size), (tag))
 
+#else /* CONFIG_KASAN_HW_TAGS */
+
+#define hw_enable_tagging()
+#define hw_set_tagging_report_once(state)
+
 #endif /* CONFIG_KASAN_HW_TAGS */
 
 #ifdef CONFIG_KASAN_SW_TAGS
-- 
2.29.2.729.g45daf8777d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/dd061dfca76dbf86af13393edacd37e0c75b6f4a.1609871239.git.andreyknvl%40google.com.

Return-Path: <kasan-dev+bncBDX4HWEMTEBRBCVNQ6AAMGQEZ6LMNVA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3e.google.com (mail-qv1-xf3e.google.com [IPv6:2607:f8b0:4864:20::f3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 89D542F82F7
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 18:53:15 +0100 (CET)
Received: by mail-qv1-xf3e.google.com with SMTP id c2sf8384619qvs.12
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Jan 2021 09:53:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610733194; cv=pass;
        d=google.com; s=arc-20160816;
        b=hHE00DR3PJ+7C1mz0m3ZaEVJn5LHVmBec7s/2gddWsnt+R8RzuShii8aWsi/Og9nnQ
         GAxrs+sYIODJPWzdP0Erv31E/m+VelzI3Dyv0ojmz+RbmkMULjc5rDUG7RimnZ8Ogqxs
         FbEH30F2IZDETrIkuekG3IdBHGQY1e30B0uuJUk09mVTSNt7V57WbmL0y2CG31DzjIXj
         Vl9T+NwK47eo9Xq5tFVMxX3vclFeYPjZW2DdhDHQO6hTAoE1b/pHXSKvWcifkGAPThxt
         qx6ZKfOJPdVZlcG0grWR63k/cFfSD6cOro1CwSqBsbvc821d8QwJCsUd++w9bK5lXwkS
         z3Ig==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=5W1dTschgQJKCiNFn/rmtHLOyx9M/A8cs3LlUnfyg5U=;
        b=0W8YOdCzGyjQiTbnsNK4p8/+ja+q6QY8s+b5fowYZfWVFFtbJQUbXCmR96tq33ysSk
         QTtgQOrkGFTRMfpQISAcyklb2eNJ/pu1sbhpx8sES3uQsHFjpsWfakB+dGpoi9tNAEkF
         VZ1clY/84XF5Cgfqst+zRSmS7245EQTikwVxhhi2w/DTCeA5IMdCIX8oGaA8o2p0Q7eb
         zH/i/+mtZMrexpc7D1AwkJvT2VQgMt8owMyhu0W1A+4EBVwoZG3mTBasFqqU0RYAuC3f
         GvStbiFVcYrm4FBxZG/XyKROzj3tgpTK+CfJ9a5brPSftoNTFx8YuqOr1TRGLUCt2mGv
         wzLQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YGhs6+f0;
       spf=pass (google.com: domain of 3idybyaokcuqgtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3idYBYAoKCUQgtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=5W1dTschgQJKCiNFn/rmtHLOyx9M/A8cs3LlUnfyg5U=;
        b=SELVW5oZK7NGCx6iI+eayyqeZp+Ffz1vsWfOe1dLZr002MBjKU9SzOb1IE7aLCteMD
         qBi39U+2R8G037cgxIw0uSDk03ZA84DUSLpxV+yLAiEQQyCcvO5vmHs/yvXBamggdRlE
         uoJy9qBB3afHxQFCkfUj8/CwMSnUCuiebctET7y5JYLXNBd1/ecdwKOBZfpGg1Za5txe
         vl7KJd0pZ7MEZjwrqZyeC9sG6LUjJ4Mf3bNeMynjIPN+DriXqVeixxPyir0ruUTOPrft
         pXhjJnOmvvFIig8Torgr9rxYvBv4bI+aMsmCLHCO7IRXrbi5HrB5DfnITNVZNIMKPH3t
         gVpw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5W1dTschgQJKCiNFn/rmtHLOyx9M/A8cs3LlUnfyg5U=;
        b=TEjqFaPjCGzdcOSbytZsUOR9d0D/bWTte0d5rKMcVHbNCfaZMfRFRNPkUEXShGoJ/L
         RH/RC/3OpqASJYlk1ey6fnHa8ehpnsetRdXFXQ2HyHK1CJjvvfFpHY7bspPAn9WJ/kv+
         c/YrVGnJDGvthkYq8tXuAJtW00zWnioI9xqxAXsxQNvosUdrzFQyk/0wVnHTrNvc77gV
         WUp6s25aqvLhr5b/oqcSsocvtKTvotwfAaiPcgYkzZvhDUtJo9sqQU8jNPScBYyEMylI
         jylG/OgfAL1zcI0lrRQRjV/sjUx4ya1OviNCo915en9be8eaAFE1b7WhVF1ngO61JspR
         UZEA==
X-Gm-Message-State: AOAM531941rJuAL6HXjOtK4u2qzuzPgiIppWfRk/GVrCwiBIi9uzQhTd
	vriQ5sRcoLRiC2zfEr9+ycU=
X-Google-Smtp-Source: ABdhPJzgow6/A4mvKsk7l8HRGUnmyu2Az/6JjeZ3CubK/nSLV9ke3Uz1s+k/rnq6QgXVXqSJ++hy8w==
X-Received: by 2002:ac8:5ed5:: with SMTP id s21mr13037918qtx.114.1610733194653;
        Fri, 15 Jan 2021 09:53:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ae9:c001:: with SMTP id u1ls4975395qkk.1.gmail; Fri, 15 Jan
 2021 09:53:14 -0800 (PST)
X-Received: by 2002:a05:620a:ec5:: with SMTP id x5mr13125969qkm.143.1610733194222;
        Fri, 15 Jan 2021 09:53:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610733194; cv=none;
        d=google.com; s=arc-20160816;
        b=P+98mAmrnYLwB3Y1Pt3aSXOF7R+DdzuYrRIo6fLV0ZiIGun/YaOxmCecXKyuuspqup
         2jKfePNrBRRLJbRsUDX9kacse27fN+wJUXJhhkQc1wCHZ+mkg2cUd+f8hTDu/yp9Nw86
         7mi3hIMa+LSnvH8gysiIuoyEC1p6xe74otURS6qprbvv9a5mRlC1x6oiv0kFNARn1xmp
         nP3NJJOlsTnqDkXtrFdgrnKRjE/KKH+Cl7OmwN6H3CaNV2dxC62FEITsZfqV9IPpLYoh
         7LenRH9caIEJJSlfchdZ0WsP8xEANX5LRIQsUdI4MIrNEeOWkJzNdA1wi6r7Eo1MrPXj
         SrZw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=9on6B0atcycuyeVrYw1IPAD/5QIL4ENYnqCtl+BcpGs=;
        b=VOMUQEqKuPL1ZBzCmH9YQs9d7RZqqw/tDVfKkezNdBT+vq7j9bcZMtt3YLwTxqbB7Z
         RNYh4gC+Twy3OmV8lEPP1fjlIf7Z+s/DS9wtzY27S337DUeC7lboM2yOFek1faVJtQSx
         atB9MNf9LBbXeVJ+vGhu6sPzSESK+TJOynGFjCu2W7uyPJsMFPueSUzSzYQ0/cV/4K+a
         9Csq/iI7orli758pKRz4rzdCFnV84nv3aEp6akUEGMD81g4Q3NSRcIRPZ/pAucAWSMS6
         J+oloekwW9ucC3R5is5kRXqPF+2XsUA27oR+LIhQcsAp60rW9y/6nKZ8hAbIIK6yApaC
         3XYg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YGhs6+f0;
       spf=pass (google.com: domain of 3idybyaokcuqgtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3idYBYAoKCUQgtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id i2si760522qkg.4.2021.01.15.09.53.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Jan 2021 09:53:14 -0800 (PST)
Received-SPF: pass (google.com: domain of 3idybyaokcuqgtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id l3so8384250qvr.10
        for <kasan-dev@googlegroups.com>; Fri, 15 Jan 2021 09:53:14 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a0c:c211:: with SMTP id
 l17mr12803811qvh.53.1610733193859; Fri, 15 Jan 2021 09:53:13 -0800 (PST)
Date: Fri, 15 Jan 2021 18:52:43 +0100
In-Reply-To: <cover.1610733117.git.andreyknvl@google.com>
Message-Id: <51b23112cf3fd62b8f8e9df81026fa2b15870501.1610733117.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1610733117.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.284.gd98b1dd5eaa7-goog
Subject: [PATCH v4 06/15] kasan, arm64: allow using KUnit tests with HW_TAGS mode
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
 header.i=@google.com header.s=20161025 header.b=YGhs6+f0;       spf=pass
 (google.com: domain of 3idybyaokcuqgtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3idYBYAoKCUQgtjxk4qt1rmuumrk.iusqgygt-jk1muumrkmxu0vy.ius@flex--andreyknvl.bounces.google.com;
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

Also simplify is_write calculation in report_tag_fault.

With this patch KASAN tests are still failing for the hardware tag-based
mode; fixes come in the next few patches.

Link: https://linux-review.googlesource.com/id/Id94dc9eccd33b23cda4950be408c27f879e474c8
Reviewed-by: Catalin Marinas <catalin.marinas@arm.com>
Reviewed-by: Vincenzo Frascino <vincenzo.frascino@arm.com>
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 arch/arm64/include/asm/memory.h    |  1 +
 arch/arm64/include/asm/mte-kasan.h | 12 +++++++++
 arch/arm64/kernel/mte.c            | 12 +++++++++
 arch/arm64/mm/fault.c              | 20 +++++++++-----
 lib/Kconfig.kasan                  |  4 +--
 lib/test_kasan.c                   | 42 +++++++++++++++++++++---------
 mm/kasan/kasan.h                   |  9 +++++++
 7 files changed, 79 insertions(+), 21 deletions(-)

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
index 35d75c60e2b8..570c02671d19 100644
--- a/arch/arm64/mm/fault.c
+++ b/arch/arm64/mm/fault.c
@@ -302,12 +302,24 @@ static void die_kernel_fault(const char *msg, unsigned long addr,
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
+	/*
+	 * This is used for KASAN tests and assumes that no MTE faults
+	 * happened before running the tests.
+	 */
+	if (mte_report_once())
+		WRITE_ONCE(reported, true);
 
 	/*
 	 * SAS bits aren't set for all faults reported in EL1, so we can't
 	 * find out access size.
 	 */
+	is_write = !!(esr & ESR_ELx_WNR);
 	kasan_report(addr, 0, is_write, regs->pc);
 }
 #else
@@ -319,12 +331,8 @@ static inline void report_tag_fault(unsigned long addr, unsigned int esr,
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
index c344fe506ffc..ef663bcf83e5 100644
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
 
 #define KASAN_TEST_NEEDS_CONFIG_ON(test, config) do {			\
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
2.30.0.284.gd98b1dd5eaa7-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/51b23112cf3fd62b8f8e9df81026fa2b15870501.1610733117.git.andreyknvl%40google.com.

Return-Path: <kasan-dev+bncBDX4HWEMTEBRBUN2QKAAMGQEPHESNKA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 02B1A2F6B1A
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Jan 2021 20:36:50 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id r5sf2263408wma.2
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Jan 2021 11:36:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610653009; cv=pass;
        d=google.com; s=arc-20160816;
        b=wr+gG9vlF6FsuQsQieEbuU4DV1Ma6Zd7V1IwnLSnojy6zXIsGCJIx5EkUJ40mSym+a
         44/4VTrdeaC9cr0R/IT8vWeMyYGR+9qdHisxt9PP97ki+AUCNXvRFI3xgIcrbGLFPdW3
         bc2QMWy3Tr01RpHRrh0kJvVz8gCVDaoF1lSLGDHn3wkFBLuEWkk2yY3g3movalJ5EJMm
         GzvkQEPu85CzHwx+3pgAyc8u8fvRtrmBo/T0Cy5S4bJYNzdtKqJ61eQxOSEDBepz9uXT
         SLy/LxYjzzxPvSf7SvDfztWj59gr92JM/quimiBdLUy9qMqGOPgf3pxtv1X/JrnPx7Nq
         5rKA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=nyE9TT89mbheQCfuw3KALyQMsugE1b1DNe/L5DcX1JE=;
        b=gymMl5phNgEbRBE9+dfvR4Gi5OlQFTDxRc0YBWsTWuQtPqMChwgZijcvHPKV6/dGJF
         h7OQNekM6iYDOr/SlGsnItDq1WIid5BuCAcfAlD4ZnzeU+wvANtBqO8AwSsTYa/bPXYD
         J/UW3KulJEI8UJrwDRm1D6TfXsqQlyyB5VpYT+2JG1fwRN0idwtc88zUkFVgg68cyhcf
         tj9OwaPGSdOMswHOrOUPIA03Fa6mknlMODAvQlJkjQEUd3NiLQyHZBzjG+IXrBfD9G3v
         S5LlmG/pXYnJyVpO3oD55DgrB1ffCBED6skixj34lkkY82EHJByaz7KzZVRxUk8bfeKW
         Uyuw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YPOqpwdC;
       spf=pass (google.com: domain of 3uj0ayaokczmxa0e1l7ai83bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3UJ0AYAoKCZMxA0E1L7AI83BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=nyE9TT89mbheQCfuw3KALyQMsugE1b1DNe/L5DcX1JE=;
        b=FOJVv37tOQeiOW3AdGEuLIhajTNB7Z4xlddQuuMq5NX25HCHXFKxI0t4mkyIEyXW5U
         pRBktXlmuIrRD9VycFh4PuwaO+BW+iEkGZf+OsdoKE83W1qlK0tUz2Z8RMvQt4VIt144
         5p5fQaxcSa6PitGH0u5eq2ydC30SBrSsdcGbTYk58LKa3bb9lVy2xoABHt0TmniUg7ZY
         OCMqeox1z9Bny19UlMjpzibpBZdpMDIYaP4IuL+mZ/X9sOlKw0pjZJOMSVUdss0VXMIx
         fbMA8faJBFeBmMJduuGwirCaOudElvRixHKeN9hN6oGJn7UA5/mjjD6VLjruv72oQWlm
         95TA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=nyE9TT89mbheQCfuw3KALyQMsugE1b1DNe/L5DcX1JE=;
        b=ZfT2BeV8umMJMsH8pI/qcHE/4y4Eg74xmDnwAXmBsVOQrm6oolzAiTqyaMZfX1j1o1
         HT63Zvic5DDWXQGoQMONQ6W8tFFQVSP3MiB2nFxrBqKSETeqVb+oyUWCkTXwQNWF0ear
         3iNDOw2jED5pKYmboRRLXzNHE1hjLCJXikp81mO6vot6LjwCiwU3EVXktkAitzOVSsCb
         the9R2WdDNwBeH4TvxAUt/KrfC/DcjS9vyo27i5Kkh0aLdrcWuVRKS4pjh6sOTpSBYqK
         7D9YwEg/8ZM43j4mP032aZ3zm7RRfszAgke5YDXzfwx2raLuGUzkeyFvtqPKdU+R7fto
         IANw==
X-Gm-Message-State: AOAM530kLGJ4UDlw1P2MMiTnZOxxWoMqrB5iE1lR8OdOtwOWjt22luXu
	rDWDA+ghsIsO/FxiPs6l4no=
X-Google-Smtp-Source: ABdhPJxg9s4HMwrpkzQDZ0gHoa4Qsd21pXSjE4Vuki6g/1DN3X7eesOZYL7Iuth+620VuudkO7gITw==
X-Received: by 2002:a05:600c:4ed0:: with SMTP id g16mr5352661wmq.176.1610653009722;
        Thu, 14 Jan 2021 11:36:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6812:: with SMTP id w18ls6480791wru.1.gmail; Thu, 14 Jan
 2021 11:36:49 -0800 (PST)
X-Received: by 2002:adf:ba0c:: with SMTP id o12mr9476038wrg.322.1610653009031;
        Thu, 14 Jan 2021 11:36:49 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610653009; cv=none;
        d=google.com; s=arc-20160816;
        b=KHo9j5GkCRfbD8Qj3KKF3sEX4NTcrCtPXxQYCPglEHtKDVosJj8pLsvB3N5af9aL64
         tj1l9Dh7eoi5MHJM0xdLU1tLRfsEh4hHJi4rzi82LrMjsK4D3I9w0RX4DtZfKMpImZnc
         j6MKJCYyFxvzDPXkUzD9B+YayVPmMC11OLDADgGlQDJ/WZIokH5/gGsSJMSBLnG74jyL
         IoaowLOw7aTEKyzIhzsyZcWoqLb19+wWTokp7N/XON4ak/Bd1q+2OJsjzvSl+/hDsmVj
         14e2s3R81F9Bz/rcEJR/SUptVU+6t/r20eKtW830evmB/Z92gcVK1aWMIpUBE+I+BuSo
         b98g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=dlHBXzPVuIEZihoAP6Eo/10Jyzfh4Jei55DxNnJp35U=;
        b=FPosFaWu5xLBduczVjImgDrPEc+jvkNQdYuNPOAye+Evf37T91ietQ9izbwJpwqypG
         hGhuZV7x0Y7OvYobKgXvUtHELDbNfSfjh6DNuXBjJK4yf7CRfZbAlIn8roHjAomq9+hJ
         ZkIv3nBfquy2ntMnfq+sddEIcdv9hfdrnOPQiVG26G1tY6sIO6Vx+F6dhLzJV/LIu0Uw
         KgSQreEliC0giRMH6b68w8W92PEQuk+ywLeZ1b/+ZhnBQbyEC7DEO/KZjetrbikOB2C+
         agzYcY9Sin0nywI88W20aE0oXs54hVfG0nudpFO+9F1K1PNbk3oxwaKw3jjyeYzNRvGh
         rtAg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=YPOqpwdC;
       spf=pass (google.com: domain of 3uj0ayaokczmxa0e1l7ai83bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3UJ0AYAoKCZMxA0E1L7AI83BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id z188si403312wmc.1.2021.01.14.11.36.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Jan 2021 11:36:49 -0800 (PST)
Received-SPF: pass (google.com: domain of 3uj0ayaokczmxa0e1l7ai83bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id q2so3054736wrp.4
        for <kasan-dev@googlegroups.com>; Thu, 14 Jan 2021 11:36:49 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:a1c:dc46:: with SMTP id
 t67mr4074942wmg.183.1610653008585; Thu, 14 Jan 2021 11:36:48 -0800 (PST)
Date: Thu, 14 Jan 2021 20:36:22 +0100
In-Reply-To: <cover.1610652890.git.andreyknvl@google.com>
Message-Id: <a9f4f5140088f5e7b1b643c3e59799416c265c4b.1610652890.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1610652890.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.284.gd98b1dd5eaa7-goog
Subject: [PATCH v3 06/15] kasan, arm64: allow using KUnit tests with HW_TAGS mode
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
 header.i=@google.com header.s=20161025 header.b=YPOqpwdC;       spf=pass
 (google.com: domain of 3uj0ayaokczmxa0e1l7ai83bb381.zb97xfxa-01i3bb3813ebhcf.zb9@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3UJ0AYAoKCZMxA0E1L7AI83BB381.zB97xFxA-01I3BB3813EBHCF.zB9@flex--andreyknvl.bounces.google.com;
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

Link: https://linux-review.googlesource.com/id/Id94dc9eccd33b23cda4950be408c27f879e474c8
Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
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
index a218f6f2fdc8..f1b77dc79948 100644
--- a/arch/arm64/mm/fault.c
+++ b/arch/arm64/mm/fault.c
@@ -302,7 +302,14 @@ static void die_kernel_fault(const char *msg, unsigned long addr,
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
 
 	/* The format of KASAN tags is 0xF<x>. */
 	addr |= (0xF0UL << MTE_TAG_SHIFT);
@@ -310,6 +317,7 @@ static void report_tag_fault(unsigned long addr, unsigned int esr,
 	 * SAS bits aren't set for all faults reported in EL1, so we can't
 	 * find out access size.
 	 */
+	is_write = ((esr & ESR_ELx_WNR) >> ESR_ELx_WNR_SHIFT) != 0;
 	kasan_report(addr, 0, is_write, regs->pc);
 }
 #else
@@ -321,12 +329,8 @@ static inline void report_tag_fault(unsigned long addr, unsigned int esr,
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/a9f4f5140088f5e7b1b643c3e59799416c265c4b.1610652890.git.andreyknvl%40google.com.

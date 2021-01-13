Return-Path: <kasan-dev+bncBDX4HWEMTEBRBKN47T7QKGQE35535NY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73f.google.com (mail-qk1-x73f.google.com [IPv6:2607:f8b0:4864:20::73f])
	by mail.lfdr.de (Postfix) with ESMTPS id 302692F4FC3
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 17:22:02 +0100 (CET)
Received: by mail-qk1-x73f.google.com with SMTP id 188sf1713882qkh.7
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Jan 2021 08:22:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1610554921; cv=pass;
        d=google.com; s=arc-20160816;
        b=U2EjW90k1Vu2OQI1kS6q7wlJ2fSnblO6TNCG/z/r+Hvp8aJd1WuDAiFYtqZ6Hm74Sz
         MNIti0JfN2h5GqOjODrWGrOJA0f1Ib+oQjsWGy0tdemJUFQgzVYtIOGQV2BrJcKgAAsG
         8tAJ/LhyzjyokpYipcihovBiYf7CQb8nb5Og6TeHpu41skVJqPugrmUk1MYZOFAFtlFk
         x90Sq+TmMhFxVODBT2jER8gGPsy3GQLUq+wOavhEwjR79+EZ/oEdTitB6nu9NC1DBQur
         fgFs046RC+9781ChcxgtHaaUzPvSfveubR339ig8FqJlBcfm2eAljsgXG50+EMN/rnJe
         Cb7Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=LjSOAo2+LYHWDVHpkCjyOzmbWxUt2V98aDNFCHBsSBE=;
        b=bRNEk18seaWQWZV3UbKgr8l8E05BGRkk2+nAUMh8kX+uLYvL5LdDGsKt5ZUtkweGSD
         IZClZZfZWnfoBcJyuyx0I4sT13I1MRh51MvpOZTWA5oI1yMNzGLv3UIVGiU2yKPa4XJR
         MpWcBpDCEqeAqIylSG9QoOCGoaYWYGcxHnCR5BUnq5pIu0qTUuNSkj0irHCxjDNhQWi7
         irwvk3Dsb64MP6KkOBU4qYIwG+9QjCrjz39cubD+jZpCyBoLISpKfuCD3sA6xi0FFNM0
         WCgL/k1/u95WQS0Ve7K2tGL2tUjQde5pKzXFayYjFysd++LXhRs0ONZies9BuoM15Ex7
         LYfQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PzCt7v1s;
       spf=pass (google.com: domain of 3kb7_xwokcwcfsiwjdpsaqlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3KB7_XwoKCWcFSIWJdPSaQLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=LjSOAo2+LYHWDVHpkCjyOzmbWxUt2V98aDNFCHBsSBE=;
        b=ItIzuaO0Lb0IhxsM9qZOgLQzKQsQ2u+azNw2XdlWKaVprt1C6f6Xpp0a95eKkTsX+U
         6MQacj1t+nHJJeopHZCfqMHLAqE5NEMsn3CtJ8tNaabBR4J9ciMbhuRqolzxkqr449qY
         sPJowjFqvxXI5X0BWdWIbbNMqsg3Tdlvc9xWBhyNLjehsuSuir2Bg2uWX+tEEO5EbgEd
         cQyTzq1DSPy5Xfth8ur5VelfRt6NtWKq1arqeaZvyitkcFQaGZC3vyyZeGoqphSmNEP8
         4MgFg4Tr62xButnlh79c7/DFd+u2DDWAVZrdT0j36vhOg+BnaFQKofKDQkTc1TiM1BjG
         8fmA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=LjSOAo2+LYHWDVHpkCjyOzmbWxUt2V98aDNFCHBsSBE=;
        b=FQdHC236STdSGD26RH4sN2BGZ7pcP1REJn73RfZBuytXKfT/joV7ij/FOKK49xaMVt
         S6nrCVllWjjx1qVAU/3uWv8TMdqlhyOu7cUIKaN42Ojprr6fGVhfACVePGE/bmm+QmCm
         U4OFXYNQb5gm4r6d2ck+TevzIdbSCZK7O4R8iePM41CZBOfJuJ699WdHkxQzx+fAMHTX
         lJnhNkNJTvH4ZW6sl/5hQV1LJuwpDF4AxLbXP3+WBwE+BG9hJYf8A6F9uGsbnvw8m/kK
         CuOUMcKCB80G65tHbMRiqEFQRfOOM1ictl+89x1GGnQ0DZhlrtIiDfFeJu1iX6jiWx/2
         u0lA==
X-Gm-Message-State: AOAM5312eJGU/HR9GBPk4bsiJYGybT0511ZbEfPPU17mi2hllDtrtbQk
	mtgwlVOMN2BlSCJK01wJZQE=
X-Google-Smtp-Source: ABdhPJxhlFUmm76k4c+4QUHPsP4VBQEjbMDPfQRV/lAuA1PoP/zzcEiS9dBfrJS5Z+m/mV33jD2WNQ==
X-Received: by 2002:a05:620a:1368:: with SMTP id d8mr2694002qkl.101.1610554921319;
        Wed, 13 Jan 2021 08:22:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:e903:: with SMTP id a3ls562541qvo.4.gmail; Wed, 13 Jan
 2021 08:22:00 -0800 (PST)
X-Received: by 2002:a0c:a905:: with SMTP id y5mr3092279qva.55.1610554920853;
        Wed, 13 Jan 2021 08:22:00 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1610554920; cv=none;
        d=google.com; s=arc-20160816;
        b=EkRuhRBoK2yAS2mSkkrhaKDttqGc6WbEMldVyMrZvoOkwGJs1NERSmW/ewI754M/IM
         MshXgl6ZzEHK8OZE7qSHRlUkBgQrgR/WzWugLYKbM/TAR95EkDQQc//EujxwYPvjEnrs
         8WS345yy7PF3AxUJmuzAomwAgCjR9VTeyhxzKf+JNQwz91F8Ti6n8GB0cQYjKEcLMZTD
         WkivRdRTasHwvussQ7ZTOBa/ZE++C1nJpy0tAai6MNi309uKyyRRFYuxas7xehmiRVsg
         nFzs+55KZFwTaxJmQxxXFpxMwQ1SZ2WKXL5+fLONCNxwmJty8i20eaOVv2oBPDEpW4BP
         vu2g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=LSMsi4zyV7YPeXTfQ3D9RvW7XYRQ+wYWvnKyzhaYJjY=;
        b=vHQ4R9RTu0R6E2D93XOn4YYvzcHcRkEicLnZjGt0/Tvh9t6bcBl0DMV+6GyWI5ko/F
         g1rsqSMCCt3648x3tAgie5MVLojaScwsLlNnYgV4T+E8nPeW4aMODJjZPNB1zMnlSWQU
         f7pxltjQmfQ5f82UFMddxgvtxppj1yOCEfEZhLIwwJpQhTw0A6iWxmKxqNO0d+ZkI4nJ
         p4LBqLgps5XxCtmxU7KcT2yJRoC64shzo3EgFKPw8+g4dp/xQbw2IxIqNZJNrVcOOqp1
         ejRMPQNTF/HEFQ78T7ma3ft1Gz00b6YoVaKOYviVxP/Yowc7XI7dGwgnGqlKzYcjR1BC
         FPKw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PzCt7v1s;
       spf=pass (google.com: domain of 3kb7_xwokcwcfsiwjdpsaqlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3KB7_XwoKCWcFSIWJdPSaQLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id n18si140985qkk.7.2021.01.13.08.22.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Jan 2021 08:22:00 -0800 (PST)
Received-SPF: pass (google.com: domain of 3kb7_xwokcwcfsiwjdpsaqlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id g9so1719274qtv.12
        for <kasan-dev@googlegroups.com>; Wed, 13 Jan 2021 08:22:00 -0800 (PST)
Sender: "andreyknvl via sendgmr" <andreyknvl@andreyknvl3.muc.corp.google.com>
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:7220:84ff:fe09:7e9d])
 (user=andreyknvl job=sendgmr) by 2002:ad4:5a50:: with SMTP id
 ej16mr2923422qvb.25.1610554920477; Wed, 13 Jan 2021 08:22:00 -0800 (PST)
Date: Wed, 13 Jan 2021 17:21:33 +0100
In-Reply-To: <cover.1610554432.git.andreyknvl@google.com>
Message-Id: <6e23eb9542693bf5e9c5b1f841901d17427e513b.1610554432.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <cover.1610554432.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.30.0.284.gd98b1dd5eaa7-goog
Subject: [PATCH v2 06/14] kasan, arm64: allow using KUnit tests with HW_TAGS mode
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
 header.i=@google.com header.s=20161025 header.b=PzCt7v1s;       spf=pass
 (google.com: domain of 3kb7_xwokcwcfsiwjdpsaqlttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--andreyknvl.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3KB7_XwoKCWcFSIWJdPSaQLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--andreyknvl.bounces.google.com;
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
index f5470bed50b6..5c8aa3a5ce93 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/6e23eb9542693bf5e9c5b1f841901d17427e513b.1610554432.git.andreyknvl%40google.com.

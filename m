Return-Path: <kasan-dev+bncBC6OLHHDVUOBBHHD5H2AKGQEJSUWDTY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id 12B931AE98A
	for <lists+kasan-dev@lfdr.de>; Sat, 18 Apr 2020 05:18:54 +0200 (CEST)
Received: by mail-qt1-x83a.google.com with SMTP id z8sf4393978qtu.17
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Apr 2020 20:18:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1587179932; cv=pass;
        d=google.com; s=arc-20160816;
        b=N9tKcjoTQ/O1WFFG+yTS8izA4SfCzRK+7DQblfe5UFnvNzOaAGKQSL7QEl8YWRyuI5
         ysw826FdzoR/phiVkaivFk0AENoKV97nUVLz4DqciGMp8b1XoQy3XCptss0gkRHNOixg
         NWwSOoUeCxSxn3gPpsjEGZFj1y8fVveAx3Hj7PXUFxMQSNINZxcM4ipoUdh/ooZbin78
         63KoXZ3+y51GpIhWo1ugAjI44y62gF6CsYdU0uK5Qb9PRWdKpjbWpKd+jMWfqjPC67sR
         1ii7D45kq2gajdxW8+bXhKKjU7VjZ9FW+FYdpNx1IKJfzGUwACWtJoYBnzjDYjAFMnd2
         sYrw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=qR2REJmveJ9LL2oqYBygRQIJgXd1gnoEKaszojvATuA=;
        b=FiZUcvdr0pmBGVno4ZiZ0MoTKUslEESVEIo+GINXGMsFHEcL2uGLoF1zt0n+OcXQ8K
         x/JjXaPvhs0/3W/D+R3ofRPtNxYD+JIotnG6dx+6tYgSYdvD3ibk1ui3jGlaJQEJ5W11
         znD4ydS15vC3zokdfQ008H9HdD6djTz7frPbXL6Yg5uHfgmd5zKh9D4fnpOInh2CRb+P
         BTaCNCdrrgzgDB+yk9tRV37oDp9HrrPy7buui2Dv7MWuRSKS5UKJDvxA8itjLwF8LQFt
         xQwIzpv1KwFmJcRluXXTtxqsvBSosEhRaJAO5eEc4WrLbG+BcIMzsyfIuvw4FgDl955Z
         ExBg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LiW2hxPr;
       spf=pass (google.com: domain of 3m3gaxggkceihezmhksaksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::549 as permitted sender) smtp.mailfrom=3m3GaXggKCeIHEZMHKSaKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qR2REJmveJ9LL2oqYBygRQIJgXd1gnoEKaszojvATuA=;
        b=JFSueAKSvy/kr9sEzQ56Jh7w4VhKYZ7bSr+mEW4SVgHojLcBw7DfpV2Qfj88YNL/PU
         KaBQYrWBoaTVA+DRHie0rScbvoe3NJ/t44tE5K/ZvlzPKxnQX1RA4ULa68fYPe+eQ0zS
         ZHiKXayZaa90auUuqS9+ieDdMkbjCdnAkr7kS/0zKsc2fqJDFZ8Xy6Zu+OIuroEHEyj9
         9NP4y3YzrC2OEXjCJlCLFAixWe79wUQe3gTBCrg74IN/yh+AWtahugoSJ2xifZNDiMnP
         IETcESowgNs7q3PYN0fCsTYhamCnRk0Uqn+ebebR93lEZEbKHFRy7Z0oIrOxmt3H2FB3
         GC1w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qR2REJmveJ9LL2oqYBygRQIJgXd1gnoEKaszojvATuA=;
        b=jFlKvD8Gi301xXlsCaSssvDAnyuyYU99t/EG0q1B1J+M84pAEtMhOt4LIcyPKXkSl4
         XmwGC5HXS+OW5F0sHUOrrBGkP/dpJ8c8bVpsCznS+l19wMKHA5przgDYnbYS5GJUa1ev
         qfBSHVMj5KygbYXVHqx9ke8V7oSGUVbXw7z/13zfJgbIBX1xrICKFGPUbCOssrIDabVX
         Ldic58Dztp+pZemFsMsFFec9I+/xQoNYBJirvHXlARQBrjMRRRJYsM/6zAmCqbPKqL5i
         LWV05x2cRfadSQYcldcoq77hXafnI1ZjW31FaCZgK1TjZDnJWTMBRQkcOLfAIQ6U4X6q
         lHCQ==
X-Gm-Message-State: AGi0Pua1YlscX/nAt27msePOXWyQKKbz4kFgcQhYVceMhfm/T/FoHKMB
	2X28bwKTT0Sr1IwbuqerbiA=
X-Google-Smtp-Source: APiQypIRJrCOrB0EV9uIlr/1xp9ArgQN9dqVZiB00lBCj/anqsM+4DI/3xvEoH08p+Nbe5Tuqpnviw==
X-Received: by 2002:a37:a8c7:: with SMTP id r190mr6624845qke.65.1587179932704;
        Fri, 17 Apr 2020 20:18:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:528b:: with SMTP id v11ls1365125qvr.9.gmail; Fri, 17 Apr
 2020 20:18:52 -0700 (PDT)
X-Received: by 2002:a05:6214:227:: with SMTP id j7mr5838916qvt.85.1587179932284;
        Fri, 17 Apr 2020 20:18:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1587179932; cv=none;
        d=google.com; s=arc-20160816;
        b=o+yIAPA5DaYpRhBj3PAuKXy+OtFU5yAADUWN7/Mowt/Um/TFyGSqX8VYFsmHSb/GD8
         twEhm4yVKawehBCbh9/7vsrwU11MIIw38pP6FhGeXzqD8IHjPcktItDiCUWHKYDRb1fF
         9jA1AL8sv1VtMhZgppzU5D1ejBID0ORBWiW1pys2nYpUcn8BhX1vkuUiS6Qb/pBtV5r7
         fzAFXOicEK8kc3VRo1enSpvPrCGZFVYRI8Ka1TIvsv8I8pkgZliucMfM6Ak6eJJKhDcu
         ew2h87Od2Ic8O3IRSl/bAyp3kwcO4Wc20ha3ug7bYRgR3XyqxSlf8y8nVMUXp61vmbdR
         Ejvw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=YYm2bwRG5pyX36H9W2qzKGsVlXXcAWI4Cgt0/J71ouQ=;
        b=vSBd2AJ548a5Ji/YpUqo7rYIricB2bUR14R51e2joUHyWqEt62iDzcGXB80Y+d68x5
         ngulVeTaJ/1ypQ2EqdcKKTlRmHoruolVMv+h9IOwm/u5RaRZmgNeupp+yg/2pDRWAo/5
         x1Jjasv+XDuv+XXNZqtnP+GjjH07VFS3lZyG2g0A1Z7VaZs75eSlmL6MO4dA28bUELVt
         dVXUVDzo6eCYtz2H5sxaIo7mbqxeWnyz0LrtezRJh9hykRW3H8Z/c8Q5L37Dzw8MHI3V
         f3HNmHupVzKk/9N/vk8oiwukdJgrJqtd4fUom5YK+4a+X018jugPKEY2q1Pb9gOKexzd
         d8UA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LiW2hxPr;
       spf=pass (google.com: domain of 3m3gaxggkceihezmhksaksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::549 as permitted sender) smtp.mailfrom=3m3GaXggKCeIHEZMHKSaKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x549.google.com (mail-pg1-x549.google.com. [2607:f8b0:4864:20::549])
        by gmr-mx.google.com with ESMTPS id g25si240202qto.2.2020.04.17.20.18.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 17 Apr 2020 20:18:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3m3gaxggkceihezmhksaksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::549 as permitted sender) client-ip=2607:f8b0:4864:20::549;
Received: by mail-pg1-x549.google.com with SMTP id m25so3560933pgl.8
        for <kasan-dev@googlegroups.com>; Fri, 17 Apr 2020 20:18:52 -0700 (PDT)
X-Received: by 2002:a17:90a:348f:: with SMTP id p15mr8245808pjb.115.1587179931314;
 Fri, 17 Apr 2020 20:18:51 -0700 (PDT)
Date: Fri, 17 Apr 2020 20:18:30 -0700
In-Reply-To: <20200418031833.234942-1-davidgow@google.com>
Message-Id: <20200418031833.234942-3-davidgow@google.com>
Mime-Version: 1.0
References: <20200418031833.234942-1-davidgow@google.com>
X-Mailer: git-send-email 2.26.1.301.g55bc3eb7cb9-goog
Subject: [PATCH v6 2/5] KUnit: KASAN Integration
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
To: trishalfonso@google.com, brendanhiggins@google.com, 
	aryabinin@virtuozzo.com, dvyukov@google.com, mingo@redhat.com, 
	peterz@infradead.org, juri.lelli@redhat.com, vincent.guittot@linaro.org
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	kunit-dev@googlegroups.com, linux-kselftest@vger.kernel.org, 
	David Gow <davidgow@google.com>, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=LiW2hxPr;       spf=pass
 (google.com: domain of 3m3gaxggkceihezmhksaksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::549 as permitted sender) smtp.mailfrom=3m3GaXggKCeIHEZMHKSaKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: David Gow <davidgow@google.com>
Reply-To: David Gow <davidgow@google.com>
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

From: Patricia Alfonso <trishalfonso@google.com>

Integrate KASAN into KUnit testing framework.
        - Fail tests when KASAN reports an error that is not expected
        - Use KUNIT_EXPECT_KASAN_FAIL to expect a KASAN error in KASAN
	tests
        - Expected KASAN reports pass tests and are still printed when run
        without kunit_tool (kunit_tool still bypasses the report due to the
        test passing)
	- KUnit struct in current task used to keep track of the current
	test from KASAN code

Make use of "[PATCH v3 kunit-next 1/2] kunit: generalize
kunit_resource API beyond allocated resources" and "[PATCH v3
kunit-next 2/2] kunit: add support for named resources" from Alan
Maguire [1]
        - A named resource is added to a test when a KASAN report is
         expected
        - This resource contains a struct for kasan_data containing
        booleans representing if a KASAN report is expected and if a
        KASAN report is found

[1] (https://lore.kernel.org/linux-kselftest/1583251361-12748-1-git-send-email-alan.maguire@oracle.com/T/#t)

Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
Signed-off-by: David Gow <davidgow@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Reviewed-by: Andrey Konovalov <andreyknvl@google.com>
---
 include/kunit/test.h  |  5 +++++
 include/linux/kasan.h |  6 ++++++
 lib/kunit/test.c      | 13 ++++++++-----
 lib/test_kasan.c      | 43 ++++++++++++++++++++++++++++++++++++++++---
 mm/kasan/report.c     | 35 +++++++++++++++++++++++++++++++++++
 5 files changed, 94 insertions(+), 8 deletions(-)

diff --git a/include/kunit/test.h b/include/kunit/test.h
index ac59d18e6bab..1dc3d118f64b 100644
--- a/include/kunit/test.h
+++ b/include/kunit/test.h
@@ -225,6 +225,11 @@ struct kunit {
 	struct list_head resources; /* Protected by lock. */
 };
 
+static inline void kunit_set_failure(struct kunit *test)
+{
+	WRITE_ONCE(test->success, false);
+}
+
 void kunit_init_test(struct kunit *test, const char *name, char *log);
 
 int kunit_run_tests(struct kunit_suite *suite);
diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index 31314ca7c635..d58db2f67f43 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -14,6 +14,12 @@ struct task_struct;
 #include <asm/kasan.h>
 #include <asm/pgtable.h>
 
+/* kasan_data struct is used in KUnit tests for KASAN expected failures */
+struct kunit_kasan_expectation {
+	bool report_expected;
+	bool report_found;
+};
+
 extern unsigned char kasan_early_shadow_page[PAGE_SIZE];
 extern pte_t kasan_early_shadow_pte[PTRS_PER_PTE];
 extern pmd_t kasan_early_shadow_pmd[PTRS_PER_PMD];
diff --git a/lib/kunit/test.c b/lib/kunit/test.c
index 2cb7c6220a00..030a3281591e 100644
--- a/lib/kunit/test.c
+++ b/lib/kunit/test.c
@@ -10,16 +10,12 @@
 #include <linux/kernel.h>
 #include <linux/kref.h>
 #include <linux/sched/debug.h>
+#include <linux/sched.h>
 
 #include "debugfs.h"
 #include "string-stream.h"
 #include "try-catch-impl.h"
 
-static void kunit_set_failure(struct kunit *test)
-{
-	WRITE_ONCE(test->success, false);
-}
-
 static void kunit_print_tap_version(void)
 {
 	static bool kunit_has_printed_tap_version;
@@ -288,6 +284,10 @@ static void kunit_try_run_case(void *data)
 	struct kunit_suite *suite = ctx->suite;
 	struct kunit_case *test_case = ctx->test_case;
 
+#if (IS_ENABLED(CONFIG_KASAN) && IS_ENABLED(CONFIG_KUNIT))
+	current->kunit_test = test;
+#endif /* IS_ENABLED(CONFIG_KASAN) && IS_ENABLED(CONFIG_KUNIT) */
+
 	/*
 	 * kunit_run_case_internal may encounter a fatal error; if it does,
 	 * abort will be called, this thread will exit, and finally the parent
@@ -603,6 +603,9 @@ void kunit_cleanup(struct kunit *test)
 		spin_unlock(&test->lock);
 		kunit_remove_resource(test, res);
 	}
+#if (IS_ENABLED(CONFIG_KASAN) && IS_ENABLED(CONFIG_KUNIT))
+	current->kunit_test = NULL;
+#endif /* IS_ENABLED(CONFIG_KASAN) && IS_ENABLED(CONFIG_KUNIT)*/
 }
 EXPORT_SYMBOL_GPL(kunit_cleanup);
 
diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index e3087d90e00d..a44d3f8a499c 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -23,10 +23,47 @@
 
 #include <asm/page.h>
 
-/*
- * Note: test functions are marked noinline so that their names appear in
- * reports.
+#include <kunit/test.h>
+
+static struct kunit_resource resource;
+static struct kunit_kasan_expectation fail_data;
+static bool multishot;
+
+static int kasan_test_init(struct kunit *test)
+{
+	/*
+	 * Temporarily enable multi-shot mode and set panic_on_warn=0.
+	 * Otherwise, we'd only get a report for the first case.
+	 */
+	multishot = kasan_save_enable_multi_shot();
+
+	return 0;
+}
+
+static void kasan_test_exit(struct kunit *test)
+{
+	kasan_restore_multi_shot(multishot);
+}
+
+/**
+ * KUNIT_EXPECT_KASAN_FAIL() - Causes a test failure when the expression does
+ * not cause a KASAN error. This uses a KUnit resource named "kasan_data." Do
+ * Do not use this name for a KUnit resource outside here.
+ *
  */
+#define KUNIT_EXPECT_KASAN_FAIL(test, condition) do { \
+	fail_data.report_expected = true; \
+	fail_data.report_found = false; \
+	kunit_add_named_resource(test, \
+				NULL, \
+				NULL, \
+				&resource, \
+				"kasan_data", &fail_data); \
+	condition; \
+	KUNIT_EXPECT_EQ(test, \
+			fail_data.report_expected, \
+			fail_data.report_found); \
+} while (0)
 
 static noinline void __init kmalloc_oob_right(void)
 {
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 80f23c9da6b0..0c206bbf9cb3 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -32,6 +32,8 @@
 
 #include <asm/sections.h>
 
+#include <kunit/test.h>
+
 #include "kasan.h"
 #include "../slab.h"
 
@@ -463,12 +465,37 @@ bool report_enabled(void)
 	return !test_and_set_bit(KASAN_BIT_REPORTED, &kasan_flags);
 }
 
+#if IS_ENABLED(CONFIG_KUNIT)
+static void kasan_update_kunit_status(struct kunit *cur_test)
+{
+	struct kunit_resource *resource;
+	struct kunit_kasan_expectation *kasan_data;
+
+	resource = kunit_find_named_resource(cur_test, "kasan_data");
+
+	if (!resource) {
+		kunit_set_failure(cur_test);
+		return;
+	}
+
+	kasan_data = (struct kunit_kasan_expectation *)resource->data;
+	kasan_data->report_found = true;
+	kunit_put_resource(resource);
+}
+#endif /* IS_ENABLED(CONFIG_KUNIT) */
+
 void kasan_report_invalid_free(void *object, unsigned long ip)
 {
 	unsigned long flags;
 	u8 tag = get_tag(object);
 
 	object = reset_tag(object);
+
+#if IS_ENABLED(CONFIG_KUNIT)
+	if (current->kunit_test)
+		kasan_update_kunit_status(current->kunit_test);
+#endif /* IS_ENABLED(CONFIG_KUNIT) */
+
 	start_report(&flags);
 	pr_err("BUG: KASAN: double-free or invalid-free in %pS\n", (void *)ip);
 	print_tags(tag, object);
@@ -486,6 +513,14 @@ void __kasan_report(unsigned long addr, size_t size, bool is_write, unsigned lon
 	void *untagged_addr;
 	unsigned long flags;
 
+	if (likely(!report_enabled()))
+		return;
+
+#if IS_ENABLED(CONFIG_KUNIT)
+	if (current->kunit_test)
+		kasan_update_kunit_status(current->kunit_test);
+#endif /* IS_ENABLED(CONFIG_KUNIT) */
+
 	disable_trace_on_warning();
 
 	tagged_addr = (void *)addr;
-- 
2.26.1.301.g55bc3eb7cb9-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200418031833.234942-3-davidgow%40google.com.

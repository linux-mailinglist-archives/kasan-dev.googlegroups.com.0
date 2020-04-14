Return-Path: <kasan-dev+bncBC6OLHHDVUOBBVWW2T2AKGQE2VBLNWQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53e.google.com (mail-pg1-x53e.google.com [IPv6:2607:f8b0:4864:20::53e])
	by mail.lfdr.de (Postfix) with ESMTPS id 4E1B61A7197
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Apr 2020 05:17:44 +0200 (CEST)
Received: by mail-pg1-x53e.google.com with SMTP id v29sf10356168pgo.12
        for <lists+kasan-dev@lfdr.de>; Mon, 13 Apr 2020 20:17:44 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1586834263; cv=pass;
        d=google.com; s=arc-20160816;
        b=zfXDaVqET1Hp3JgJkzQuSFP/rVYii+cayo89dL1NZ8q7hmnmebg2BrWlDlXCJKt94I
         BhxSfFZdoNDALAmXPM5c/UAEQOj1WVibmgmkphXT5CZcmUC14sZ2uEjzvIElSQudo79d
         fM3JjqRIhxbn+8qna2HZrr7lfPenmazDzJcL313vFreZsIENikJHYLW0Eezqelfd/Mnm
         AYDYbd3/aRNXNky4zlv6fY8SKt0hm0YYeTO9rpHFr0Mam6udoiY5Rit85NU4bm+ZZwKj
         eQMhkGEn79CkqhZ7vqkuWRaEeO57A+uX+0acD3/WVojizX8MmHtROCSTbHUSZjvPXvdy
         DIuQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=3Z3bt1sMUxjhd5wAux73mw5Mo13qD+SkSQqnD4ev35w=;
        b=xqlWoxXSw8Y9TZB0NW6oO0tDO4MmAq3K8cOHV9ORlYgPVao2BXWVTYSKSZAEEdNBd4
         govK+enSI4aj+VwAkkla+WJhCW8I+g97RtFVQKSfePK1FoFvTW32O5620VUJsVb380uz
         kZ3xX25OQNkHj7pv+wPplkV1mfk1jDXIbYqMfHimUkHCtNzutQYc4bat8pSLMjxjqEds
         7ZDTDGEd7Aclbm6tumnARPkB48JyHvYmn3WgwOUJgozpR1/mpljnzLiF0TJmdEykGl0W
         9IRELgLe8h0ZVRqj64UbzRGeXchRJYWB+jzeA/XxhcCZva0Asuc7PC0R0L+kxpZLXCmI
         0yXA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="HdmRF/e0";
       spf=pass (google.com: domain of 3vsuvxggkcfofcxkfiqyiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3VSuVXggKCfofcxkfiqyiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3Z3bt1sMUxjhd5wAux73mw5Mo13qD+SkSQqnD4ev35w=;
        b=XYGXYjl4wejn5/5BYdTXqpdf2RB/N+2VfsjS/oAiZEqTsBMSfw8Tqtq3tp8dCZwoBb
         BnDK1rpYYxz7ezvIWt3is0y52NZzez1R68mkk9IfLbVphhFz7aSTJmAm4oHcYfTx671K
         SOzpQg/apgXgXXKUUG4hMnTrDoZtJcaopL0GMsLA8WINbmqYuDkEAFX7wDmRxS1VZyKz
         lxmLLP63VZmcM77FGFRbiuKS3WhxTseLNfa2qSDmqAWWXgF0jPi9xXlsvPJMftrsajBA
         w86dHVevIaP3d6exIRb/rLaOEwrvEYJyUY2bEllyWhowyvOj87ZdJr0ve0tV0TuB0dXB
         4BOQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=3Z3bt1sMUxjhd5wAux73mw5Mo13qD+SkSQqnD4ev35w=;
        b=tsyzbnXt2jbGFYusDrxFmwzxTvHrvKci2LfM2fys0cbuF1w+o5N/iQOjV2KhtKbhGG
         LaW4z4Ai1Wd8AwYyEWThFIjWWh9TILSjDdYDZoINwMz7BrcMtBaV9EAIHKuv+KJFLKJf
         judZhPzUcEyxED9hlr7lmV8P0VEjysUdm/loM64hMlzSJi2DflZ71NkX1INS55tbFo1R
         mtx9XjAZ3SAk0TLHV5c91Xqltb3fzrLe3flZjgMy5or3ss4GbvWSZfWUFv+mmVHjVSua
         RSfybA1VNmmLr67j30xoHDNtc5ijeROLBT3CvTnBzjcSUtaYhmj3eiP4QXIhaeU9cf1T
         Hszg==
X-Gm-Message-State: AGi0PuYpJ+6ohEnsjfbPah8SFogFHpHv2aB7nXFEVhZ66lhrW6Y8Fh4c
	WPZmtc2lI/VdN5tToPd/nXg=
X-Google-Smtp-Source: APiQypLfpaqllYoYh65wKvHu7XWPxUmERIUUSnmCnxNhnxsBPhZMr+Nobr/3d4BAxRgGLD0QYzs0Uw==
X-Received: by 2002:a63:cc:: with SMTP id 195mr11141891pga.373.1586834262844;
        Mon, 13 Apr 2020 20:17:42 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:8488:: with SMTP id c8ls2783978plo.8.gmail; Mon, 13
 Apr 2020 20:17:42 -0700 (PDT)
X-Received: by 2002:a17:90a:3fcf:: with SMTP id u15mr11351236pjm.70.1586834262315;
        Mon, 13 Apr 2020 20:17:42 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1586834262; cv=none;
        d=google.com; s=arc-20160816;
        b=dRK3kMORxmuSHjb50tfoM8Z8PP68keP1ZBa1xSi+nrVGj3a4Z1+pphpRJ/OuhwmkQR
         m7tWtxz636KDQ+2LhSXb4X87OzPs63L8mw1VQTJBuaYdNduqFbPw9uoun3dv1tJ+Jb8W
         Hu8v4DtigGPqfiiykuXle4yp+tiEmx9SttI7cv58GFuQoXXTHO0K6ziLZDPY+xwRKZlM
         LP4XCl3n55hUm4Wsa6L/KxF4HArkjW9yz8CfTgfecMWYAdLRsdbqaqOYXbO1buPVXQ4d
         5IQz6OfY7mVaMawAJ7xeGhfktIM/0z5EXeri8pZ5fAdOUQaaVE5j52b+xp6dUe+7VL7Q
         +SIA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=s5/bs+yC8axu1LpyzHbXKS3+loSdJl1/+btbiFoLEQc=;
        b=f+OgS7DD+kewUzQNuJernnG9yB2WVw2q+jbr4CNmJHTaZwb1wcK3TPPDCGBg/tRSIs
         BJmgNtxnLo1uWso8FQo8S/AqmSxYo3gCd7SOFAfPJ6oDi5KZhnKohSqJjPpRrh/0aZIg
         1J4YOsQABopW6t3cz8sRlEaPW3BY2SzRfCq55Ct+wLDaaZiNiegfMLwjoNfBaJY6rqAv
         7ndOyw7SWmZPiLN1ukrn8OyzfF4DyjFaqqqjPcelEcnGO4okuoRdOzRrROZ2QU5gX+TW
         kzsnlwva4oRPM/B8FrhyYcwzds09DFpZnSwYz3dvbhLFsWwA1V47Zj5k7FebXKwQIvGK
         6CQw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="HdmRF/e0";
       spf=pass (google.com: domain of 3vsuvxggkcfofcxkfiqyiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3VSuVXggKCfofcxkfiqyiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id z185si697843pgd.4.2020.04.13.20.17.42
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 13 Apr 2020 20:17:42 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3vsuvxggkcfofcxkfiqyiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id 5so14171665yba.23
        for <kasan-dev@googlegroups.com>; Mon, 13 Apr 2020 20:17:42 -0700 (PDT)
X-Received: by 2002:a25:844f:: with SMTP id r15mr31017182ybm.380.1586834261327;
 Mon, 13 Apr 2020 20:17:41 -0700 (PDT)
Date: Mon, 13 Apr 2020 20:16:46 -0700
In-Reply-To: <20200414031647.124664-1-davidgow@google.com>
Message-Id: <20200414031647.124664-3-davidgow@google.com>
Mime-Version: 1.0
References: <20200414031647.124664-1-davidgow@google.com>
X-Mailer: git-send-email 2.26.0.110.g2183baf09c-goog
Subject: [PATCH v5 2/4] KUnit: KASAN Integration
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
To: trishalfonso@google.com, brendanhiggins@google.com, 
	aryabinin@virtuozzo.com, dvyukov@google.com, mingo@redhat.com, 
	peterz@infradead.org, juri.lelli@redhat.com, vincent.guittot@linaro.org
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	kunit-dev@googlegroups.com, linux-kselftest@vger.kernel.org, 
	David Gow <davidgow@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="HdmRF/e0";       spf=pass
 (google.com: domain of 3vsuvxggkcfofcxkfiqyiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3VSuVXggKCfofcxkfiqyiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--davidgow.bounces.google.com;
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
	- Also make KASAN no-longer panic when panic_on_warn and
	kasan_multi_shot are enabled (as multi-shot does nothing
	otherwise)

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
---
 include/kunit/test.h  |  5 +++++
 include/linux/kasan.h |  6 ++++++
 lib/kunit/test.c      | 13 ++++++++-----
 lib/test_kasan.c      | 44 +++++++++++++++++++++++++++++++++++++++----
 mm/kasan/report.c     | 34 ++++++++++++++++++++++++++++++++-
 5 files changed, 92 insertions(+), 10 deletions(-)

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
index 5cde9e7c2664..148eaef3e003 100644
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
index 3872d250ed2c..7b4cb107b387 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -23,12 +23,48 @@
 
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
 
-static noinline void __init kmalloc_oob_right(void)
 {
 	char *ptr;
 	size_t size = 123;
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 5ef9f24f566b..a58a9f3b7f2c 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -32,6 +32,8 @@
 
 #include <asm/sections.h>
 
+#include <kunit/test.h>
+
 #include "kasan.h"
 #include "../slab.h"
 
@@ -92,7 +94,7 @@ static void end_report(unsigned long *flags)
 	pr_err("==================================================================\n");
 	add_taint(TAINT_BAD_PAGE, LOCKDEP_NOW_UNRELIABLE);
 	spin_unlock_irqrestore(&report_lock, *flags);
-	if (panic_on_warn)
+	if (panic_on_warn && !test_bit(KASAN_BIT_MULTI_SHOT, &kasan_flags))
 		panic("panic_on_warn set ...\n");
 	kasan_enable_current();
 }
@@ -455,12 +457,37 @@ static bool report_enabled(void)
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
@@ -481,6 +508,11 @@ void __kasan_report(unsigned long addr, size_t size, bool is_write, unsigned lon
 	if (likely(!report_enabled()))
 		return;
 
+#if IS_ENABLED(CONFIG_KUNIT)
+	if (current->kunit_test)
+		kasan_update_kunit_status(current->kunit_test);
+#endif /* IS_ENABLED(CONFIG_KUNIT) */
+
 	disable_trace_on_warning();
 
 	tagged_addr = (void *)addr;
-- 
2.26.0.110.g2183baf09c-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200414031647.124664-3-davidgow%40google.com.

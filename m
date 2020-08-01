Return-Path: <kasan-dev+bncBC6OLHHDVUOBBT5KST4QKGQEYVIMDUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1037.google.com (mail-pj1-x1037.google.com [IPv6:2607:f8b0:4864:20::1037])
	by mail.lfdr.de (Postfix) with ESMTPS id 98CB42350EA
	for <lists+kasan-dev@lfdr.de>; Sat,  1 Aug 2020 09:10:08 +0200 (CEST)
Received: by mail-pj1-x1037.google.com with SMTP id s4sf12058948pjq.8
        for <lists+kasan-dev@lfdr.de>; Sat, 01 Aug 2020 00:10:08 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596265807; cv=pass;
        d=google.com; s=arc-20160816;
        b=w4iCJQYUctEhPagn+eETsrLfvOAdp2luK0f0CX1wHzWIR43xqvFrCP1Sqf8YlFGaiO
         lg9wmHZRZRNhqmV8RQc47MrdTNMc9cC+hl36QaFCQZLGTbJvQF1v/agQIVbRhxFuh6Hj
         4OWx8aIsIhmSUEARXiBsZpVrJ1LMHMhCWzW66j+fisRe4Bj7J3diyXHAIPYPfl6uVf2D
         Rm1yp4FN59IFxdWNoW8ajYSib/u2GpBhKPmNYuIr8zAZ82BeIltJmKC9Gp5FWwkWolwS
         KnxpFspvGYI68kHZ6V4UgDIYWWSriF22EPLsYaGmcGummGuxpPYBF2hk5dtKjcKBzigO
         RyJQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=Y0fltAq2VMv5+lqYW1asA8ECGO1oorw3k9j94CM5fNg=;
        b=OC2Ole6EB2V7gUKvvWvzgzMZR00D7LFgSzaTVT3yAL/eGAEiGdXUS4C4xfnwNrvzom
         mkpai+Ipy7P7gfpj8dhiOBeHWvoWBuUauIepxMVvnl0zoVtsq9r1s5oz7/Zy/DY88tWM
         rdHf3woNav9nsTtSziJFIb1SR3Cn2nCt0SX+GeTdZycQ6fzsWIEWUOUSErHhqWgxfQgK
         8qqI27vNrZh9ID1NziKRndQCO1vV1Ii1o2cO3MUyU/DiQ5hwTuoVhzTHS1nQ8c+9Pm+T
         KU8iDZCN+myKx1Tk/MlXOeEVQog+VQ5Zsv4SaRHaTOS52BM6Mvx/dB3KgcxhNx+ymEqG
         qEyw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pxmI23j4;
       spf=pass (google.com: domain of 3thulxwgkcq0qn8vqt19t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::649 as permitted sender) smtp.mailfrom=3ThUlXwgKCQ0qn8vqt19t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Y0fltAq2VMv5+lqYW1asA8ECGO1oorw3k9j94CM5fNg=;
        b=mKRZws1qAhO81W/qnDSNBnDH4JYBsMKML5HobFCEa5JM2tJ4XxJLN0kmL7k82s3ius
         zPPE/Fd3Snt+AgytwD70XGamlrfkwl9LVqUTbV1wwqu7h2q0Q1TfwFzM021HJmZg/FrM
         xVmrbecxi9UohrQ5snMmyF7Be3S8cktOkUXIfD3re9dtCIQG9dn4uUyvnUyLD4GULDTC
         Sz5tGODzDNYENmsSjTbPEMlIHk39GGYBX5Rqt4+V3ErW8yoVhgwpRTcPWzTUEYD79bis
         qJwlp6duEbZa6WPZUWOYEsVsALo/tD/KBmIWw/ZjkMnMe2s+CORWjkuD4Bjoixb04LZh
         XzDA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Y0fltAq2VMv5+lqYW1asA8ECGO1oorw3k9j94CM5fNg=;
        b=If9obff93N7biaNU/Ar625YuzK1ANM+67qQGrPIZMMcFWHBqSoRUIpaR8ojvfl3ygT
         NtmnfI9bHnuidNxe59BdcXrewLrjJDjt9eYfqRzoobdaIkgiXitoYFpfo1SDqnS5Tgrt
         JdU4lkzIG+sPGopPuVQ5gDWUJOjVROfqR0upMbc9naXSTOQ1qf3mJDfxY7ZNwGf9+YoW
         4zyfH51t425MQoMpsEU2maMtm5JX9fZqEOW60sU18lKrvyO9vu3q8u2TiOyfW9kw98HN
         /Zt/0swpN7P/pue+ut46Ze+lkg7Ehj7neOb7gg5bjVV/oRraFqlqPY3yhvIyvqM+aADg
         1RNA==
X-Gm-Message-State: AOAM5302FLwOKfRfFADnU1qQwNLp2h3PX2bPLT4NFpr6+a/AoM3Tr0sp
	4028s5S8yEd1WXvVTsNEloA=
X-Google-Smtp-Source: ABdhPJyJV5CSbfsN7k8e6Q4ZoffNROl6oSb65jWi0WyZk76+aTunX5XZHnBnMsMJIlyjbgJxfEKh/A==
X-Received: by 2002:a05:6a00:22cc:: with SMTP id f12mr6557793pfj.172.1596265807329;
        Sat, 01 Aug 2020 00:10:07 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:ab10:: with SMTP id p16ls3742371pff.3.gmail; Sat, 01 Aug
 2020 00:10:06 -0700 (PDT)
X-Received: by 2002:a65:63ca:: with SMTP id n10mr7066579pgv.252.1596265806878;
        Sat, 01 Aug 2020 00:10:06 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596265806; cv=none;
        d=google.com; s=arc-20160816;
        b=DM74jlWP+m+NqwyWegB7R4U28DFd9h/K7XLCHM1BfIlpbSNiwUvjyQanFinadRf+cr
         0fJ/x/2G/xWmyZ8sMcK5RyDEr1+YANHC7cQTq2shp+Cm7pXohfSVKNdNgmi5sVcEkyHW
         4KjgYUpww8kVB6JZISzOmtV1CEAz8Hl/jkesHL3YuIq1Jf1U4GDa4deEfdXVfDL/3hlW
         r9pXhvFXGcL4OM2IOw2We9sR8AG4qG5Cvs8ofcjG+Ttzn2IHegCpY/JGYUIIotaiw5Sv
         w7SuDXaxi2k8TO5blRG1zRvNxF1dsMfSR0R8cs7bmzmy2uHiu4hiYtUSpqs2SLfGBuU/
         Mrpg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=J3RmpWXwZ/1d89ythMYIXtVZiV0eTdWaBFiczRT37Ws=;
        b=z3d2lyPbz9gLmVNg2xbJQSpY5sBBGKj7S8kUri+CcrNEK4aSBxKKbCkQbiugcCBnl7
         AWuzniutJvAU1pybCZkF4zqAPhqMxHhUIVVMOXolU0uRjC81WJB/VpMN+HrU+TPGWerJ
         CgJ8W8msrqsDhVQu1ZK56VQJZFNZT3JuuBcY4XD0iIMMW/rRXFBldJElTQqgbAcLEzCX
         6f8/BCFta/W72s8zYbatEzNjPierefiIwN1xklN3E1aL1u1weXH27wdc+Q28DpF5eNZh
         vqP3FXKLTNfnU3xY95HK1g1yVxNi9+dqwgMfNPU2sFy0PaPZ1a/wgCrbFWaZ1lcarPiG
         uPYQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pxmI23j4;
       spf=pass (google.com: domain of 3thulxwgkcq0qn8vqt19t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::649 as permitted sender) smtp.mailfrom=3ThUlXwgKCQ0qn8vqt19t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x649.google.com (mail-pl1-x649.google.com. [2607:f8b0:4864:20::649])
        by gmr-mx.google.com with ESMTPS id o6si50002pfu.3.2020.08.01.00.10.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 01 Aug 2020 00:10:06 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3thulxwgkcq0qn8vqt19t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::649 as permitted sender) client-ip=2607:f8b0:4864:20::649;
Received: by mail-pl1-x649.google.com with SMTP id s2so23844451plr.22
        for <kasan-dev@googlegroups.com>; Sat, 01 Aug 2020 00:10:06 -0700 (PDT)
X-Received: by 2002:a17:90a:ce0c:: with SMTP id f12mr7012478pju.44.1596265806531;
 Sat, 01 Aug 2020 00:10:06 -0700 (PDT)
Date: Sat,  1 Aug 2020 00:09:21 -0700
In-Reply-To: <20200801070924.1786166-1-davidgow@google.com>
Message-Id: <20200801070924.1786166-3-davidgow@google.com>
Mime-Version: 1.0
References: <20200801070924.1786166-1-davidgow@google.com>
X-Mailer: git-send-email 2.28.0.163.g6104cc2f0b6-goog
Subject: [PATCH v10 2/5] KUnit: KASAN Integration
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
To: trishalfonso@google.com, brendanhiggins@google.com, 
	aryabinin@virtuozzo.com, dvyukov@google.com, mingo@redhat.com, 
	peterz@infradead.org, juri.lelli@redhat.com, vincent.guittot@linaro.org, 
	andreyknvl@google.com, shuah@kernel.org
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	kunit-dev@googlegroups.com, linux-kselftest@vger.kernel.org, 
	David Gow <davidgow@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=pxmI23j4;       spf=pass
 (google.com: domain of 3thulxwgkcq0qn8vqt19t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::649 as permitted sender) smtp.mailfrom=3ThUlXwgKCQ0qn8vqt19t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--davidgow.bounces.google.com;
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
Reviewed-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Acked-by: Brendan Higgins <brendanhiggins@google.com>
---
 include/kunit/test.h  |  5 +++++
 include/linux/kasan.h |  6 ++++++
 lib/kunit/test.c      | 13 +++++++-----
 lib/test_kasan.c      | 47 +++++++++++++++++++++++++++++++++++++++++--
 mm/kasan/report.c     | 32 +++++++++++++++++++++++++++++
 5 files changed, 96 insertions(+), 7 deletions(-)

diff --git a/include/kunit/test.h b/include/kunit/test.h
index 59f3144f009a..3391f38389f8 100644
--- a/include/kunit/test.h
+++ b/include/kunit/test.h
@@ -224,6 +224,11 @@ struct kunit {
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
index 087fba34b209..30d343b4a40a 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -14,6 +14,12 @@ struct task_struct;
 #include <linux/pgtable.h>
 #include <asm/kasan.h>
 
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
index c36037200310..dcc35fd30d95 100644
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
@@ -602,6 +602,9 @@ void kunit_cleanup(struct kunit *test)
 		spin_unlock(&test->lock);
 		kunit_remove_resource(test, res);
 	}
+#if (IS_ENABLED(CONFIG_KASAN) && IS_ENABLED(CONFIG_KUNIT))
+	current->kunit_test = NULL;
+#endif /* IS_ENABLED(CONFIG_KASAN) && IS_ENABLED(CONFIG_KUNIT)*/
 }
 EXPORT_SYMBOL_GPL(kunit_cleanup);
 
diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index 53e953bb1d1d..58bffadd8367 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -23,6 +23,8 @@
 
 #include <asm/page.h>
 
+#include <kunit/test.h>
+
 #include "../mm/kasan/kasan.h"
 
 #define OOB_TAG_OFF (IS_ENABLED(CONFIG_KASAN_GENERIC) ? 0 : KASAN_SHADOW_SCALE_SIZE)
@@ -32,14 +34,55 @@
  * are not eliminated as dead code.
  */
 
-int kasan_int_result;
 void *kasan_ptr_result;
+int kasan_int_result;
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
+ */
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
+
+
 
 /*
  * Note: test functions are marked noinline so that their names appear in
  * reports.
  */
-
 static noinline void __init kmalloc_oob_right(void)
 {
 	char *ptr;
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 4f49fa6cd1aa..e2c14b10bc81 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -33,6 +33,8 @@
 
 #include <asm/sections.h>
 
+#include <kunit/test.h>
+
 #include "kasan.h"
 #include "../slab.h"
 
@@ -464,12 +466,37 @@ static bool report_enabled(void)
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
@@ -488,6 +515,11 @@ static void __kasan_report(unsigned long addr, size_t size, bool is_write,
 	void *untagged_addr;
 	unsigned long flags;
 
+#if IS_ENABLED(CONFIG_KUNIT)
+	if (current->kunit_test)
+		kasan_update_kunit_status(current->kunit_test);
+#endif /* IS_ENABLED(CONFIG_KUNIT) */
+
 	disable_trace_on_warning();
 
 	tagged_addr = (void *)addr;
-- 
2.28.0.163.g6104cc2f0b6-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200801070924.1786166-3-davidgow%40google.com.

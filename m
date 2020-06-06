Return-Path: <kasan-dev+bncBC6OLHHDVUOBBL5L5T3AKGQEBIJ6LIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 6FE931F048D
	for <lists+kasan-dev@lfdr.de>; Sat,  6 Jun 2020 06:04:00 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id c8sf7827557ilm.5
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Jun 2020 21:04:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591416239; cv=pass;
        d=google.com; s=arc-20160816;
        b=qqSsJ7/fyrG9AY5/eJ0F1do+gjn+cy5YOnSzsNDs+Q9LMxSw86rv/nAM1mcnZMaF41
         Zeog1g1TMBukBvmVuNbf9bdrfad1GEAC9gAAeUkdN7WDv3YQ023Ug2iAk8FiQtGg1oGb
         7kmBTA9qXikYuwXRY7l/sHehYaaAl7yvqhOQbFPzfARQ9vR0a/hl4ZBruLluuKDT8uc4
         rpiy/yu8H8gJ6FPDXS+ITG1MRxnYD5J9qrfoJNrrXgP6i0yBBJRrCPisLtexVvSyTTPa
         worTc+9zc5DvUC8U87QMQfgdIXq1E3ngaiaKXtfDMfNNUaFZpAr9M8gAcaWL2PExJ8G/
         6IqA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=TFvpRA07YuA4zJohU5Vl6WREq8Sm0ahCqLct+NA4s3U=;
        b=X5WDksqSG5L5c9PW4cQKv7c/Z4JukHF1UsDsmIKjCx/paWkKObA2AW8OZDruwBXYBz
         whygNk/3+r6PWGNC31SGYcoWrTmh4/Ej4VLX4myJzjjXiLIn5cOdC7EUacPH1V5hmISD
         XInxO4O/2x4Z3kfwRE4ubClE/jp9bGuwLmftHc/83JJ8wmxzJ9qpCzraiuVSJeNFcxb+
         NhNMJWFNuRunq8bVBLbtmuEI7+8gU0H8hBgud0NxvlNQiyWaV6zAoP73PG8t77PiNZTw
         INjBCzvUmnDC9IArE625O88nKyRwVLay7KvHJehWKXvT7f+zBwWxPPi21ho64ZVBTPy0
         pCLQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WpxVuskQ;
       spf=pass (google.com: domain of 3rhxbxggkcumif0nilt1lttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3rhXbXggKCUMif0nilt1lttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TFvpRA07YuA4zJohU5Vl6WREq8Sm0ahCqLct+NA4s3U=;
        b=Ek/W0HFg4/x26n+UeUnxDcFqKu56WJX4Q0LGgeREMT/W8yuYothmwJKtmI39ome/S7
         Zk4Nnb2bQfNiEXOrYrRau6YsTyJukkhKK+0I9WhbewkmIn3gbDHUdYsGiPLAGmmTlNJ2
         ghhalhsUqoELde6LQ4xXCU0G4hYAos3RjDZQcfDByN1lwhG0rKkO5khJgRJmDqV6/Jp1
         QQteAKKhrQR2d9JR035O7n2ldp9SEGsZfesn42eikFUacDfQNgtkY9CZ/k6QJigI5oKv
         pNTP5tqoEMbgmUJeUsFy0xYihkGBhvEX9Dz+GWs0ID+03oMvQF/KnLIXYRjTaFgU/qYt
         MMwQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=TFvpRA07YuA4zJohU5Vl6WREq8Sm0ahCqLct+NA4s3U=;
        b=SEbYh+ZmCr3S3wlQgwTG9RJbJhosbNXmt4iJhCzVW1Pgj7xI7gnNisLO5uZZ0/ll6t
         nOwEfEIvjBftFnTzNeuSsTKKmGeMtNVP7iA0AgnX2fj7v1zV7CNY8DEj08fUJjo9iO86
         PEFkuWSDxViOWC7wo1haLVBhEJORsT5KdovnVgstYw2ev1H5ieVhBLWYU12ex3W0FHK0
         kiFqP5yslcXQaedwDMSPuYiIRlYNrdtjX7H7eLNUjvlyX8gANPyU0igQe+5SWs3nUoiW
         EZCgws2a7ZBUJoqSH1j7DW4nsWw4J9vtu09D7nXV64OVAt1P3FumcEZgIgx8GBTZRC0h
         Zvig==
X-Gm-Message-State: AOAM530GhcvHm/uTX/U2QBMmA5R6KHG2kp8S94ALD+mwj8N55LxQ1KvA
	DYbzqhXQcWPCq/IF3qk/bs0=
X-Google-Smtp-Source: ABdhPJz31SeWBqwcWZtK8MYBzSgFfaW9gjt+To/JCZegN+IWZH/9yQExWPtpSd2L/03EAZmsHCzMZA==
X-Received: by 2002:a05:6e02:c:: with SMTP id h12mr11098925ilr.125.1591416239410;
        Fri, 05 Jun 2020 21:03:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:2dc6:: with SMTP id l6ls1922773iow.4.gmail; Fri, 05
 Jun 2020 21:03:59 -0700 (PDT)
X-Received: by 2002:a6b:6a13:: with SMTP id x19mr11349369iog.175.1591416238999;
        Fri, 05 Jun 2020 21:03:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591416238; cv=none;
        d=google.com; s=arc-20160816;
        b=Va9+7mWYptvv/U+GsS1GZ09pvTTsKIDKU4mAF/bPcjHQTiX0hSnuVzK/FgYgyiE1qa
         tO4lWrHMn2Jnucsncm1fyafafgxHuYpV8GePxK75ncvoLf1H3qKkj0vxDzSKs+1f8Htv
         VPqoV6vhDc8KH1uGG2YxX1ud2szzYdpSfx1ZcMrpEQKxXBVGQ97AMtuSQ7nScNP5UJiH
         AQMZW2OzRF+baV8BcHnrM60/+qROCpcThVRdnbcnEeosd4Ixq3xTgCdRyM71d0+Fdt1q
         nRehd+OL0PMPEL9b4Ek5LLywA5XMwmgKr+4V04xd8ZucS6/sNKjqqXe/UMaHK7qkG/Sa
         R7CQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=49WwL7MaYChSHfyRgjr8LOMQ2nhTltp4GLnuvg625Bk=;
        b=uVk6hNhZ11ZgI484rxYpxsvfBCHreuQqPirUtYgVexEZgelRf68bDIpY7lYDy110HH
         OuMlPrQ5tkfz08PWbZkha3qpySejrT9pNyAQaAKfpugMCztSzW1J+unkHXWnWlHsb5Y0
         J//qfMhCEKRoVxPqOng5mGpRi1bDBei+uV04s21oh6GQ8eEvFUxUllP/ecAmiGLjPzVm
         RgbdwE97WquQlNgjGDV+CLtnYnenV59434c2XHSiBN2kddhPmlFmww2Yjo6+w3WW8N0g
         eLiPT018mYHBN0GLfE2ygdNiCxnFVu3mAC08S7fxgGIn0828S6PyGjp3uzrY1siht+fN
         zYJg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=WpxVuskQ;
       spf=pass (google.com: domain of 3rhxbxggkcumif0nilt1lttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3rhXbXggKCUMif0nilt1lttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id y22si204619ioc.0.2020.06.05.21.03.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Jun 2020 21:03:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3rhxbxggkcumif0nilt1lttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id p18so8298124qvy.11
        for <kasan-dev@googlegroups.com>; Fri, 05 Jun 2020 21:03:58 -0700 (PDT)
X-Received: by 2002:a05:6214:60c:: with SMTP id z12mr13172139qvw.236.1591416238349;
 Fri, 05 Jun 2020 21:03:58 -0700 (PDT)
Date: Fri,  5 Jun 2020 21:03:46 -0700
In-Reply-To: <20200606040349.246780-1-davidgow@google.com>
Message-Id: <20200606040349.246780-3-davidgow@google.com>
Mime-Version: 1.0
References: <20200606040349.246780-1-davidgow@google.com>
X-Mailer: git-send-email 2.27.0.278.ge193c7cf3a9-goog
Subject: [PATCH v8 2/5] KUnit: KASAN Integration
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
 header.i=@google.com header.s=20161025 header.b=WpxVuskQ;       spf=pass
 (google.com: domain of 3rhxbxggkcumif0nilt1lttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3rhXbXggKCUMif0nilt1lttlqj.htrpfxfs-ij0lttlqjlwtzux.htr@flex--davidgow.bounces.google.com;
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

This patch makes use of "kunit: generalize kunit_resource API beyond
allocated resources" and "kunit: add support for named resources" from
Alan Maguire [1]
	- A named resource is added to a test when a KASAN report is
	expected
	- This resource contains a struct for kasan_data containing
	booleans representing if a KASAN report is expected and if a KASAN
	report is found

[1] https://lore.kernel.org/linux-kselftest/CAFd5g46Uu_5TG89uOm0Dj5CMq+11cwjBnsd-k_CVy6bQUeU4Jw@mail.gmail.com/T/#t

Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
Signed-off-by: David Gow <davidgow@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Reviewed-by: Andrey Konovalov <andreyknvl@google.com>
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
index dc2c6a51d11a..842adcd30943 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -23,19 +23,62 @@
 
 #include <asm/page.h>
 
+#include <kunit/test.h>
+
 /*
  * We assign some test results to these globals to make sure the tests
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
index 80f23c9da6b0..45f3c23f54cb 100644
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
@@ -486,6 +513,11 @@ void __kasan_report(unsigned long addr, size_t size, bool is_write, unsigned lon
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
2.27.0.278.ge193c7cf3a9-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200606040349.246780-3-davidgow%40google.com.

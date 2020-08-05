Return-Path: <kasan-dev+bncBC6OLHHDVUOBBQHLVD4QKGQEWNIELJQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc38.google.com (mail-oo1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id C3ECF23C491
	for <lists+kasan-dev@lfdr.de>; Wed,  5 Aug 2020 06:29:53 +0200 (CEST)
Received: by mail-oo1-xc38.google.com with SMTP id m10sf18003492ooi.18
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Aug 2020 21:29:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596601792; cv=pass;
        d=google.com; s=arc-20160816;
        b=xpHqkP/izMEewhPA821E0xZOQB5peJRRtN3GlX6cJm6JhRIeoHSXX9gknVnfCCeTKf
         KRp4J3zhKmIrTiuqEsqk+Zm9BAKimQHWS6hHdiiQfhzbET6cUYYqmodnuf/2trFYm/gN
         qPKAQnY07aLLtb3gOGzfrqGA+pFxl2GcZpI2qIqDDANirm/FohciZueW1M7UjGKqS/1e
         G3M3Vs7wwmyvKDltvqdrQafihx8nKAUeis60ZfSACLBsQOXRUZ8tqcVw11PfnSanpbTZ
         S25fsisDbVTL587R6nIkVPFZLK4C2Y+GnY5nwIXO9HdAh7F4OPO5hzA1pZxCDe3PgpQK
         Kc/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=Ni+87Mo42Lm+i8EvF8jwvh7Q3VXOqNAFXlQj1v3um28=;
        b=BHKITZZY7Zl8pVUdpBzXLbWdHqpqLJAQ5Gogsixwbwv2fFqN6cuwXm3sotv7RXhDbv
         TgKNrsqMuJ/ZOiqjTyY6gYN0eKMIDB3DeSYpo2psYKd3rPIszWbewlZQiwHqjy5rl/vN
         xD/ZXoZC1dkOVBbDyHdaEl5deFRxEW1vXrUuTOkHVRe8ekNzFLxQYE+i5wwsuBcXS6d/
         EFzv8WTTrA7STDJ7xkPv/azW1RWd6z868zIPQSVpNAVOUHsGpFqHgmYXDvag0lFvFEOe
         YT9r/wQtwnilHVhRk9HoOKzgZ+y6ccs+a4IDyqM6f4QZYHK+rh0wwd1pkZoBtCXBDv5d
         LNvQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LvNXYaNF;
       spf=pass (google.com: domain of 3vzuqxwgkcdi1yj614ck4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3vzUqXwgKCdI1yJ614CK4CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ni+87Mo42Lm+i8EvF8jwvh7Q3VXOqNAFXlQj1v3um28=;
        b=s+OSc8rjh0JQTkyWavV1gEMe7OMVJHwOa+Yi+SMDktNyN/fzCwiMpgw2NNqfSNv9+G
         jg/EBVn6TZOvyqXC63jj78YFfQiHkVXRjgLmzEme8Woj0k7RalHFgyY0eB2QUgQ9wm1s
         Mxg7uq11njshLhKEpDgBFtkO4shXjQtp7XWD2yb40pENp/jry8qbMjv7Q1JrCFWV2Xpw
         4/er28iljNqNLXe0Nk44c/hCTXLn72xG6OxAdj5248uNJ9MCE0eU8gfIOS/Wec7sKocU
         lgjBc9W/UXHVLAzmLEK7b8U1bj13nMBc3WGRvr5R4ei2ftPGkDkkgUtg+b/HU/bSH4N7
         iUUA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ni+87Mo42Lm+i8EvF8jwvh7Q3VXOqNAFXlQj1v3um28=;
        b=PRmfaW81CwQ55cmWR0149cBM6K5UN+3Qv8vSI6NWC5TTArhkRQs6WV2230BMkPC0pO
         D/pPyuEvYkzUagtBbhbTLwmR1uxZ9weW0HgPs7OUdgU7vx9f44V+Z8o3pxvh15609vGa
         4ZJyBEGlwbfG5i+3pXzCNRNWdC/3oC5zu17Sha5FXx3umGZPvOAME+dz5ECK0AXjmYRU
         tWZUmEHnKtPLr2WpsEad2Cv5rb+AefsmUT3nFURsZT9ddCGGxUTHT66vQovFclgweL0+
         D1O+iAwmhEjeBQUB0hCgUuOE2McM3BX70R/LboTGlVaAMSL4TiBD6smF7k9JxqKZsP0s
         Z1ZQ==
X-Gm-Message-State: AOAM531HPwFtije1TIKHQqclWgOdGHP5xv2pwMDUO5RtwYWrVTGu0IZe
	INrIxaKWQwTuYHq2LDn6Fnk=
X-Google-Smtp-Source: ABdhPJx40nMBkNoQ2J8xRHftIYvh+x5aKhko+K8Llb+WcNp8MlMpQaa9o6f4i5+irBYVa7iaEve6Rg==
X-Received: by 2002:a9d:6b0e:: with SMTP id g14mr1139794otp.171.1596601792600;
        Tue, 04 Aug 2020 21:29:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:42c5:: with SMTP id p188ls157274oia.3.gmail; Tue, 04 Aug
 2020 21:29:52 -0700 (PDT)
X-Received: by 2002:aca:f457:: with SMTP id s84mr1349493oih.138.1596601792228;
        Tue, 04 Aug 2020 21:29:52 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596601792; cv=none;
        d=google.com; s=arc-20160816;
        b=Erca+snQeldjhqbgVbNp8yenPKUsIUAA4FGt3oHdhBEbi6itsGI0DKLCQnCRualzTy
         tokcnBb0OEO9Y33cD5awPIgrln5LFHAiOJbXinbgI7PHxwGrSCKH6W/JE1eTERgenKhn
         cDzBeVnyimSWFtYCzEs+bJL9zeKHORK4CF6Mk0h0ZJJOHYLPPluTihOW8y8Vi4sJBxIl
         Vqs672uG1+x2s/vQm7PAK90JYuyw0DfkapNDfzudlRonKE6ntQUm8lBPHa+0dv7dE2Ge
         Fkk1wWDI2tJd7MgQD7HC4g942Fs4dsePAJr1epD4+jW9ZkVEkjLOZS+KJqOr7QufMyoO
         hVuQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=J3RmpWXwZ/1d89ythMYIXtVZiV0eTdWaBFiczRT37Ws=;
        b=ush6oQO2s15WY4mmWc7/0ucOI/TafZXmOQrCW56fhIfSh6LCixPUrQi/818oIzDrlS
         GFDzekO2eMlgO/KY0/9VEzLvoIXnmUbv2+oc+fYNEoXB7xtHwnHBZ1tu72aMG9i4btcR
         3hPlkhjHKcOy/rizHYGQEtRh4LBwXzduDQi6ceP+/LQde0HD4J2BTbuGg55Vr4rVsJdQ
         pWVCvVKvvTplg0AKwmG6aziRuxkefrD2kvvZGlDajB3NNyKHQEHVk3Yg+mYbJ73SNA43
         8u1dUBc40O/Rk7oJabeBmYV58xRq1jQJwi6ou87SUot8uKVtSmOlgEIhKeWhH+FebFZH
         ZfbA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LvNXYaNF;
       spf=pass (google.com: domain of 3vzuqxwgkcdi1yj614ck4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3vzUqXwgKCdI1yJ614CK4CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id m21si77434oih.4.2020.08.04.21.29.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Aug 2020 21:29:52 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3vzuqxwgkcdi1yj614ck4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id g127so11577456ybf.11
        for <kasan-dev@googlegroups.com>; Tue, 04 Aug 2020 21:29:51 -0700 (PDT)
X-Received: by 2002:a25:3106:: with SMTP id x6mr1908298ybx.364.1596601791487;
 Tue, 04 Aug 2020 21:29:51 -0700 (PDT)
Date: Tue,  4 Aug 2020 21:29:34 -0700
In-Reply-To: <20200805042938.2961494-1-davidgow@google.com>
Message-Id: <20200805042938.2961494-3-davidgow@google.com>
Mime-Version: 1.0
References: <20200805042938.2961494-1-davidgow@google.com>
X-Mailer: git-send-email 2.28.0.163.g6104cc2f0b6-goog
Subject: [PATCH v11 2/6] KUnit: KASAN Integration
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
To: trishalfonso@google.com, brendanhiggins@google.com, 
	aryabinin@virtuozzo.com, dvyukov@google.com, mingo@redhat.com, 
	peterz@infradead.org, juri.lelli@redhat.com, vincent.guittot@linaro.org, 
	andreyknvl@google.com, shuah@kernel.org, akpm@linux-foundation.org
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	kunit-dev@googlegroups.com, linux-kselftest@vger.kernel.org, 
	linux-mm@kvack.org, David Gow <davidgow@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=LvNXYaNF;       spf=pass
 (google.com: domain of 3vzuqxwgkcdi1yj614ck4cc492.0ca8ygyb-12j4cc4924fcidg.0ca@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3vzUqXwgKCdI1yJ614CK4CC492.0CA8yGyB-12J4CC4924FCIDG.0CA@flex--davidgow.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200805042938.2961494-3-davidgow%40google.com.

Return-Path: <kasan-dev+bncBDK3TPOVRULBBNU6TH2AKGQEG2AWH2I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x23d.google.com (mail-oi1-x23d.google.com [IPv6:2607:f8b0:4864:20::23d])
	by mail.lfdr.de (Postfix) with ESMTPS id 2973A19CBD8
	for <lists+kasan-dev@lfdr.de>; Thu,  2 Apr 2020 22:46:48 +0200 (CEST)
Received: by mail-oi1-x23d.google.com with SMTP id l137sf4505639oih.21
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Apr 2020 13:46:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1585860407; cv=pass;
        d=google.com; s=arc-20160816;
        b=uKgTuf/ROI8mxzNIlTpp2wvpVDpuiz0mzLszeVQV3EX6t4CLV/J7PwN8kgVGiKGVpR
         SB5eI4IsZQoZvvFNzfTASiSOCc31WS+paj27qFmY8vnQ+DhyN8LXpXPJ3X0ZGSX062pa
         7BUHKkMLs1k7Jd5Wa/yhaXdI4B5RM/Cv/cAyTDj6XQVqoW5NfcXEFycCB1a34xvJijBe
         i0pSfz9lLCNdJZHq2y171MJTmD40WffvA84w+KPj23PhgJjNQamryhsmaTbM374TaqIQ
         p+bv8bS8GneOeonVKYEnVuXSbx3+zHTWagAuF4cqHkKEE22+JKccqR1C7QbbAoUVO/J8
         +QKQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=lQrt8kavAtiH6OtPYkJ0QEHquGlMESKK5UUfpdeIl3k=;
        b=UgUWsuX5X1zwJAPwFX5vt+9RzhpIvKAL6omjNmxF8MM/mzABWfmfoXeoOoG1FY+NMt
         5UrMF2GmPAvRODp4XwgYuhjVxz4SBBD6HjNIpEHO6qYVElbni/CiMZL6tnGz7DP3AZjo
         ODF3naJjyJbqsT0OnlhUMBO51QjHFCDbqOjejdXzJgb4GoX5Y0arS98uaMkO9kTzNnQz
         bNGiJQbj5kdFtEEtY1kUbsMZinMGYYLnt1QwjTLxPIO7wEKzNnHSe6xKEpcIvYWsUkfM
         Eaz9Q8qD6+nV0h8e69awvqNtyrUOF2Q3voypBZ8ZULgSpxl923l2Uad+h8rGAJdXy1AC
         N7MQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Eofb7qax;
       spf=pass (google.com: domain of 3nu-gxgwkceybzqapitnwvawowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--trishalfonso.bounces.google.com designates 2607:f8b0:4864:20::104a as permitted sender) smtp.mailfrom=3NU-GXgwKCeYbZQaPITNWVaWOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--trishalfonso.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lQrt8kavAtiH6OtPYkJ0QEHquGlMESKK5UUfpdeIl3k=;
        b=C8M98EmQP1F7TWtSZqjkwqJHqSWQkaMvv9QUS0FMyxpXT7ij4yBjEa+ENG79iJWWvG
         aMB1pmJQQB6YL/lXMTM8miNvOLFOCOQn6ejfU0RtlQ2mzqGJqfIwee5X7M/ym9t1u8Kl
         oMuerv/ScaiLuvyq+0pSbLeVdZa6Yhxz83JtYKkU+RVNdJ0bWehyjzFTwQ6OWys+hieV
         mlxgM67M6HIjhXg0tIWqHFGm19j63CLjoHFfkxf23Uc6Qaw2u9dozcGOVfJwGaOd0GUV
         t28YAlq5MNd3ubGbL+j6HaBTziy0MIwwzVqIj/SsZathzsxaa0cnB/PGJ2iHZwyEoTLO
         7SYg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=lQrt8kavAtiH6OtPYkJ0QEHquGlMESKK5UUfpdeIl3k=;
        b=oclK4fddnIatKKl6VBY63xvzTVJZfYuto6GIU8QtfRVuVs3ygDcHCwTSD4ZWA1ISol
         xMSzG9sedzMaBnaf0s3uRGk25HbA5qkgrkwZ2dmJr5iON8Fv+2OP1zOBfb2uaGadsx2F
         iYCtqw5AyNsn31ANwpF2sDjvjhfLrU1KLlwJ33zoCLDmOx5rn5Y1R1BPECfmwzOJhsid
         7ZgISI5+FxtpjG2w8rkKDKzkTeOKLISIwANsykh7qHxOj5tO/W2eZsPZnZ8h9tWp5qK4
         ZwMDb3hRyxBvoUm5fUArox8J31WI6cw6diFQ+kJbDhxl9rx9PBozM8Qe9168Iiy9l7lx
         bEEw==
X-Gm-Message-State: AGi0PuasjN+MfIKfSiFrZRQsGbxh5KrB2ElSw3SnY4+nMpIwpV4c6WfV
	zFll0rJfLA02OCFrehBG4BQ=
X-Google-Smtp-Source: APiQypJd3j9c9sESYDDuQCzW1ZnsYSyy1S6jFWAZE7VNCYA9HD6kY+PIgDS+KgnGLML27QAFU7kIag==
X-Received: by 2002:aca:5014:: with SMTP id e20mr768831oib.34.1585860407009;
        Thu, 02 Apr 2020 13:46:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:3089:: with SMTP id f9ls2165387ots.0.gmail; Thu, 02
 Apr 2020 13:46:46 -0700 (PDT)
X-Received: by 2002:a05:6830:200c:: with SMTP id e12mr4008990otp.198.1585860406579;
        Thu, 02 Apr 2020 13:46:46 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1585860406; cv=none;
        d=google.com; s=arc-20160816;
        b=AbZ2QJNG7gxI/TM+rovgfJvULK78avfmCVSET+8xhkT+7x26HhsrSJl4BecKdj24BV
         y9gkDS5yndAzscD4H96P7ImXJZz837qlEWlL79SHz9DMUfFW+PCMnDFEO63TUw67jMRK
         d2SuzRUwxe9u+ox1MoT1A93pBef4i+Y18qA6ZfrloS1TynO9Acccd+fsfzsQQ9VlwKyZ
         SaPmB4oZs/a9pPalUeXdtXAgJPbSdI1b3io4Ixk2DEZQzqbD8x5NBNYD8OMe/HaWQ3zT
         qwkWN3J8Pfik3/jNNjNW9vOVsP4Ly4XZgFMZlWwgvvJ5wOgdv3gSUvQea3LRAfIqrUAC
         Z7CA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=tYL+uQBZdi0KOgINSVQl+qIlWrLdwDRqpATJxQQU3LQ=;
        b=OethPN/1uGe2P1sdoGnE3/a8y4rdfKU0BroGxgArhNm67Pp7+LK62XV2QIafSHw531
         8mKcn+e/scaTaeQAwthBWxPy/qCfs9MknFHZGrYwrm+iSeEtebfcb9wHFghBz/7GfIh3
         Gj77D2bpZS0g/W2Bsm01cZpZ8kuZi/tFueq5W35brGIVf2tbmVPmFNu1i8hYQctimVup
         7qlI2jYFuubP0Y3aKJqa1Ta6GKVVBuLMn7T1/3CJKolLeYJI7kDWd3oa1F/a/Fklml7u
         tNFm4O4sTPDXRWspoD3k6CPO3HdlkWWRsb3DGnVcG26BmmpPe1rFoV+qg0Qqlz5KJQmH
         +GrQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Eofb7qax;
       spf=pass (google.com: domain of 3nu-gxgwkceybzqapitnwvawowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--trishalfonso.bounces.google.com designates 2607:f8b0:4864:20::104a as permitted sender) smtp.mailfrom=3NU-GXgwKCeYbZQaPITNWVaWOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--trishalfonso.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x104a.google.com (mail-pj1-x104a.google.com. [2607:f8b0:4864:20::104a])
        by gmr-mx.google.com with ESMTPS id k23si363406ooa.0.2020.04.02.13.46.46
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 02 Apr 2020 13:46:46 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3nu-gxgwkceybzqapitnwvawowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--trishalfonso.bounces.google.com designates 2607:f8b0:4864:20::104a as permitted sender) client-ip=2607:f8b0:4864:20::104a;
Received: by mail-pj1-x104a.google.com with SMTP id p14so4512483pjp.3
        for <kasan-dev@googlegroups.com>; Thu, 02 Apr 2020 13:46:46 -0700 (PDT)
X-Received: by 2002:a17:90a:202f:: with SMTP id n44mr5857243pjc.150.1585860405766;
 Thu, 02 Apr 2020 13:46:45 -0700 (PDT)
Date: Thu,  2 Apr 2020 13:46:36 -0700
In-Reply-To: <20200402204639.161637-1-trishalfonso@google.com>
Message-Id: <20200402204639.161637-2-trishalfonso@google.com>
Mime-Version: 1.0
References: <20200402204639.161637-1-trishalfonso@google.com>
X-Mailer: git-send-email 2.26.0.292.g33ef6b2f38-goog
Subject: [PATCH v4 2/4] KUnit: KASAN Integration
From: "'Patricia Alfonso' via kasan-dev" <kasan-dev@googlegroups.com>
To: davidgow@google.com, brendanhiggins@google.com, aryabinin@virtuozzo.com, 
	dvyukov@google.com, mingo@redhat.com, peterz@infradead.org, 
	juri.lelli@redhat.com, vincent.guittot@linaro.org
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	kunit-dev@googlegroups.com, linux-kselftest@vger.kernel.org, 
	Patricia Alfonso <trishalfonso@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: trishalfonso@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Eofb7qax;       spf=pass
 (google.com: domain of 3nu-gxgwkceybzqapitnwvawowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--trishalfonso.bounces.google.com
 designates 2607:f8b0:4864:20::104a as permitted sender) smtp.mailfrom=3NU-GXgwKCeYbZQaPITNWVaWOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--trishalfonso.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Patricia Alfonso <trishalfonso@google.com>
Reply-To: Patricia Alfonso <trishalfonso@google.com>
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
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
---
 include/kunit/test.h  |  5 ++++
 include/linux/kasan.h |  6 +++++
 lib/kunit/test.c      | 13 ++++++----
 lib/test_kasan.c      | 56 +++++++++++++++++++++++++++++++++++++++----
 mm/kasan/report.c     | 30 +++++++++++++++++++++++
 5 files changed, 101 insertions(+), 9 deletions(-)

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
index 3872d250ed2c..dbfa0875ee09 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -23,12 +23,60 @@
 
 #include <asm/page.h>
 
-/*
- * Note: test functions are marked noinline so that their names appear in
- * reports.
+#include <kunit/test.h>
+
+static struct kunit_resource resource;
+static struct kunit_kasan_expectation fail_data;
+static bool multishot;
+static int orig_panic_on_warn;
+
+static int kasan_test_init(struct kunit *test)
+{
+	/*
+	 * Temporarily enable multi-shot mode and set panic_on_warn=0.
+	 * Otherwise, we'd only get a report for the first case.
+	 */
+	multishot = kasan_save_enable_multi_shot();
+
+	orig_panic_on_warn = panic_on_warn;
+	panic_on_warn = 0;
+
+	return 0;
+}
+
+static void kasan_test_exit(struct kunit *test)
+{
+	kasan_restore_multi_shot(multishot);
+
+	/* Restore panic_on_warn */
+	panic_on_warn = orig_panic_on_warn;
+}
+
+/**
+ * KUNIT_EXPECT_KASAN_FAIL() - Causes a test failure when the expression does
+ * not cause a KASAN error. This uses a KUnit resource named "kasan_data." Do
+ * Do not use this name for a KUnit resource outside here.
+ *
  */
+#define KUNIT_EXPECT_KASAN_FAIL(test, condition) do { \
+	struct kunit_resource *res; \
+	struct kunit_kasan_expectation *kasan_data; \
+	fail_data.report_expected = true; \
+	fail_data.report_found = false; \
+	kunit_add_named_resource(test, \
+				NULL, \
+				NULL, \
+				&resource, \
+				"kasan_data", &fail_data); \
+	condition; \
+	res = kunit_find_named_resource(test, "kasan_data"); \
+	kasan_data = res->data; \
+	KUNIT_EXPECT_EQ(test, \
+			kasan_data->report_expected, \
+			kasan_data->report_found); \
+	kunit_put_resource(res); \
+} while (0)
 
-static noinline void __init kmalloc_oob_right(void)
 {
 	char *ptr;
 	size_t size = 123;
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 5ef9f24f566b..497477c4b679 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -32,6 +32,8 @@
 
 #include <asm/sections.h>
 
+#include <kunit/test.h>
+
 #include "kasan.h"
 #include "../slab.h"
 
@@ -455,12 +457,35 @@ static bool report_enabled(void)
 	return !test_and_set_bit(KASAN_BIT_REPORTED, &kasan_flags);
 }
 
+#if IS_ENABLED(CONFIG_KUNIT)
+void kasan_update_kunit_status(struct kunit *cur_test)
+{
+	struct kunit_resource *resource;
+	struct kunit_kasan_expectation *kasan_data;
+
+	if (!kunit_find_named_resource(cur_test, "kasan_data")) {
+		kunit_set_failure(cur_test);
+		return;
+	}
+
+	resource = kunit_find_named_resource(cur_test, "kasan_data");
+	kasan_data = resource->data;
+	kasan_data->report_found = true;
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
@@ -481,6 +506,11 @@ void __kasan_report(unsigned long addr, size_t size, bool is_write, unsigned lon
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
2.26.0.292.g33ef6b2f38-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200402204639.161637-2-trishalfonso%40google.com.

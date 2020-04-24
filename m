Return-Path: <kasan-dev+bncBC6OLHHDVUOBBJ4HRL2QKGQE5U7K76A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id 61AAD1B6DD8
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Apr 2020 08:14:00 +0200 (CEST)
Received: by mail-oo1-xc37.google.com with SMTP id s185sf6239781oos.11
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Apr 2020 23:14:00 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1587708839; cv=pass;
        d=google.com; s=arc-20160816;
        b=TCZUHe/lHH2X3JRZYEyooK5pwhf7ky+PVsKgG2HtLsZuZBpR9/LI9ZVmwpw1SMvcrb
         /oK31O/eBPG/ZB7vtI1MD6W9J8enndSFOhK3y7a/pzfzKFLaPfw+6fNK+foFbj6XA6Lg
         +fSKfecKsVzmHuyIpt7vJzhSSlNkzR/g5GFBcmO4wpkhKecowWdQRJOCu2BLLVtj6ext
         Wfl9VG8WmsIRZrdwKDpRShb+V1XZTXDAXhceQ7HeC8d37tBWpyZifNUDE/Swgyl9XSKU
         ms0xdFBTOlQxIUl+XHWYnee5psKFsDKo5WCnw68nzXA8Sgk++8VfCSCqcVSjMgB642Af
         mBXg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=e0bI+fsyYhclPY23RIhh9BF8m6BShvWjHdkMqpkhkXA=;
        b=xSzjuiK7SB2rOEApq/2TngM/VtSIu1pGbOgEjm5Fji8XCwGqSTCQdk4SN50qd3Ek9C
         fGxjspS5w2yE69H5XV0dUPPepN2oH9kwc5dlZaoPjyO/Jtife0IkpYlVV/9rxo/R/Pcq
         uNIIAjgLruNcCTdMyHx8Pqugiyi/wBXUUJNLTaiC8hXQ4sKt4TRrtbrzT3h/hxaoUERh
         +4SSl5gjqGQ6/Jqqem5XNEJ9iYSEXiVM3vi6T8iYmlMtR/MQZsqE9JGOgqLqQ3eZBvKW
         uupSbGuetiiLpyzEsw1VVry3yKdHlV65lQWaqi0/mi8Da9NB7ZXw4ZcYdRlIaP463f/m
         5UeA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dmjNNyI1;
       spf=pass (google.com: domain of 3pooixggkctmspkxsvdlvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::549 as permitted sender) smtp.mailfrom=3poOiXggKCTMSPkXSVdlVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=e0bI+fsyYhclPY23RIhh9BF8m6BShvWjHdkMqpkhkXA=;
        b=ZTZ8J/i7nwufYHQsVFUDSGR4dy7Bt3i1gq1yJUAxkYRCQIiS+h4GvHklschmW0BWDj
         xk4kjVafLhDWEGYbWnGFw+vlIF/LCx1qK3BSer2B3Gcbkjvw8k3a/8YAsKGb5yBYjbHT
         2q9by9Aeau6UHXn2av3jxAHlRHdgupbdLzDo4yXOPiJLU26JtI7OuV+PpG2R0/LaPL3c
         Wqv06YCTBkk+TWbam+S2GTNnVphUXioa9U+ermt6qRrhFm0vgT5t1H4o4oSKZ+lCR4Ay
         jqniQtEgKxhQj3OdyTQTF/y167ppAmcvqSGjHC1GMRJcEbSXwvF3YLsTbaGHazcEyWie
         I9nQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=e0bI+fsyYhclPY23RIhh9BF8m6BShvWjHdkMqpkhkXA=;
        b=MxzGv+oGgMlsAz1BJArBtrhlONTpMflOzhXOvnK+i1wdq2yKHSqm/IvvDDV+e4rI4N
         g1p5FtXFT6DtF/PPZlAF6CWtGQiVdrvl2eYu4WLNtZTrBwA1rR94OwfLwwUcRIoSFcLn
         KFnONOc/Tm7y/87kxjpbcxmNElkBnSnmVatb+Iu+ADTnxT5s3ReXIo4UQZO9ZA+Cj5RU
         Ra0uxqu/nEJS+kPieQ+Vm7s5v6BrD4La14/U6AJMk6cwLpKJf6tLiR5oUROjzMhc+fkn
         j9Sdg+nH6lV3Gl7aVDwTuHlfrcKJJIuHEL/YQ3T+hzcV1eSU3dX6X5EdL5dl/B2EXJRe
         FiUA==
X-Gm-Message-State: AGi0PuZrMZOPOTs7b29V8YCWaVqrb5wMAOJA6HHx4RQu70zBbCGlNVjg
	olQjgtJwMpEc9UzPbZJ6Gok=
X-Google-Smtp-Source: APiQypK3cvaoa2n94zNxOqnyLHW6bZ5zhrYa5JoIhd56rVfmZxl9h9HB/n+ptbbh7XuLgzuqMFMtxA==
X-Received: by 2002:a4a:1ec3:: with SMTP id 186mr6610538ooq.66.1587708839332;
        Thu, 23 Apr 2020 23:13:59 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:315b:: with SMTP id v27ls241896oog.8.gmail; Thu, 23 Apr
 2020 23:13:59 -0700 (PDT)
X-Received: by 2002:a4a:d516:: with SMTP id m22mr6499250oos.72.1587708838976;
        Thu, 23 Apr 2020 23:13:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1587708838; cv=none;
        d=google.com; s=arc-20160816;
        b=FrHpgTys0AB2pD8TyCQhVA2RLkFgoefGKdHfJUGRAAkEaBbhjTvmiEKNhClE+Pa67P
         V6UFO1mU7/R1OZA//uxaXmlThBXVDQLPn4v6Zag6Jik+5UUZht7Xc8ExrPXcyPYLpGmR
         wT92jxqCWHF5Quy1IL2p1UJFNsLK6IvpsCplK3OIz31jnUjjvfskT867Fy7DS9Inu95C
         ASoE1JYQINqgcQMr64wsEDECi486PjCwJX7GB/XV/jNIaiqFmfM8tS15z0Cio22rmlHB
         VGuSh6zKRJ0B/dDc1RXAqx7z+Fve4Ji61XJ5U1XMJuSE+yLXbpSff6CwSCdUMCxOAk4z
         nC+g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=HEF/DAV8bcIOedhqOgbS7UFU8rZD4FDsBF5mByxyLwc=;
        b=HdI5xBn8xzSIpmpK43hVwSTtBw0kgv+1wvAWEjVOESlYsqIcsQICfv7lykd0+uUKAK
         yStpOz/2oUuhKd3oLIWyfIuYz5BICdAJVAQnxmE9dZf2EHkd4jUgaK6nKEtoy/9YBNLz
         igawFRc5geEv86c5t2jgUliLOL3+UvRSXeM2T9VwnDRhw6TLZzIkYQa0ZGliorZIpqCp
         v+deTYN4uLyYiOLJaLBJ6KpdnEativHK/q2brCT6IsHpLz5cfNseMO4ansUstv4BUvo+
         +rlr9q43bQMuMp6eJM6vPZ+xLgzJmxkydryniW5muz947HCate7YQ9fiBbz1a0voJAhu
         aTow==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=dmjNNyI1;
       spf=pass (google.com: domain of 3pooixggkctmspkxsvdlvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::549 as permitted sender) smtp.mailfrom=3poOiXggKCTMSPkXSVdlVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x549.google.com (mail-pg1-x549.google.com. [2607:f8b0:4864:20::549])
        by gmr-mx.google.com with ESMTPS id w196si626947oif.4.2020.04.23.23.13.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 23 Apr 2020 23:13:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3pooixggkctmspkxsvdlvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::549 as permitted sender) client-ip=2607:f8b0:4864:20::549;
Received: by mail-pg1-x549.google.com with SMTP id g69so5613412pgc.11
        for <kasan-dev@googlegroups.com>; Thu, 23 Apr 2020 23:13:58 -0700 (PDT)
X-Received: by 2002:a17:90a:3287:: with SMTP id l7mr4678886pjb.126.1587708838255;
 Thu, 23 Apr 2020 23:13:58 -0700 (PDT)
Date: Thu, 23 Apr 2020 23:13:39 -0700
In-Reply-To: <20200424061342.212535-1-davidgow@google.com>
Message-Id: <20200424061342.212535-3-davidgow@google.com>
Mime-Version: 1.0
References: <20200424061342.212535-1-davidgow@google.com>
X-Mailer: git-send-email 2.26.2.303.gf8c07b1a785-goog
Subject: [PATCH v7 2/5] KUnit: KASAN Integration
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
 header.i=@google.com header.s=20161025 header.b=dmjNNyI1;       spf=pass
 (google.com: domain of 3pooixggkctmspkxsvdlvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::549 as permitted sender) smtp.mailfrom=3poOiXggKCTMSPkXSVdlVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--davidgow.bounces.google.com;
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
 lib/kunit/test.c      | 13 +++++++-----
 lib/test_kasan.c      | 47 +++++++++++++++++++++++++++++++++++++++++--
 mm/kasan/report.c     | 32 +++++++++++++++++++++++++++++
 5 files changed, 96 insertions(+), 7 deletions(-)

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
index 2002f0cc5165..ef3bfb9fae48 100644
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
index 7700097842c8..c4bf58dd73cf 100644
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
2.26.2.303.gf8c07b1a785-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200424061342.212535-3-davidgow%40google.com.

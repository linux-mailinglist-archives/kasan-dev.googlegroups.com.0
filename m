Return-Path: <kasan-dev+bncBC6OLHHDVUOBBWGCR34QKGQE6MULCTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id A25E9233E63
	for <lists+kasan-dev@lfdr.de>; Fri, 31 Jul 2020 06:43:05 +0200 (CEST)
Received: by mail-qt1-x838.google.com with SMTP id b1sf12748099qto.17
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Jul 2020 21:43:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596170584; cv=pass;
        d=google.com; s=arc-20160816;
        b=bPO/y8BnijdMYkwM4Y3Nd9ykgTsDtrHRk6FfLQcBopin/0TGuMu+EyDjNIx0f33nh7
         5cY9z2uvLAqGHSc0n9Vsfk9fDS1hof0ygA+ADpJKNnHxkS5mHjrt7KbKU6HoFcOcNd70
         gQNvezeJrZSttjUFyOS3/5TVrU5B8W8Z2+CQpugsLYxmS6PvDNYSDbwrPiEo+pyRx/EV
         lReNbdugh4+KpklN+8XvTv2HD1U7H7rr3GymJhM8Sk8X6kYDrsq5utRExIHFMnq0hAA+
         t43vacsLoyFrYYl6aUSi1J+c05vji+0uCNLy+3lx48tbYHufFZksOSohef1Npm1PkiLh
         dzrg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=wNQIB65I9BJxtFuurwJDs7NKbaDnv5csBxvazhASFYM=;
        b=hFiohxziegxF1espForezL7+ZT7JnROEXT+Yt20XMRTp3TNtApSkvbnHmAauWC5pHd
         7P1LrA/YAsDOfXjREdvEkRb8WEQujVB9fqYwaQXSTQrG8OQnKUkj5A7oGNQGbmx50jZO
         vZ/8HRQEwXP/aFQmXbCXhq8mer2+bAAJGgV5cyNi6mU7Lb6o+oYvmfXMQLXWPbwCIjgb
         f3DyehK/xVy1olVW+3mHaVc71Vt704Mak31+bAoB8htKNt9dOrt455RYOQ6g5mHBrtp0
         PTjwbBx/hp06ip7ADZKaqT/dwVy1H1UlQqH+p9jYyB3h9+/ES909U2OhUCszd1/8H4GI
         wl5A==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=F5FUtMZE;
       spf=pass (google.com: domain of 3v6ejxwgkcsghezmhksaksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3V6EjXwgKCSgHEZMHKSaKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wNQIB65I9BJxtFuurwJDs7NKbaDnv5csBxvazhASFYM=;
        b=greaFp75r0kYY5H6eD4htDqRGEVv3zs3WuRSVXs1LhW5VUqoeczWpBIsP7vQI9TqSI
         5XiJD/hADv7gMK0s0VTzRJCiycETs8bwdxd0W8NRndZ41zH3OgQMtAHVWX4BhaqDmSMG
         uF4JJ8EK2t6zS9MJUws38IR4YUQPOvGY3hRVTujBpRWJvsMlKUkS+lRAIryFAt5ouU7Y
         nsocXt8nsxTR0GejtQxr2difIbDNuCcI4Dpdm0ZOx2IERPvmlW0UDFu+RR/fAGDug/0t
         szgIs/bN6IOyiqICGTBS5pp1espF6xx39vLBiH3vluiLg6FFSvcQCTpYvKCFCQsokyOe
         3+Iw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wNQIB65I9BJxtFuurwJDs7NKbaDnv5csBxvazhASFYM=;
        b=GipbA/d1zEWKKjCEeMQQBV5DVFrkgAdSQHw/rNiFzibzgGd+9uMJ+1gSPJIBy8Gbzo
         E5JHpc5NQRGagBa2zSL5qhyfwXAyEptdTErAEEtJ81W+DyibNZWrxaFJOPozAaZUzcTn
         wYGSyX2zLEfjwl0SWZq1nnd6IwCRytGNg9KTNpBBj6tHxTcLzA0evJ+Rm40zXwmagcey
         EMCSu468iAv/dlkl/LSbOyDRhtaZYprbY156wximXRa+NbLJ0m+Xbz9/mbyjjHvh0diC
         TRv+9c03w2dtII64kyr6zlkYXOwHHxEQ9Dl89fZI8WsTPJD6dHukxZ1818HPKAqar45a
         qDyw==
X-Gm-Message-State: AOAM532L1UAfZwNB3+2kgalLcLPQ9CJMMzB03gIUdoqXAZ+HnNy+ojHB
	2vZOwY1cMJavnJoXuSRX9Ag=
X-Google-Smtp-Source: ABdhPJx4l+xwhgQOlaDRaQIswJUKxzN3B9ENEtKCIePSwvcLWVWWjW4Hr/Y/ndL89XAFCaBVRSWfiA==
X-Received: by 2002:ac8:65c4:: with SMTP id t4mr2072118qto.264.1596170584561;
        Thu, 30 Jul 2020 21:43:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:fd27:: with SMTP id i7ls1891086qvs.3.gmail; Thu, 30 Jul
 2020 21:43:04 -0700 (PDT)
X-Received: by 2002:a0c:bd18:: with SMTP id m24mr2300998qvg.132.1596170584172;
        Thu, 30 Jul 2020 21:43:04 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596170584; cv=none;
        d=google.com; s=arc-20160816;
        b=Pq4Tmog2gm9tbcU7ZrnWDXkpWYH1twdddKrbFxEFfn2pzR0THFnx65uBySVLyhrlG7
         iep5hZNiO44p6du3+Ejuxfw5C4ReiXHS4N3y3loFv5S/fBND2vKY7H1UNuaw/jHcfPsk
         FDKMGnDqCx3ay/JMFtR8bWJAoD1przecej7l1dhfYylFWJJnEDkx55Eg8ToQMqNMcpOU
         wOwKbVbAuY28JVIfTIv5wvBsagcOIR+eLK00XCuo4/ggVcHExrTaeyzMmi1qGW8gG9K8
         Lpiq/YcUNfsgKe2E/7ZZ6lorXT+m1I18Rf5qJCp04acyhL7Lyt9mbJvvuREt7wE5RKvZ
         SmHw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=kYS2D6CxxblTibspc3xfpsTe+zwQeBARGFYFgMjXAdI=;
        b=p11wrGmNIEnn+qlItkX/d/8BCJ0L8sQX/Uopjk2BduWN7KhaySDGQqRJBKWh2Iel0y
         tjqWOVAFydQeQ1dhowjW/yq5MYhk4tuQEp7ENIQzj/72uMMlMQnFsOy5Ib1ebbhe8qbD
         xJEUv7AvTxgsAbXuDctbaDM0qSDvfdm/WHp3tsmrpQ5xuKyTHudfaHrOkw/DUX6gcxf5
         +5ykfeTn8Qxwe63wk+gLtfOmerB+Vx8CR4kG44cSy4biKox9dgnj2ALL8cEt68M7dsWj
         68YMty6B5H2iwjCaUVqfRKRFVXpH+3bqhx7qlUVD71doV/WTAqtRxwSEXxs1jRQLV289
         QFlg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=F5FUtMZE;
       spf=pass (google.com: domain of 3v6ejxwgkcsghezmhksaksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3V6EjXwgKCSgHEZMHKSaKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id w195si350243qka.7.2020.07.30.21.43.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 30 Jul 2020 21:43:04 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3v6ejxwgkcsghezmhksaksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id u12so36798500ybj.0
        for <kasan-dev@googlegroups.com>; Thu, 30 Jul 2020 21:43:04 -0700 (PDT)
X-Received: by 2002:a25:84cd:: with SMTP id x13mr3482818ybm.425.1596170583730;
 Thu, 30 Jul 2020 21:43:03 -0700 (PDT)
Date: Thu, 30 Jul 2020 21:42:39 -0700
In-Reply-To: <20200731044242.1323143-1-davidgow@google.com>
Message-Id: <20200731044242.1323143-3-davidgow@google.com>
Mime-Version: 1.0
References: <20200731044242.1323143-1-davidgow@google.com>
X-Mailer: git-send-email 2.28.0.163.g6104cc2f0b6-goog
Subject: [PATCH v9 2/5] KUnit: KASAN Integration
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
 header.i=@google.com header.s=20161025 header.b=F5FUtMZE;       spf=pass
 (google.com: domain of 3v6ejxwgkcsghezmhksaksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3V6EjXwgKCSgHEZMHKSaKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--davidgow.bounces.google.com;
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
index 82522e996c76..3ccb7874a466 100644
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
index 51ec45407a0b..90a1348c8b81 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200731044242.1323143-3-davidgow%40google.com.

Return-Path: <kasan-dev+bncBC6OLHHDVUOBBUM7475AKGQEGBXSSLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73f.google.com (mail-qk1-x73f.google.com [IPv6:2607:f8b0:4864:20::73f])
	by mail.lfdr.de (Postfix) with ESMTPS id 46499263DE6
	for <lists+kasan-dev@lfdr.de>; Thu, 10 Sep 2020 09:03:47 +0200 (CEST)
Received: by mail-qk1-x73f.google.com with SMTP id r128sf2964139qkc.9
        for <lists+kasan-dev@lfdr.de>; Thu, 10 Sep 2020 00:03:47 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1599721426; cv=pass;
        d=google.com; s=arc-20160816;
        b=PIxUJ+gq9DIGv5QB9LLhGiVs8BM7DkWIjYPevjd0QKYTflsX9xm+qXkUczjKkL0t9C
         AT8TOU98aWWInCpKc9CKq8grZHLTnMAaaEF4xbpOA8xk/Jwg3XOCcbtl2/MkGhR0YJpn
         mdoNRlK3iXk0jyEKuiVe8rqezQARuoPveJkwkxG8C/k7jB4F6mIsuzEe/vXnIUhFi5wg
         QaWf8P52XGw3Q0Mjk6coHNDdJJKqy54LmOE6wxDufyxVBtfJ5FmY7i1f/8i5t9d7bPJc
         kpFK/qBOij9+5paNs2INWs+Cn+v7qo8RoA4Y3UUwCeEridRUqLJNmmU8nn6a2lhUV6HC
         LyEw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:sender
         :dkim-signature;
        bh=P7p5MgROU1D9eSlqiFJ6+rIavHzYMZojnNNoj8V15/s=;
        b=0p86Z09B2GRcd11xux8y4Np7owzl9porEyWo2qMfPXRaEApq6f2GhvE2UTx+CCODwG
         WOZF7Pelh8voyl7eRSL1STfHunoPxdzzeR7zh+2lC6yVnENKEBFZbChUfUOjwQeL9D/l
         qtRpXfyorpU8fnhS64aw+RwV+IHB6IDAnxQ9amk3U2L9l2b0lFQrt8vWoaDPiwKvM09d
         D0L94GfgRFQtwehr922N812lJrXB+ievEi5Ax+hVHiBY7372IYl7wNlOd3GcMm28Gubp
         kaWtz6ZWL5FVM4JT8pkFUns7K+RmSkRPlfxu6FRd9sFgPHgd6a9mxDYHW6tbpUgCaEa+
         xGDA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NGM0s3bz;
       spf=pass (google.com: domain of 30c9zxwgkcdg74pc7aiqaiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=30c9ZXwgKCdg74PC7AIQAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:in-reply-to:message-id:mime-version:references:subject
         :from:to:cc:x-original-sender:x-original-authentication-results
         :reply-to:precedence:mailing-list:list-id:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=P7p5MgROU1D9eSlqiFJ6+rIavHzYMZojnNNoj8V15/s=;
        b=XapK6KE9SWvZTKW8GpfjUY48Z1dTbfl8qFCQewLxgby40uCuEG2xGalUL+iKW5I0/I
         sbz68jEt8ANecazcpnmokz1goSaBdkFGbF2IdmG+t2rB/xWawmBkGk5OkRHltlJTkRDK
         BvSZ9GssVsL3Xdiy/8ZkUKDEpvp3PvgRFWlTrsVH7KeFMO2TzgI6nWvIYld+SbN7yeGX
         3JHNf/puwb1FJtXqBZUoMAXnRQFAXUAjjolyJVtyLsmbS1vWIAMl2qcnhPJ5kuSQn4tg
         ZmOhmtb0N3hkhD9H6opnx2KjBXprpV+WA0kGd7QVCc/Ip62frlcylBvgwqyGcqABkFcg
         9y+Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:sender:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=P7p5MgROU1D9eSlqiFJ6+rIavHzYMZojnNNoj8V15/s=;
        b=fWFRPTUnHpggx9Vd63Vhe0rwa2mMoVlS3TcaxrtNpUgqLDpajuiZ+jq3kbTdh/Vcuu
         uqWOzRbtxflRVM7kObu9sAEwch5m/3yqMfmI4tNyxiNj+Bqgol3Ss8+ILPp0lz79+QJH
         i3yKZUyyhiTu8SnJ5soGKhLxx2MGIUVONO5ZaCX9rB9sSH5hn4I1QQwl+EpyMFaWWzy1
         IZEm1GP64V5JB8Kfxk8j5Mu4rPNsK5jutS3CtaY4y42ayoQhvcgY/EWkoLmrWmWRiSPj
         l3cs7Shc2En2SevBkkcXKSdF7cvBvJ7boDfbsDKLnSJiLy3IQKmcFbOU8zfO418c1Mk+
         vF6A==
X-Gm-Message-State: AOAM531J5UEEUXjHah6s0Z9GS4Uh/5Svft8kS+1b55fCkqN0iatPTavk
	8mUYRVERom3sWcGtfB8Ujxg=
X-Google-Smtp-Source: ABdhPJzNy2NNGhMNo2yrmqwV+8QmfdxjtF2oaSuU+6CHeNaROWUDBxO60eXyRLYCh1cVgG1krhqxdg==
X-Received: by 2002:a05:6214:a61:: with SMTP id ef1mr7777211qvb.115.1599721425910;
        Thu, 10 Sep 2020 00:03:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:23c3:: with SMTP id r3ls2126301qtr.11.gmail; Thu, 10 Sep
 2020 00:03:45 -0700 (PDT)
X-Received: by 2002:aed:2f01:: with SMTP id l1mr6738523qtd.349.1599721425363;
        Thu, 10 Sep 2020 00:03:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1599721425; cv=none;
        d=google.com; s=arc-20160816;
        b=C1jIRQP7lez6A1AlSiBfCqPlAKIdrhjXml7pgplUY1YKX/yWrssaDt9rBVEaXvempp
         qFIECJp+lASwhWRWPFknnucAXaW2LaWMnsnQNZ+HfPByZQfdh1u3sniCoa8v7ZL2hG74
         s1kAH/2iT547kX9wE9naj1WTLfFgsOUIn5mfwSQRxJPdEaJi0fYdhor4KdKh06GZrowl
         ZUDOAlvF/Fm+fecs4K1JeL/GZcVhRt3+nPz/pjv0LZv4H6LYe9FE4JPTp5mGeJk40S/e
         gIgxmTyalzK7CwoD3gZgJNWpF10CwzfJ8rdcVZBhgTvuH2TulkvGbIeDm0rdAPpAmAEJ
         ioMA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:sender:dkim-signature;
        bh=12Gbrk+oVobgGKJ2rAHsZ/bJaOl8tbeqfCworNeSW6o=;
        b=egyyNeEozFZlaCi5ldw0h/kbgmt+n7kZiJE0WwBtteiZHtzLvuPbzSQmYSUVd3GdTP
         RReEeLokw3T6+ihCXqAvKoOver4IoTzDj04PxWukY6S0hpW6kbQQhRfY/k/0wFnzvhf3
         iFUrwnxe8B7KNAUDvJjA0wgJhBqSAh/DbRwoHPjBjxOn1L525v3L1oa7O4Em4LB/cHsY
         QcOnU7D0+AucQB3sdU9+iRrOjwuSg9KL2pW9UcX72mUH8FUlweDrJIIyKqAIoOgz4EmV
         PFNU4gsG3hpkJhQcMpXv6mopiz/esW8uMdRIAMqkhJzi3pEyi022LgNnQPhrnrdx0uGG
         Ug4A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NGM0s3bz;
       spf=pass (google.com: domain of 30c9zxwgkcdg74pc7aiqaiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=30c9ZXwgKCdg74PC7AIQAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id l38si301747qta.5.2020.09.10.00.03.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Sep 2020 00:03:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of 30c9zxwgkcdg74pc7aiqaiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id 205so2976128qkd.2
        for <kasan-dev@googlegroups.com>; Thu, 10 Sep 2020 00:03:45 -0700 (PDT)
Sender: "davidgow via sendgmr" <davidgow@spirogrip.svl.corp.google.com>
X-Received: from spirogrip.svl.corp.google.com ([2620:15c:2cb:201:42a8:f0ff:fe4d:3548])
 (user=davidgow job=sendgmr) by 2002:ad4:42b3:: with SMTP id
 e19mr7817774qvr.6.1599721425010; Thu, 10 Sep 2020 00:03:45 -0700 (PDT)
Date: Thu, 10 Sep 2020 00:03:27 -0700
In-Reply-To: <20200910070331.3358048-1-davidgow@google.com>
Message-Id: <20200910070331.3358048-3-davidgow@google.com>
Mime-Version: 1.0
References: <20200910070331.3358048-1-davidgow@google.com>
X-Mailer: git-send-email 2.28.0.526.ge36021eeef-goog
Subject: [PATCH v13 2/5] KUnit: KASAN Integration
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
 header.i=@google.com header.s=20161025 header.b=NGM0s3bz;       spf=pass
 (google.com: domain of 30c9zxwgkcdg74pc7aiqaiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=30c9ZXwgKCdg74PC7AIQAIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--davidgow.bounces.google.com;
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
Tested-by: Andrey Konovalov <andreyknvl@google.com>
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
2.28.0.526.ge36021eeef-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200910070331.3358048-3-davidgow%40google.com.

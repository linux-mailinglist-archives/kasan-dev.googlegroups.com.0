Return-Path: <kasan-dev+bncBC6OLHHDVUOBBG66ZD4QKGQEPO5OYMQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 3CB84241604
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Aug 2020 07:39:41 +0200 (CEST)
Received: by mail-pf1-x437.google.com with SMTP id 4sf9601611pfd.23
        for <lists+kasan-dev@lfdr.de>; Mon, 10 Aug 2020 22:39:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597124379; cv=pass;
        d=google.com; s=arc-20160816;
        b=EafpX03OLCbQxGcombbxGNOJC5bJR1VPSGaCIzKsQIKN9ysQvBhVeTU/WHbzDs4w0l
         0AjqbsxOIFURQlAInpk7f76eiO71jXDjfg3pF3J07wM+GcvaVj6mOsId6dpdkXVrsIwU
         4gikmEE+A3Aj3JQFX3AJ1i9AKRDDFLCK+xTlSMsU2KqatjzElMWt7F5WE9raEykCk5fc
         NTHioH86O2TO3hjiODk7EFnjyKeubd6J1fRTzYaD6523z/Cq2Knz8LyIMrEs+nlAvCPY
         JG/xnQbwrHT9TRGILt5KuDHP3mboetqNRistx8ItFZ4TJQTIdLq8QDjrNz+hY/Q44Ktf
         Kq0g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=aTn2hMcwjtGewU4L0/g5uRbbcJUpYfi66JQa/1wQfZQ=;
        b=Mx2+8qncNr7f4b69sE7fgpu6Gn+GRNtVEfDad8ZdKPt/pN2sjC7SGtardAI+/axMY3
         3B7EkvCU9mVIvF1iv/sdvpqCcVqpBU4l+kW1eoKmiRWDXcmJrkTtDiJBsxdFtH5LYofQ
         2FNAhYpd5N57QtM+huu2A3tc3Wv4db23ze0GnW0Sww2CeLQnBfup0LPUkMLV2260ZMwm
         COqbXOpDIiRKRObSRQL2W726uAELEQytdOLy+nA/WEZUSGPnZ+Su0CQPITmXaBygV28s
         JyzEM78kML9mHl7V+BnKPd0Ufkf+B9tCVyMd5U3RQOXDq96v091PDn3cRQVuFgR03XdN
         Iufg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=adeVaIMD;
       spf=pass (google.com: domain of 3gi8yxwgkcuegdylgjrzjrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::449 as permitted sender) smtp.mailfrom=3Gi8yXwgKCUEgdylgjrzjrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aTn2hMcwjtGewU4L0/g5uRbbcJUpYfi66JQa/1wQfZQ=;
        b=GxMXd/Xih6+FYFwXckj5Ya/trQzHTKzAugC5GYd+hHbaJaUTy5GCBlHKTGQHv8LyRe
         ZmDxSSNgA3NaVoYy8OCc+1oOo8S3Y8nGHMKTsKT/9lTso8AsongW4Gd0Yo1BLw96GElI
         i6X2SJfcpKCV6nnbuZMRMILXxmH+tvj8QZVzhOp8BEFegEgMuQTik6OcE21zbOlpVn45
         R6btoJWU4V3b2dTnVADlWEfwJadGFULzKqgc2bqmUgowp23L9xc3UzbBV+8lnMgsdg2b
         A6ANiPpdOmi4mKwb8AD858Tj9uEUs6HIGpZ9LcXwfJiBeKtJ/wnkRShR3cDhm78CEOWE
         qmBw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=aTn2hMcwjtGewU4L0/g5uRbbcJUpYfi66JQa/1wQfZQ=;
        b=jnCUlqoHVlaIrcL+aEPQHuYBp2UuW1FGoGTgS7mUZisazj1hZRrLcHzctLEYVeLqWc
         3xz9BSN8004k5DCwHR+UScNl4l1AV0iGXv3OrqcIhj6WbW6T44iIO4ecOg38tEuQZqcD
         5vJgPo6czCI0Gh5SiixGg9WK1WK2P3g7TQH6OjAqzFJpyq4Zg7qIZvwzVGHa5rFEGe27
         Z4rFmrO8lhqkaj34W4i5lYvN/GqhyC2hYK2U9nPTqaVNBaUkRYw6E7uPaCK0AttzzTi9
         dxgKowoiE7YdcQZBPlPtWjqtDbBacfSUzVSalCZ5k44mXG0Eh68CR1FvFoILKjxazQxd
         gJfQ==
X-Gm-Message-State: AOAM533X0MIgAHEPj6DcssK87H0+OSIUHebh0NRszG9Txm2tS7RDFYjx
	lPuJr/sBrSjv3WGazUngL5I=
X-Google-Smtp-Source: ABdhPJx49YlyA7KfqlL/H1DmmEgtz4z0EN7BHk+p/HVaa8EQqRFksXMhYqUUI5FGI/qG5nqG9Exq7A==
X-Received: by 2002:a65:438c:: with SMTP id m12mr24236493pgp.373.1597124379684;
        Mon, 10 Aug 2020 22:39:39 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:534d:: with SMTP id w13ls4866906pgr.8.gmail; Mon, 10 Aug
 2020 22:39:39 -0700 (PDT)
X-Received: by 2002:a63:5350:: with SMTP id t16mr16155756pgl.35.1597124379164;
        Mon, 10 Aug 2020 22:39:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597124379; cv=none;
        d=google.com; s=arc-20160816;
        b=WSiJxcXtlFVG2Uwhz6Vw2muXffXIzwFRhnBHcnw9QZZRYCM4eFr9n221rziqU0XjW6
         HAO27FyPM95XMLWZIy0gR01VRthshqL0uQanNlcbb+zL7hw0XReJhuZqnqnio8daZCKc
         ou+Y684v6wKdsvOoVjw8QqTq8fADC0bRe4r7QlNMGiKborHxOI/3KbnKnBp/YVCq8AS0
         PkEBZH2ookeomlbtfuS0gM5YEnyQRqkfGuBKZiMNbZ/PKgN9Qi7UWo5FnZt+s9j0Qwwm
         dHAY9gyUqq4AnbUJYZEuYAMbvHzHWzaIIHjkaoS9hjOEcftpnbazYu9bCYbhULrBLXb6
         0NSA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=mmCjcomi9llkyxIDKndpWK4qy9qeHrJlm3x7Fs8tnIE=;
        b=P1KaS6u3LQ/KAoU7RN+7zHSyVGMmgh8ZpvCvVjCOrkxrD6pY8hWMV5T95j2u6aBEPb
         neEXDHu5pSB371FbuVoc18jFi3viLFlx1NUFpclAGCj6WVYzYBpn9BVKq5P65977LNfF
         3q51SAMbEL5cbqPQPtDysOHzSR+7odsOIVuw9sU9wXfFOPNIDn1opTt4TOMs47Nb/6Al
         oTBWAL33la+9gqj/U9+pV+kmIkZzE4EoyvNoJlf/Axo6uc8XmFmkKkgBdlLu2O9IIeI7
         x3r+pDAoXXp2pesi2YhrKlIgdAPszbdtp1KmkhpzHflCSw1gm8F66TbC8mqk6d+gyLHb
         un5A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=adeVaIMD;
       spf=pass (google.com: domain of 3gi8yxwgkcuegdylgjrzjrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::449 as permitted sender) smtp.mailfrom=3Gi8yXwgKCUEgdylgjrzjrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x449.google.com (mail-pf1-x449.google.com. [2607:f8b0:4864:20::449])
        by gmr-mx.google.com with ESMTPS id n3si96959pjb.3.2020.08.10.22.39.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 10 Aug 2020 22:39:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3gi8yxwgkcuegdylgjrzjrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::449 as permitted sender) client-ip=2607:f8b0:4864:20::449;
Received: by mail-pf1-x449.google.com with SMTP id b142so9656448pfb.9
        for <kasan-dev@googlegroups.com>; Mon, 10 Aug 2020 22:39:39 -0700 (PDT)
X-Received: by 2002:a17:90a:3488:: with SMTP id p8mr381649pjb.1.1597124378453;
 Mon, 10 Aug 2020 22:39:38 -0700 (PDT)
Date: Mon, 10 Aug 2020 22:39:11 -0700
In-Reply-To: <20200811053914.652710-1-davidgow@google.com>
Message-Id: <20200811053914.652710-3-davidgow@google.com>
Mime-Version: 1.0
References: <20200811053914.652710-1-davidgow@google.com>
X-Mailer: git-send-email 2.28.0.236.gb10cc79966-goog
Subject: [PATCH v12 2/6] KUnit: KASAN Integration
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
 header.i=@google.com header.s=20161025 header.b=adeVaIMD;       spf=pass
 (google.com: domain of 3gi8yxwgkcuegdylgjrzjrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::449 as permitted sender) smtp.mailfrom=3Gi8yXwgKCUEgdylgjrzjrrjoh.frpndvdq-ghyjrrjohjurxsv.frp@flex--davidgow.bounces.google.com;
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
2.28.0.236.gb10cc79966-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200811053914.652710-3-davidgow%40google.com.

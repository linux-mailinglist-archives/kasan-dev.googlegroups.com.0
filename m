Return-Path: <kasan-dev+bncBDK3TPOVRULBBSVRSP2AKGQEXC6DLWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x838.google.com (mail-qt1-x838.google.com [IPv6:2607:f8b0:4864:20::838])
	by mail.lfdr.de (Postfix) with ESMTPS id D464F19B51F
	for <lists+kasan-dev@lfdr.de>; Wed,  1 Apr 2020 20:09:15 +0200 (CEST)
Received: by mail-qt1-x838.google.com with SMTP id x10sf607017qts.14
        for <lists+kasan-dev@lfdr.de>; Wed, 01 Apr 2020 11:09:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1585764554; cv=pass;
        d=google.com; s=arc-20160816;
        b=ZibmJL1pipmViT8GiuwmwLD52HAu4RHAwvbbdy+nu9SPUvKvuFDGFC43ZqEi5ElOWv
         +N8WxXoX8JTyF68xTiQRD66wrbdRckit87UUEWWd4xMJ9jCv0H6Y5xp/0xWTxk8rqy/E
         ar+GidcEEGUCKTja37Hds1SptcKcN7FljpYt795UCRWjVp7FefnKFTPsoGyXEtlbZX9I
         PBzId2qArM+NI1Crjx2kMmUPxYjv9gjkc0KQw9WpsSKQWvOE9+SCdUXFkPJkAw9d7r9C
         fqDhO9qLb799zPlfhMWmuqrWzVT1a1dvz/tk8H8MZ6IDknFjWVRw7srkfV+ZF5yUv4ga
         SNRQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=DINmGvpVoqPFVUrORSR/j1cDNkP5CMt1CshLz9d2U0A=;
        b=u3TjdoTZbSm9kap/Qm/OpHxBGXjqae36sEQGs+iD7lsXHfCXGRwEuX8CasbM7SAzBn
         N32udCvRJd2d5rIY491jYGzdmFEwueFKaf5XL81YH+zCmK+rkNDdvcDfNleXXe+8SIsv
         ILjvAR+TV8ZctRchOz0rYG2JXFp6MW68CMUoAJZZOEMgakdnyfcetQVyHBPav+ED9+IF
         fuw4CR/5Qz8bVKbBt1+z9kJ3BODnjPYVIq2aRzXaLLFUzQo8lS6ddtvnI4X209Adcp/w
         flFeFqPBKuLDeaRuTE5KiPRmDwJjETSfNlEQAZ/3UOrbao/vTHcXZwT8eLV6qeCh2sm0
         KMKg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QLz1ACgI;
       spf=pass (google.com: domain of 3ydiexgwkcyg53u4tmxr0z40s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--trishalfonso.bounces.google.com designates 2607:f8b0:4864:20::44a as permitted sender) smtp.mailfrom=3ydiEXgwKCYg53u4tmxr0z40s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--trishalfonso.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DINmGvpVoqPFVUrORSR/j1cDNkP5CMt1CshLz9d2U0A=;
        b=PJIWYH/ojKMRJc/blozo8NqmSyZNhA7Q/d2fduHD2ZYTYd9Jt2kTA+pNY78ga3cFCz
         FzGY6oCiofck2JvmJ3vbimixqpzkQTjU52t7JTQVVfkRiDM1ytJlUMonAHnZsk7A5mce
         4gFCZ/zq/NdrsuvezX7IoiBbaG7kLroaMN+5x8Oik8X3Jha3QKMbGNWDPa4NeAxWO/fa
         ZKfKfqjRquRp9w7JIY5Gm+Gc8CPCS6kebdDnB3prseP9XouPzQwVnpFGESsbK9BJGOJP
         z89q9c+ezgFFALhbTj6sOj1lwQf758xMZoVNoIroendciZaFh/a515hRPCvRvTNCYVwu
         Eu5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=DINmGvpVoqPFVUrORSR/j1cDNkP5CMt1CshLz9d2U0A=;
        b=A52+cf+1fT1mYcAzsJR4M8XnCgNIgF1ih6pk/8U+Ci4FpJEpZ1zMs7EF/nfAN5VEwL
         ndeXUfmdZWeTgMiUT2/Jy1ppOtIjnzLIN0kLNq37YPRJrMsUQNKfRzv2FMzrMP7ONA1e
         Xx2zbNG12JN1/fTjloeeUkUnFeqSSUlPiQ30RAnlSYQviIHYFY9m+wYA14STshTnYDEc
         WsZGiDPHh4twkmvwvpGJjN9fYrm75MiKNWHkkVlgSx1j/mUnCl+ankesapno5fsKcbuI
         YYCW6hyg9UZyZQN4hYvNoclVYufWHJ8RBblfDtqblvrh4gAYjIey92nHYUe886/bxQmQ
         mxog==
X-Gm-Message-State: ANhLgQ0pdFKV9ZkbfEy6EtqyRFMvSaEqzrBkfVAW8F0hzUTnixd4+hTO
	pDkl3jMXPkzx0bWnGw9E7sY=
X-Google-Smtp-Source: ADFU+vsmvarwdt+HfUNNKMlNvJCM9gSIkGv6+ZwHVhovA+F1Gt5HwJpezUBvztkYLloIISz4jmKNDw==
X-Received: by 2002:ad4:58b3:: with SMTP id ea19mr23315992qvb.8.1585764554773;
        Wed, 01 Apr 2020 11:09:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ae9:dc83:: with SMTP id q125ls240693qkf.9.gmail; Wed, 01 Apr
 2020 11:09:14 -0700 (PDT)
X-Received: by 2002:a37:9e56:: with SMTP id h83mr11709905qke.389.1585764554304;
        Wed, 01 Apr 2020 11:09:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1585764554; cv=none;
        d=google.com; s=arc-20160816;
        b=wtRIC8kG6nwYiejyMRSqyeneY1NO6QpqKEzMRvjvngPoFyySaez81C3FrIUv92maeL
         r3NYFiWRIfqvT9RGGi/HpJIlUh/jeCXmsZFwx24ClfbZS5GoD+bepB1a42ZliWBZ3oEZ
         GCLzQI4/OgwlV8o2f2q+7J3oxCnJXVjpE9B5SDM57HI6AGnemR0wmDQyUMPQftvDIlmt
         pwP4WNI/Spv5Q45Y3ClPd/f2r/73wQvPL0NtkCBB5hDbIYCsjf3G/QpFbYlWb8Ff4iBy
         2TAkdxu8aSNn3xkyPgn9ndCNAhKwhggE8k+RZp55kGTmVMJpmWMYjPIllW5v2htRJJuv
         h+2w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=dfj6qndQNIOdNolD9suMom+D63tUGLQMMKawugGabdI=;
        b=1EJ1zqZiJetGh1Jr74Q/QJLuodSITskrc+YMVriNeZlLIZ/EcaP8NbByoVRINeazHx
         K+ft+ecVON2y/0f/QoS+PhO5/SZqGtEHyTuIMkJZFfgPekOC7Og/q6xtqjPrXcRg/mSU
         PftdjuAU4cSe6kjdRXD5wdTfhNEVGoGWd/pS2JcUCFSOJg1f6WTDhV+bPZBoyVJgT+tm
         qcF3t8VqQK3hkXvC7h0JMwfweMZXHUFbLbdGoGsajJtDmtt2gXk6Fjwfs5yetk1HMdCG
         wDV6biQrrVjD31mDoeVd35oVsdS0yjGhZ9h9fr2xcA3ju/vZvqxMULS/4CsTKxCdCZ01
         N4sw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=QLz1ACgI;
       spf=pass (google.com: domain of 3ydiexgwkcyg53u4tmxr0z40s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--trishalfonso.bounces.google.com designates 2607:f8b0:4864:20::44a as permitted sender) smtp.mailfrom=3ydiEXgwKCYg53u4tmxr0z40s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--trishalfonso.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x44a.google.com (mail-pf1-x44a.google.com. [2607:f8b0:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id x11si176415qka.4.2020.04.01.11.09.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 01 Apr 2020 11:09:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ydiexgwkcyg53u4tmxr0z40s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--trishalfonso.bounces.google.com designates 2607:f8b0:4864:20::44a as permitted sender) client-ip=2607:f8b0:4864:20::44a;
Received: by mail-pf1-x44a.google.com with SMTP id y84so334662pfb.7
        for <kasan-dev@googlegroups.com>; Wed, 01 Apr 2020 11:09:14 -0700 (PDT)
X-Received: by 2002:a17:90a:a40b:: with SMTP id y11mr6542493pjp.130.1585764553740;
 Wed, 01 Apr 2020 11:09:13 -0700 (PDT)
Date: Wed,  1 Apr 2020 11:09:04 -0700
In-Reply-To: <20200401180907.202604-1-trishalfonso@google.com>
Message-Id: <20200401180907.202604-2-trishalfonso@google.com>
Mime-Version: 1.0
References: <20200401180907.202604-1-trishalfonso@google.com>
X-Mailer: git-send-email 2.26.0.rc2.310.g2932bb562d-goog
Subject: [PATCH v3 2/4] KUnit: KASAN Integration
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
 header.i=@google.com header.s=20161025 header.b=QLz1ACgI;       spf=pass
 (google.com: domain of 3ydiexgwkcyg53u4tmxr0z40s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--trishalfonso.bounces.google.com
 designates 2607:f8b0:4864:20::44a as permitted sender) smtp.mailfrom=3ydiEXgwKCYg53u4tmxr0z40s00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--trishalfonso.bounces.google.com;
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
     	- Use KUNIT_EXPECT_KASAN_FAIL to expect a KASAN error in KASAN tests
     	- Expected KASAN reports pass tests and are still printed when run
     	without kunit_tool (kunit_tool still bypasses the report due to the
	test passing)
     	- KUnit struct in current task used to keep track of the current test
     	from KASAN code

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
---
 include/kunit/test.h  |  5 +++++
 include/linux/kasan.h |  6 ++++++
 lib/kunit/test.c      | 13 ++++++++-----
 lib/test_kasan.c      | 37 +++++++++++++++++++++++++++++++++++++
 mm/kasan/report.c     | 33 +++++++++++++++++++++++++++++++++
 5 files changed, 89 insertions(+), 5 deletions(-)

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
index 3872d250ed2c..cf73c6bee81b 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -23,6 +23,43 @@
 
 #include <asm/page.h>
 
+#include <kunit/test.h>
+
+struct kunit_resource resource;
+struct kunit_kasan_expectation fail_data;
+
+#define KUNIT_SET_KASAN_DATA(test) do { \
+	fail_data.report_expected = true; \
+	fail_data.report_found = false; \
+	kunit_add_named_resource(test, \
+				NULL, \
+				NULL, \
+				&resource, \
+				"kasan_data", &fail_data); \
+} while (0)
+
+#define KUNIT_DO_EXPECT_KASAN_FAIL(test, condition) do { \
+	struct kunit_resource *resource; \
+	struct kunit_kasan_expectation *kasan_data; \
+	condition; \
+	resource = kunit_find_named_resource(test, "kasan_data"); \
+	kasan_data = resource->data; \
+	KUNIT_EXPECT_EQ(test, \
+			kasan_data->report_expected, \
+			kasan_data->report_found); \
+	kunit_put_resource(resource); \
+} while (0)
+
+/**
+ * KUNIT_EXPECT_KASAN_FAIL() - Causes a test failure when the expression does
+ * not cause a KASAN error.
+ *
+ */
+#define KUNIT_EXPECT_KASAN_FAIL(test, condition) do { \
+	KUNIT_SET_KASAN_DATA(test); \
+	KUNIT_DO_EXPECT_KASAN_FAIL(test, condition); \
+} while (0)
+
 /*
  * Note: test functions are marked noinline so that their names appear in
  * reports.
diff --git a/mm/kasan/report.c b/mm/kasan/report.c
index 5ef9f24f566b..87330ef3a99a 100644
--- a/mm/kasan/report.c
+++ b/mm/kasan/report.c
@@ -32,6 +32,8 @@
 
 #include <asm/sections.h>
 
+#include <kunit/test.h>
+
 #include "kasan.h"
 #include "../slab.h"
 
@@ -455,12 +457,38 @@ static bool report_enabled(void)
 	return !test_and_set_bit(KASAN_BIT_REPORTED, &kasan_flags);
 }
 
+#if IS_ENABLED(CONFIG_KUNIT)
+void kasan_update_kunit_status(struct kunit *cur_test)
+{
+	struct kunit_resource *resource;
+	struct kunit_kasan_expectation *kasan_data;
+
+	if (kunit_find_named_resource(cur_test, "kasan_data")) {
+		resource = kunit_find_named_resource(cur_test, "kasan_data");
+		kasan_data = resource->data;
+		kasan_data->report_found = true;
+
+		if (!kasan_data->report_expected)
+			kunit_set_failure(current->kunit_test);
+		else
+			return;
+	} else
+		kunit_set_failure(current->kunit_test);
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
@@ -481,6 +509,11 @@ void __kasan_report(unsigned long addr, size_t size, bool is_write, unsigned lon
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
2.26.0.rc2.310.g2932bb562d-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200401180907.202604-2-trishalfonso%40google.com.

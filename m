Return-Path: <kasan-dev+bncBDK3TPOVRULBBB6CZ3ZQKGQEDWO7H3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id A397C18BCE3
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Mar 2020 17:42:48 +0100 (CET)
Received: by mail-qt1-x83a.google.com with SMTP id i36sf3244878qtd.9
        for <lists+kasan-dev@lfdr.de>; Thu, 19 Mar 2020 09:42:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1584636167; cv=pass;
        d=google.com; s=arc-20160816;
        b=cnjJxCVfQkIVhmJnYSTtOt5pAQgubAR7Uj5eDVZE5PzlP3CJgh2ylrBc67YxPEOrss
         oT73dLLfw9dRb4UObwL0Pbo4BNqf3jYuIZvWUrJfHLJ2uyCgdOskc37+/kvlEwb8WWbe
         OzuAoTp4akDLcemIOcyFLdldrE1fX8FUYUxGjyevdT8LkN/7aoy52btfhbNTJyKL2Hic
         FJEDlufDWifoQu0WLjETnqXq8OvV1+YGBbZgqPEyHi264JnQ0Dc1RrlQdM/YCI/ecVU0
         3+WQCtQR6rJu7waVZUh8h5Iy1GcyrKC80NLyuGDlnpSrLb/VI5Ms2Ry0e+KAmVKd2el9
         hQnQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=PWcOh1ypqldKS+XtpC6gI1Sc1W1e3OJsCuebBAvgtzI=;
        b=hMkcZEEfDEn2jDlLG1S7g4dBFiSnlbUfqJxUwSOT61nPrOil0VcMtPXxSDlvEwMhOs
         smjYzrB34EoBrvDWWQ6K05nJrbDQzlBxHGtpxQ5QG3//cHylcDgAl5tDhZSaotW3rr1c
         6in/CNW/aoyalU7zixDjgZozH1cHqR2GnJ+q7XTlFtjFhpsTUYkZ0DxWDkul9f8ahN8N
         Vclxn/+CPpTS+0f0AUWT8+F/70PRC9Lmu/yw8dAzPB5DEC2av0rwAyUBpBplkvEPZI/4
         /v4YES5pFKFxyHKVXKKMAVEt4qHUykPaR4YxrkMRmWziM9R2ZjZ0i4pr9BGlMwoa4FIL
         YqJA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=hdDV9H3L;
       spf=pass (google.com: domain of 3bqfzxgwkcrea8z9yr2w5495x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--trishalfonso.bounces.google.com designates 2607:f8b0:4864:20::104a as permitted sender) smtp.mailfrom=3BqFzXgwKCREA8z9yr2w5495x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--trishalfonso.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PWcOh1ypqldKS+XtpC6gI1Sc1W1e3OJsCuebBAvgtzI=;
        b=pdx3APccYRdIzVjhpRVantoNDBZTd8xrU4SfUSjlJGl55dpPUyww0uJ8+8goAi+Yu1
         e4MhdPlcSebCJG0rnsmFZnvpAeTNyLc4Svyo7SKXNqVbjVL77hX40gLEbvhJm8hXKC+K
         oHfi5oUvQDHnRl/W/gSIRChVgJmF3bTSSaM2LdvSmRm348WfXFBDvWPWX+8iU4STeQfS
         UoVEpbjPD7+5Maanbe33Y4xETaAN2DMnLf9XZTYJdiFf9EcppsOs8RDeEJZ++CpBDxQi
         NRXg/DA3VLgfwpt30F5BnRdCnXjCRhgbASNfCLh0NqeRdLt6UbgOUW133IUmYyTf2nHf
         jA7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=PWcOh1ypqldKS+XtpC6gI1Sc1W1e3OJsCuebBAvgtzI=;
        b=T7ONFcxD++FAqYtm+QvkbGOFOIEcRG2fmtopuQ6TwXoY9j9UJFdxftxx4noHUWhvLW
         bF/geDBuGzrmiMrXSogY/AS4ICI2peRH7KRyhsQRryE+hUrX9+4B/SP3ABE0zGygxmRD
         UK9uaSHwzk/Lz3cI008OoYWdBnZxic5IcYwW6F1wMTy5LJsKz7xV6nELDhFn0VzeQxNy
         WViWE0wWxl8XTnLnOBFgeI1lpCoiPJvOi4c1KEBRKy/wDojip4A6c6nhojRhAEq/0iaK
         tNbNfGquFlQmP69ebPKoN/9JVxRcePdMV3OD13/66tC+L4tgVe9+dQd81g+MN1NEYMhR
         uuqA==
X-Gm-Message-State: ANhLgQ1JOlNSvWNFsA6u5Ec76/xgWS72RwhDoqKeplqB0/gJ/FRnFYi/
	0YSNvQ06RSMQ9N9FfyDYTdQ=
X-Google-Smtp-Source: ADFU+vt8YCpvNQ8IMxJ/bAxE+nY0WJmMs2lJn/aJrJzSDpu1rFgNrzuSHKGR7rcJGZJi+Cjm1coXbQ==
X-Received: by 2002:ad4:5994:: with SMTP id ek20mr3844829qvb.93.1584636167723;
        Thu, 19 Mar 2020 09:42:47 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:645:: with SMTP id 66ls1568871qkg.9.gmail; Thu, 19 Mar
 2020 09:42:47 -0700 (PDT)
X-Received: by 2002:a05:620a:20c2:: with SMTP id f2mr3996697qka.296.1584636167339;
        Thu, 19 Mar 2020 09:42:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1584636167; cv=none;
        d=google.com; s=arc-20160816;
        b=RL8ig831kU5KGOVc+P6xCFkn4RTN5xecLY5FKket40Y6z345qg4bMZYTPzAbcnSM24
         r36hUZ3qPBo0ulHtf7l/IdpuyaKeRoaKZBX+ubJ5CrxF/VDzNEFehxZjWODQBVrGZtyh
         ix3hLr2L3rWU0QqLVGB2ZJMPJl5vL3B21YDFhoILgvAK4A7dX4l2+AhnV6PvHHXnF6uv
         PH2U0xYxHDMNlKxbl7br7iNQIGO1kazfd3CySQYXphwVAsKvLYpJj2w+xegseFjERh23
         XiyHjuSmFYVlpNXk7ImP6/MQGpcYK980h62LlhZuTyCBdIDEFdg9rXuinVE9W3PRqJvn
         /sZg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=Xrj+8qNx0KoAn4W34u+9YgQgrTU26Dej+YkYnDk+H1c=;
        b=MNUOYOTyaUUPLNi9G+S8ZmTg7gPwSrN1X+i+bZP9S1iT1Y1ppEOTlpYMnud0jSOuOO
         u1rj4WvIZATp3gEAensST9qd5DfPMrLPKMM/hXX37jU6fDmTLiRWCaJy0PskSqkgfbyJ
         f8efzLfK1/qcnWYNaIDvazISOhm3dkfJCJnp7TcnrAf3IOQXICWxw4RcuPJS939e+1bk
         ld90W84s89z8+J4QcRHwXSFHkVNRwENVSQ9LyTy/5a05uJq2wjTQdNaNyyPkUa5PrbzS
         5gZtZ3Vw7p6X1Iz22KdHK+YmQtA/0wgUgPvQsDfVzB74QXfrmTKX08qWex6WI1d429yb
         962g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=hdDV9H3L;
       spf=pass (google.com: domain of 3bqfzxgwkcrea8z9yr2w5495x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--trishalfonso.bounces.google.com designates 2607:f8b0:4864:20::104a as permitted sender) smtp.mailfrom=3BqFzXgwKCREA8z9yr2w5495x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--trishalfonso.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pj1-x104a.google.com (mail-pj1-x104a.google.com. [2607:f8b0:4864:20::104a])
        by gmr-mx.google.com with ESMTPS id z126si170840qkd.2.2020.03.19.09.42.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 19 Mar 2020 09:42:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3bqfzxgwkcrea8z9yr2w5495x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--trishalfonso.bounces.google.com designates 2607:f8b0:4864:20::104a as permitted sender) client-ip=2607:f8b0:4864:20::104a;
Received: by mail-pj1-x104a.google.com with SMTP id t7so1877101pjb.9
        for <kasan-dev@googlegroups.com>; Thu, 19 Mar 2020 09:42:47 -0700 (PDT)
X-Received: by 2002:a17:90a:628a:: with SMTP id d10mr4805164pjj.25.1584636166443;
 Thu, 19 Mar 2020 09:42:46 -0700 (PDT)
Date: Thu, 19 Mar 2020 09:42:26 -0700
In-Reply-To: <20200319164227.87419-1-trishalfonso@google.com>
Message-Id: <20200319164227.87419-3-trishalfonso@google.com>
Mime-Version: 1.0
References: <20200319164227.87419-1-trishalfonso@google.com>
X-Mailer: git-send-email 2.25.1.696.g5e7596f4ac-goog
Subject: [RFC PATCH v2 2/3] KUnit: KASAN Integration
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
 header.i=@google.com header.s=20161025 header.b=hdDV9H3L;       spf=pass
 (google.com: domain of 3bqfzxgwkcrea8z9yr2w5495x55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--trishalfonso.bounces.google.com
 designates 2607:f8b0:4864:20::104a as permitted sender) smtp.mailfrom=3BqFzXgwKCREA8z9yr2w5495x55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--trishalfonso.bounces.google.com;
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

Make use of "[RFC PATCH kunit-next 1/2] kunit: generalize
kunit_resource API beyond allocated resources" and "[RFC PATCH
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
 include/kunit/test.h | 10 ++++++++++
 lib/kunit/test.c     | 10 +++++++++-
 lib/test_kasan.c     | 37 +++++++++++++++++++++++++++++++++++++
 mm/kasan/report.c    | 33 +++++++++++++++++++++++++++++++++
 4 files changed, 89 insertions(+), 1 deletion(-)

diff --git a/include/kunit/test.h b/include/kunit/test.h
index 70ee581b19cd..2ab265f4f76c 100644
--- a/include/kunit/test.h
+++ b/include/kunit/test.h
@@ -19,9 +19,19 @@
 
 struct kunit_resource;
 
+#ifdef CONFIG_KASAN
+/* kasan_data struct is used in KUnit tests for KASAN expected failures */
+struct kunit_kasan_expectation {
+	bool report_expected;
+	bool report_found;
+};
+#endif /* CONFIG_KASAN */
+
 typedef int (*kunit_resource_init_t)(struct kunit_resource *, void *);
 typedef void (*kunit_resource_free_t)(struct kunit_resource *);
 
+void kunit_set_failure(struct kunit *test);
+
 /**
  * struct kunit_resource - represents a *test managed resource*
  * @data: for the user to store arbitrary data.
diff --git a/lib/kunit/test.c b/lib/kunit/test.c
index 86a4d9ca0a45..3f927ef45827 100644
--- a/lib/kunit/test.c
+++ b/lib/kunit/test.c
@@ -10,11 +10,12 @@
 #include <linux/kernel.h>
 #include <linux/kref.h>
 #include <linux/sched/debug.h>
+#include <linux/sched.h>
 
 #include "string-stream.h"
 #include "try-catch-impl.h"
 
-static void kunit_set_failure(struct kunit *test)
+void kunit_set_failure(struct kunit *test)
 {
 	WRITE_ONCE(test->success, false);
 }
@@ -237,6 +238,10 @@ static void kunit_try_run_case(void *data)
 	struct kunit_suite *suite = ctx->suite;
 	struct kunit_case *test_case = ctx->test_case;
 
+#if (IS_ENABLED(CONFIG_KASAN) && IS_BUILTIN(CONFIG_KUNIT))
+	current->kunit_test = test;
+#endif /* IS_ENABLED(CONFIG_KASAN) && IS_BUILTIN(CONFIG_KUNIT) */
+
 	/*
 	 * kunit_run_case_internal may encounter a fatal error; if it does,
 	 * abort will be called, this thread will exit, and finally the parent
@@ -590,6 +595,9 @@ void kunit_cleanup(struct kunit *test)
 		spin_unlock(&test->lock);
 		kunit_remove_resource(test, res);
 	}
+#if (IS_ENABLED(CONFIG_KASAN) && IS_BUILTIN(CONFIG_KUNIT))
+	current->kunit_test = NULL;
+#endif /* IS_ENABLED(CONFIG_KASAN) && IS_BUILTIN(CONFIG_KUNIT)*/
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
index 5ef9f24f566b..ef3d0f54097e 100644
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
 
+#if IS_BUILTIN(CONFIG_KUNIT)
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
+#endif /* IS_BUILTIN(CONFIG_KUNIT) */
+
 void kasan_report_invalid_free(void *object, unsigned long ip)
 {
 	unsigned long flags;
 	u8 tag = get_tag(object);
 
 	object = reset_tag(object);
+
+#if IS_BUILTIN(CONFIG_KUNIT)
+	if (current->kunit_test)
+		kasan_update_kunit_status(current->kunit_test);
+#endif /* IS_BUILTIN(CONFIG_KUNIT) */
+
 	start_report(&flags);
 	pr_err("BUG: KASAN: double-free or invalid-free in %pS\n", (void *)ip);
 	print_tags(tag, object);
@@ -481,6 +509,11 @@ void __kasan_report(unsigned long addr, size_t size, bool is_write, unsigned lon
 	if (likely(!report_enabled()))
 		return;
 
+#if IS_BUILTIN(CONFIG_KUNIT)
+	if (current->kunit_test)
+		kasan_update_kunit_status(current->kunit_test);
+#endif /* IS_BUILTIN(CONFIG_KUNIT) */
+
 	disable_trace_on_warning();
 
 	tagged_addr = (void *)addr;
-- 
2.25.1.696.g5e7596f4ac-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200319164227.87419-3-trishalfonso%40google.com.

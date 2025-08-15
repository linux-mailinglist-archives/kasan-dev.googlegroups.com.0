Return-Path: <kasan-dev+bncBDQ67ZGAXYCBBJU37TCAMGQETAXFPUA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id B3F35B27E5E
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Aug 2025 12:36:24 +0200 (CEST)
Received: by mail-qv1-xf3f.google.com with SMTP id 6a1803df08f44-70a9f5b078bsf20215756d6.3
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Aug 2025 03:36:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755254183; cv=pass;
        d=google.com; s=arc-20240605;
        b=LoQrtbDP1YTIgZAtRoisz5a2hPtswxsqmdDVqXXJIwICdc3DW4p/vombCKmpQbpPEk
         0XypPSkpUm7BACb75+zlyYRV4loLIdSgg+2MlTNFJrUC6kjeb0c5AIJm9mqhHLqaro5C
         MX9IpQnjfyI5dppLYvMTQI6aWsoSI0owqvra2xDHAJVSnO+MUsIMVJLpe6woI9Lbamt0
         n+DLrhhRIF262SuGCLwd1WNWWL+ie+98ogSqaduORppY29o0Z0osTSgMh6GvBE+GxGsm
         Mo0/wjSqjOg8NGcR2i/f30RJGtuMrX9UZsAPZd/1flIIhchCD9JZt0+hTQvlTLIRAcBq
         RiPw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=oB7JRB6kzwvsR3QT8AOxc6UENTSQ5XnPTDAod/QIa1E=;
        fh=3TTnaF1kZYYd0LQLIY3VbSKLFWn9DCAxooOM/u+fHl4=;
        b=N5o911TvbW1Q7eIPGYGWIfrskU7C8o7GaV1C+vD4tD3GQQDzpBLL3BIudBgnXppgZi
         0+RXVWC/3veNem0G6Z0GilZy0daitYDgXl0z2Ywb5LwPVwxOPii/03BVNiNQxSoG+Dde
         76fqODV3t9GvgD4H++HC9awyvJfxWg0FNO9MuQt4LHINymtRPnNm/o0UhW1CECZ0nhGU
         /OTzUkDZIFTgYqAj/4rkLjw5VJMvoCjRozF8zzsIJ/AZSAZDcFqUBDKo95jFkje/b6y/
         GREOjea3Y2FxI/e5pYg7wf/QQoRv07AuN14npjFHOI6yuvg8cGTjCMkPtE3NhIsAwCoj
         pRLg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="DkD/6scE";
       spf=pass (google.com: domain of 3pq2faagkcygym3uq7uos00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3pQ2faAgKCYgym3uq7uos00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--marievic.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755254183; x=1755858983; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=oB7JRB6kzwvsR3QT8AOxc6UENTSQ5XnPTDAod/QIa1E=;
        b=mTKbwaHOMqutMzTTNp0MwfPFQSgEJCykcQJ36phNOl9qskuwEET86xs9TUkmSF3K3n
         wV8NWXoHvSrUMOqRNSlcJL+sboA3jIr/p9+tMTFh4vCoAX/OSnzYPAQz4amu4NJdOZJg
         rb4GCd3a6EXttksWwMbEhTxzsHsVbGf0x4BpBNXn7t71McdOm4fUyoa5/Pz1NtaoEdwe
         b6HRk73ptYbe5oWcG2igHnxAG8S4ZWOz90kELlD3lam/pum6MB0cKgYuNii7BixwYz2z
         2lbuzZTYYXHwHjCxynNfbmnAMGLgLtdQC4ma79dMQ9r0x+fHxUZG3Cj1RMUHEOZhOk9H
         ixbg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755254183; x=1755858983;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=oB7JRB6kzwvsR3QT8AOxc6UENTSQ5XnPTDAod/QIa1E=;
        b=Venzj30XL4xxGA+nCaKU2NB3v3/bwyswNlHZ25qRQEifmm9zl6rltUFtCNXnVbC8UM
         PZnXSr27H7JW9Sgta96E4HFv4TBoj5nvPkVUjYVrNBY/Ovorh1LDF1FBR2kRlnhPnpdE
         OxZTHnS1brmMM+dHIasGKtTjoVjExOGnMV2xNtHfIjCN2GpH4qXnvJxgIu8UWpEta5UJ
         aK6BAcLGaj485M79aZEWgZEZ+Lbf9xUeC7o/oYAxuw0eMC4raaKcF7H/83YIF4n6xa4g
         2pSQ0wtyq2ADkFuBL/vlbdX0tf/8X2JLxWwBGYYegRo/nqpZY5S8u8RDF3g9fysW3Hwl
         dypw==
X-Forwarded-Encrypted: i=2; AJvYcCXRXh4y6ntD29Hxh9LQrt6Zkz7Wy5nqlerVqcARq+iUSxHsv2qVmyy1E2KPvhvBzBfCa8D9gQ==@lfdr.de
X-Gm-Message-State: AOJu0YzWO8C4d3WCoUX7WjV07tV5cdATwOgOc8FsRpr/fsgVzhSXojz5
	fVt/HXzahY1zlh9qIdeBgf8KOZll0GohEscn3DqhoUXnu3VrtoSQ/7Le
X-Google-Smtp-Source: AGHT+IHkK/WU5l6FVuYZdHqOn06+bW2lTStB9Hg0e1I4wLHJ9P2IExIKarA/qAyTV3rxHoyhoSWwsQ==
X-Received: by 2002:a05:6214:cc6:b0:707:6161:5988 with SMTP id 6a1803df08f44-70ba7a8abccmr15955416d6.7.1755254183123;
        Fri, 15 Aug 2025 03:36:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcve+zylheIhQ3tLXCgKlvOtgB0ypDBq0vixSAPg6nM/Q==
Received: by 2002:a05:6214:d6a:b0:6f8:b2f3:dfb9 with SMTP id
 6a1803df08f44-70ab79eefdbls26103946d6.2.-pod-prod-08-us; Fri, 15 Aug 2025
 03:36:22 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVAbhtPMwoyIdJsgfOyDxoJ1LQYtpYoR/hhaYxob8ZXps3fmtcWe1FgpGPU4mWDtZdUDUhOU/Oy5iE=@googlegroups.com
X-Received: by 2002:a05:6214:242a:b0:70b:a4d2:3687 with SMTP id 6a1803df08f44-70ba7b54337mr16282806d6.21.1755254181849;
        Fri, 15 Aug 2025 03:36:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755254181; cv=none;
        d=google.com; s=arc-20240605;
        b=IV5jFQ6TDQHpiNNvo6yoKAWk4yweYVcKyu1Ad8wPhhAjA+OFgiGcpIYXYu7DNHnD7V
         9/hrZ3++nqyxvkC7QjTOuVhr2rask9dTOYfGppmJRxt6EZeOZBPE+GQ+Wi4NrBgG0jAX
         FWg4X2ThOHjc1yn6OJNfL/5RCNqq7bA/XqHOf/gWQfMo3KVFWLo2ztxDkp6HvgQh1leo
         chzbyGoaQoLs+p0U8ZLomQ5baJqiN6RJEzEWoaviE3SqY4hFuI9h5+k0ttioo/ZwylI8
         DJiVUuoFhs8B7i9FG9vD51830USY7hdl3C4Rditvpu51lWFeYhp89azfqdcxVPt6AnHi
         St1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=RNyqlzYzn7jh+8CRt3OEjX2dauCV97Pxa7UQdJrgoqo=;
        fh=19by5sL3W7L/Ut41DWa2Ng7QBPdfOTO9YCU3jzTUjSU=;
        b=kEX3OhQMg2oxbkV6iJooLu+Nm8dJgmhSZYwUdoUhMfe2gAnFxdLgl0Vj1RZkCdwa5U
         UjmxzqY7nIH9HhPwgjpJ/YrRucdF3bLs95pgE/v5AT7CaYw+Cydn+5bGfCCz9PRZaOnQ
         3kfNHO7eUwkk8CTl1/c35uIvOZBHGBW7g7RIWQQcDqiw3bxxUGiZL5fCXUZJ8vau0im3
         2H2Wnplx1liCXQpX1IR2y9j22Zixpyj1U56rIClNSI8YxOlUAqlB0X3IoGKgyr+8ZZVf
         d2n9Edr2GfPAA3j2lWhZ0aaApHbq5yCe9hgcKqC6EDL1gtX+YccdkdhudYqm5hD5c9jU
         gCfA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="DkD/6scE";
       spf=pass (google.com: domain of 3pq2faagkcygym3uq7uos00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3pQ2faAgKCYgym3uq7uos00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--marievic.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-70ba91ad560si329756d6.3.2025.08.15.03.36.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Aug 2025 03:36:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3pq2faagkcygym3uq7uos00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id 6a1803df08f44-70a88dd04faso60300186d6.0
        for <kasan-dev@googlegroups.com>; Fri, 15 Aug 2025 03:36:21 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU0AC0CRn7NchlPWTzOcU2sPYNWREC5mN94hhW6vuPa2tw8k3L39bc+7jW3Bd2963zRa4MYKtHQJXY=@googlegroups.com
X-Received: from qvbqh9.prod.google.com ([2002:a05:6214:4c09:b0:709:2a7e:b05])
 (user=marievic job=prod-delivery.src-stubby-dispatcher) by
 2002:a05:6214:27ef:b0:707:6977:aa77 with SMTP id 6a1803df08f44-70ba7c1d3bfmr12153106d6.33.1755254181483;
 Fri, 15 Aug 2025 03:36:21 -0700 (PDT)
Date: Fri, 15 Aug 2025 10:36:02 +0000
In-Reply-To: <20250815103604.3857930-1-marievic@google.com>
Mime-Version: 1.0
References: <20250815103604.3857930-1-marievic@google.com>
X-Mailer: git-send-email 2.51.0.rc1.167.g924127e9c0-goog
Message-ID: <20250815103604.3857930-6-marievic@google.com>
Subject: [PATCH v3 5/7] kunit: Add example parameterized test with shared
 resource management using the Resource API
From: "'Marie Zhussupova' via kasan-dev" <kasan-dev@googlegroups.com>
To: rmoar@google.com, davidgow@google.com, shuah@kernel.org, 
	brendan.higgins@linux.dev
Cc: mark.rutland@arm.com, elver@google.com, dvyukov@google.com, 
	lucas.demarchi@intel.com, thomas.hellstrom@linux.intel.com, 
	rodrigo.vivi@intel.com, linux-kselftest@vger.kernel.org, 
	kunit-dev@googlegroups.com, kasan-dev@googlegroups.com, 
	intel-xe@lists.freedesktop.org, dri-devel@lists.freedesktop.org, 
	linux-kernel@vger.kernel.org, Marie Zhussupova <marievic@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: marievic@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="DkD/6scE";       spf=pass
 (google.com: domain of 3pq2faagkcygym3uq7uos00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--marievic.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3pQ2faAgKCYgym3uq7uos00sxq.o0ywm4mz-pq7s00sxqs30614.o0y@flex--marievic.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
X-Original-From: Marie Zhussupova <marievic@google.com>
Reply-To: Marie Zhussupova <marievic@google.com>
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

Add example_params_test_with_init() to illustrate how to manage
shared resources across a parameterized KUnit test. This example
showcases the use of the new param_init() function and its registration
to a test using the KUNIT_CASE_PARAM_WITH_INIT() macro.

Additionally, the test demonstrates how to directly pass a parameter array
to the parameterized test context via kunit_register_params_array()
and leveraging the Resource API for shared resource management.

Reviewed-by: Rae Moar <rmoar@google.com>
Reviewed-by: David Gow <davidgow@google.com>
Signed-off-by: Marie Zhussupova <marievic@google.com>
---

Changes in v3:
v2: https://lore.kernel.org/all/20250811221739.2694336-6-marievic@google.com/
- Code comment edits.

Changes in v2:
v1: https://lore.kernel.org/all/20250729193647.3410634-8-marievic@google.com/
- kunit_array_gen_params() is now explicitly passed to
  KUNIT_CASE_PARAM_WITH_INIT() to be consistent with a parameterized test
  being defined by the existence of the generate_params() function.
- The comments were edited to be more concise.
- The patch header was changed to reflect that this example test's intent
  is more aligned with showcasing using the Resource API for shared
  resource management.
- The comments and the commit message were changed to reflect the
  parameterized testing terminology. See the patch series cover letter
  change log for the definitions.

---
 lib/kunit/kunit-example-test.c | 113 +++++++++++++++++++++++++++++++++
 1 file changed, 113 insertions(+)

diff --git a/lib/kunit/kunit-example-test.c b/lib/kunit/kunit-example-test.c
index 3056d6bc705d..3e858367be01 100644
--- a/lib/kunit/kunit-example-test.c
+++ b/lib/kunit/kunit-example-test.c
@@ -277,6 +277,117 @@ static void example_slow_test(struct kunit *test)
 	KUNIT_EXPECT_EQ(test, 1 + 1, 2);
 }
 
+/*
+ * This custom function allocates memory and sets the information we want
+ * stored in the kunit_resource->data field.
+ */
+static int example_resource_init(struct kunit_resource *res, void *context)
+{
+	int *info = kmalloc(sizeof(*info), GFP_KERNEL);
+
+	if (!info)
+		return -ENOMEM;
+	*info = *(int *)context;
+	res->data = info;
+	return 0;
+}
+
+/*
+ * This function deallocates memory for the kunit_resource->data field.
+ */
+static void example_resource_free(struct kunit_resource *res)
+{
+	kfree(res->data);
+}
+
+/*
+ * This match function is invoked by kunit_find_resource() to locate
+ * a test resource based on certain criteria.
+ */
+static bool example_resource_alloc_match(struct kunit *test,
+					 struct kunit_resource *res,
+					 void *match_data)
+{
+	return res->data && res->free == example_resource_free;
+}
+
+/*
+ * This is an example of a function that provides a description for each of the
+ * parameters in a parameterized test.
+ */
+static void example_param_array_get_desc(struct kunit *test, const void *p, char *desc)
+{
+	const struct example_param *param = p;
+
+	snprintf(desc, KUNIT_PARAM_DESC_SIZE,
+		 "example check if %d is less than or equal to 3", param->value);
+}
+
+/*
+ * This function gets passed in the parameterized test context i.e. the
+ * struct kunit belonging to the parameterized test. You can use this function
+ * to add resources you want shared across the whole parameterized test or
+ * for additional setup.
+ */
+static int example_param_init(struct kunit *test)
+{
+	int ctx = 3; /* Data to be stored. */
+	size_t arr_size = ARRAY_SIZE(example_params_array);
+
+	/*
+	 * This allocates a struct kunit_resource, sets its data field to
+	 * ctx, and adds it to the struct kunit's resources list. Note that
+	 * this is parameterized test managed. So, it doesn't need to have
+	 * a custom exit function to deallocation as it will get cleaned up at
+	 * the end of the parameterized test.
+	 */
+	void *data = kunit_alloc_resource(test, example_resource_init, example_resource_free,
+					  GFP_KERNEL, &ctx);
+
+	if (!data)
+		return -ENOMEM;
+	/*
+	 * Pass the parameter array information to the parameterized test context
+	 * struct kunit. Note that you will need to provide kunit_array_gen_params()
+	 * as the generator function to KUNIT_CASE_PARAM_WITH_INIT() when registering
+	 * a parameter array this route.
+	 */
+	kunit_register_params_array(test, example_params_array, arr_size,
+				    example_param_array_get_desc);
+	return 0;
+}
+
+/*
+ * This is an example of a test that uses shared resources available in the
+ * parameterized test context.
+ */
+static void example_params_test_with_init(struct kunit *test)
+{
+	int threshold;
+	struct kunit_resource *res;
+	const struct example_param *param = test->param_value;
+
+	/* By design, param pointer will not be NULL. */
+	KUNIT_ASSERT_NOT_NULL(test, param);
+
+	/*
+	 * Here we pass test->parent to search for shared resources in the
+	 * parameterized test context.
+	 */
+	res = kunit_find_resource(test->parent, example_resource_alloc_match, NULL);
+
+	KUNIT_ASSERT_NOT_NULL(test, res);
+
+	/* Since kunit_resource->data is a void pointer we need to typecast it. */
+	threshold = *((int *)res->data);
+
+	/* Assert that the parameter is less than or equal to a certain threshold. */
+	KUNIT_ASSERT_LE(test, param->value, threshold);
+
+	/* This decreases the reference count after calling kunit_find_resource(). */
+	kunit_put_resource(res);
+}
+
 /*
  * Here we make a list of all the test cases we want to add to the test suite
  * below.
@@ -296,6 +407,8 @@ static struct kunit_case example_test_cases[] = {
 	KUNIT_CASE(example_static_stub_using_fn_ptr_test),
 	KUNIT_CASE(example_priv_test),
 	KUNIT_CASE_PARAM(example_params_test, example_gen_params),
+	KUNIT_CASE_PARAM_WITH_INIT(example_params_test_with_init, kunit_array_gen_params,
+				   example_param_init, NULL),
 	KUNIT_CASE_SLOW(example_slow_test),
 	{}
 };
-- 
2.51.0.rc1.167.g924127e9c0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250815103604.3857930-6-marievic%40google.com.

Return-Path: <kasan-dev+bncBDQ67ZGAXYCBBGOY5HCAMGQEO3HZYPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63b.google.com (mail-pl1-x63b.google.com [IPv6:2607:f8b0:4864:20::63b])
	by mail.lfdr.de (Postfix) with ESMTPS id 9C5F2B2181D
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 00:18:03 +0200 (CEST)
Received: by mail-pl1-x63b.google.com with SMTP id d9443c01a7336-24249098fd0sf52841125ad.0
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Aug 2025 15:18:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754950682; cv=pass;
        d=google.com; s=arc-20240605;
        b=gCNvo5x5i4MX1bAXUvt053GjlARTUDaGSg31g/IUI+z9V6AJJJtLoqn2ya3OUK3Bgn
         1o8kCgWeTclMbVpBzvw5yYsooOIED0LZ/gAJxpokrj9j7gUYA7uBQrhuwl7/CQVvxUAg
         sptH5a2+nQdqipwJEGGh9ePE7UAa0U1gRqAUOiEWygx4jHJjBnj6llUMKvTkXEVpZrpS
         49FvLglK1iqFgT+lbYiS8dp9a8o2GsTW3z4TfC/qCzR6gXZgDET0abfB0jleESyEtUv4
         EuV6Ds8ihP/s0cnk1w5pgEbr+tnZ3s6MOnjuoWddgBb5j49waitghQ/h7yMGUlDWlRc6
         LgsA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=QpFO7TGmo35901fzrTDfPJCrQ3k1rtKBOxWsQ6Ty/dU=;
        fh=xBo7js1orCDUUZxuCnLtoHd6mI47inDwkqip8Tn1s6o=;
        b=R4Ogcic4GmpCn86CKWbHxthm0JA1aYgQRQpYvkQBqXlza/DxlZH2Ke6lY0govYgQX7
         YjgFjSWsRHzjYzi+U/RHsJ7kMuseQDAnyeP5a+OCHqGAf2yUPxgWTCG6EOA9oE9tUwPl
         bB2CdeNTBObMVnbLtUMv2ddsDsdHM8Hdl9GMWl4i2NfMVWsy75F16E4H3B/iXOK8b3FA
         /sFGz0287J9CmpiAvDJd8x8yC/BvB7bO1496ucFe6P/JZvf4d1kDRCsBbXoajPVjv2Js
         z+rgty1ZfuvYZ1+DITbiK8nEfvoOkCz/LpmZftrWPfsSB+jWdGj9YCKeHhsEtS//fI2T
         T13g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ELR5posk;
       spf=pass (google.com: domain of 3f2yaaagkcaqqevmizmgksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3F2yaaAgKCaQQEVMIZMGKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--marievic.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754950682; x=1755555482; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=QpFO7TGmo35901fzrTDfPJCrQ3k1rtKBOxWsQ6Ty/dU=;
        b=hj6PuF22ZPVVC8O4O5HHFH6ndak6qzDh+ymFNkbInqy/1dMFEJ+rxOBFy+VsNydhCb
         l6C006JCw70onBuYBv9wYOWi8JEEG9XrTZBXZFzN2OUqAzMteUHb0if55WAWNU4gkAEw
         xnuqMi8vmk7jVLzut9qGgemBOshQK/mztcKvhwod0Qsvrz2pyEnyZL9J4RLG3pTuk+FS
         8FdogR/NEqH0Uv592RDaU1mEAs7XpCqJn6sU5R+cAB+wfvX0Whwnb1QT8EdR7tz5qp1s
         Ky1eNc6jz1OE5tbQdEYbx5UR/fF9fKiM1qZ5ycNqvTWba/DpLM2wLyPLstVH2k0j84l9
         fPWA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754950682; x=1755555482;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=QpFO7TGmo35901fzrTDfPJCrQ3k1rtKBOxWsQ6Ty/dU=;
        b=wwQhfJDqotEmg87zUeuIE2uIY47kfAq6LC0NbshuTxoYmUgmBAiq5aMcZfFS59Fjz6
         tib99IRJFUgkEIgJqJBErj44jJBw2QdU0V4G1jkdTFl4J/AqvfsbyDbDBeGzN70tpqbx
         Id6TLHJAuxrAH1eqk/jZ4mZo8SeMMtA60HgMpytLcaeIMmJABaBpxel0tn0252fMXU9G
         G5Yl0oNgvUifXrFBa7v04y+Bq3XEVxtmNstJCJndvYOZTZlWcaFJZrvQ8rLRsdtExR/R
         0R2iECVJ/DgsPhE4IncCaClL4EKE4SaivPm7W7Ngqzmg8EG3xIThtw2HiNErKaV7JFJL
         LVjg==
X-Forwarded-Encrypted: i=2; AJvYcCWs1i7XgGasKIkAmuGSXDhcLX7ISKhuNNV1IPo/3PcbE7Lf8xCyfhR0u+6XOGFz30BMlmUlTA==@lfdr.de
X-Gm-Message-State: AOJu0YyjlMCTs3C28GxzbYJi2o8E6idBPvEsHONdHCUuFTtnbmzMvrk+
	Qk4aeCTHborOSFykl3TnpKDz3ubZAKRySuc4kEwDihX6pkXCxpIMt7Xj
X-Google-Smtp-Source: AGHT+IF3iNDj6KD/tG87nCp/p9FodEuFidJusuPBnYm45pNbY3HeIwMzzSdY8iJDuxYLkqHmDCH7iw==
X-Received: by 2002:a17:903:2283:b0:240:9a45:26e6 with SMTP id d9443c01a7336-242fc230f18mr14824825ad.10.1754950681719;
        Mon, 11 Aug 2025 15:18:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZf1gzUcN7s8e8UGU11TTs0CUcgrBPscP51EQ9sy4YbZ/A==
Received: by 2002:a17:903:4407:b0:240:b084:efd2 with SMTP id
 d9443c01a7336-242afb634c0ls52214965ad.0.-pod-prod-05-us; Mon, 11 Aug 2025
 15:18:00 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXj6+TPGRFGEdeZDvfRACgfWOTcy+O28AJ7/ekdHvdmj7rTw0IYsCB2u+amEGY39UKfOZ20lAWZQRU=@googlegroups.com
X-Received: by 2002:a17:902:cf11:b0:240:3ca6:184c with SMTP id d9443c01a7336-242fc38b907mr16672385ad.48.1754950680464;
        Mon, 11 Aug 2025 15:18:00 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754950680; cv=none;
        d=google.com; s=arc-20240605;
        b=PCpFwK1psbmFujcqggD55H9DpdkhfGcIIjxp/SGwGNGMOla6VzUILWpaaDPkDi787W
         udCtIzN20SaJN8aSld1V4/zK94l9XDkOdM+fAEMoroXZPfLlJ1FoKXkNOCLS4pez37su
         VxbSNUI+Hb49bZPrVpYomzRG9IBdr505kjTjGzC13MJ7GQqWhLMNTHkaEKpNx0u88Pm/
         FlZz9HQ1G58mRNEjxrPasqPn3QFUOSyVElabS3kfbTpAxCQOpxQ0brPzbHTkIpHryp8j
         cc4blz/6UI4wjVJnfwLhdoZVAze694XfbXIFJlJMDB0GX/M+Pid6TXvscl5FMMckK4WY
         gsjg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=kZCyJ8fS+0ViRKQvRY7E+bm8qVK2uq6SSWVZQUVTZM4=;
        fh=1vcSZgq8+Z1BiNjW1ch48L/NAXy6a4uyxdF5u6vfWAc=;
        b=Rd7QhH7C950s/aG5Mkc80mHHQcss4FjvF7f7+DkeF1wGgzc22zA7cNia1smHZBwlWd
         ADotkZbylfRaNP6suZ8Dlyb0/lL9Cio4OSxR6jGJJUVwn6KrX42L6vMOPEEOGWAPFtGQ
         4L9Tj5cI6w7oQDp2L/NKK+ukcka7Uul+mHMQytP6GNSnzc6hj4X9kVGnnKqEQ0OOrutd
         c9jxdO9p1aNCJqLlVoeJp9egqURZ7v9AEDrlmsybizbFnWlU6PNgBSUy3pGGPTLTocHo
         SjVPus8AzXv3zi52hgaQPIDWSNmOq2g30fYXBohcEiIT2hfKdNZSxeOh2MAnDf9F48HF
         52LA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ELR5posk;
       spf=pass (google.com: domain of 3f2yaaagkcaqqevmizmgksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3F2yaaAgKCaQQEVMIZMGKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--marievic.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qk1-x749.google.com (mail-qk1-x749.google.com. [2607:f8b0:4864:20::749])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-3206334aa31si1498879a91.0.2025.08.11.15.18.00
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 11 Aug 2025 15:18:00 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3f2yaaagkcaqqevmizmgksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::749 as permitted sender) client-ip=2607:f8b0:4864:20::749;
Received: by mail-qk1-x749.google.com with SMTP id af79cd13be357-7e6857795eeso1275236485a.3
        for <kasan-dev@googlegroups.com>; Mon, 11 Aug 2025 15:18:00 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUoXMIgmhxUzKgho2RrgeTI/ekA0uiJolRfJ6i3BfIOOPc8aPQRwMSuUjSMRDdXmoXi/XoizNanf6w=@googlegroups.com
X-Received: from qktt14.prod.google.com ([2002:a05:620a:4e:b0:7e6:9d66:9ee3])
 (user=marievic job=prod-delivery.src-stubby-dispatcher) by
 2002:a05:620a:e0a:b0:7e6:2610:f2e0 with SMTP id af79cd13be357-7e8588faba8mr194499385a.39.1754950679395;
 Mon, 11 Aug 2025 15:17:59 -0700 (PDT)
Date: Mon, 11 Aug 2025 22:17:37 +0000
In-Reply-To: <20250811221739.2694336-1-marievic@google.com>
Mime-Version: 1.0
References: <20250811221739.2694336-1-marievic@google.com>
X-Mailer: git-send-email 2.51.0.rc0.205.g4a044479a3-goog
Message-ID: <20250811221739.2694336-6-marievic@google.com>
Subject: [PATCH v2 5/7] kunit: Add example parameterized test with shared
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
 header.i=@google.com header.s=20230601 header.b=ELR5posk;       spf=pass
 (google.com: domain of 3f2yaaagkcaqqevmizmgksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--marievic.bounces.google.com
 designates 2607:f8b0:4864:20::749 as permitted sender) smtp.mailfrom=3F2yaaAgKCaQQEVMIZMGKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--marievic.bounces.google.com;
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

Signed-off-by: Marie Zhussupova <marievic@google.com>
---

Changes in v2:

- kunit_array_gen_params() is now explicitly passed to
  KUNIT_CASE_PARAM_WITH_INIT() to be consistent with
  a parameterized test being defined by the existence
  of the generate_params() function.
- The comments were edited to be more concise.
- The patch header was changed to reflect that this example
  test's intent is more aligned with showcasing using the
  Resource API for shared resource management.
- The comments and the commit message were changed to
  reflect the parameterized testing terminology. See
  the patch series cover letter change log for the
  definitions.

---

 lib/kunit/kunit-example-test.c | 118 +++++++++++++++++++++++++++++++++
 1 file changed, 118 insertions(+)

diff --git a/lib/kunit/kunit-example-test.c b/lib/kunit/kunit-example-test.c
index 3056d6bc705d..f2819ee58965 100644
--- a/lib/kunit/kunit-example-test.c
+++ b/lib/kunit/kunit-example-test.c
@@ -277,6 +277,122 @@ static void example_slow_test(struct kunit *test)
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
+	 *
+	 * Alternatively, since this is a static array we can also use
+	 * KUNIT_CASE_PARAM_ARRAY(,DESC) to create  a `*_gen_params()` function
+	 * and pass that to  KUNIT_CASE_PARAM_WITH_INIT() instead of registering
+	 * the parameter array here.
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
@@ -296,6 +412,8 @@ static struct kunit_case example_test_cases[] = {
 	KUNIT_CASE(example_static_stub_using_fn_ptr_test),
 	KUNIT_CASE(example_priv_test),
 	KUNIT_CASE_PARAM(example_params_test, example_gen_params),
+	KUNIT_CASE_PARAM_WITH_INIT(example_params_test_with_init, kunit_array_gen_params,
+				   example_param_init, NULL),
 	KUNIT_CASE_SLOW(example_slow_test),
 	{}
 };
-- 
2.51.0.rc0.205.g4a044479a3-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250811221739.2694336-6-marievic%40google.com.

Return-Path: <kasan-dev+bncBDQ67ZGAXYCBB7WFUTCAMGQEXEUKPIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53c.google.com (mail-pg1-x53c.google.com [IPv6:2607:f8b0:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id D5FD3B15396
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Jul 2025 21:37:36 +0200 (CEST)
Received: by mail-pg1-x53c.google.com with SMTP id 41be03b00d2f7-b31f112c90asf161961a12.0
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Jul 2025 12:37:36 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753817855; cv=pass;
        d=google.com; s=arc-20240605;
        b=JOe4+zfjNVTUc44SH92WqZ9MpGcgCZGF/htm1reQ92rsjxJ56xzPMPfVTo7bOqlk3k
         V2sqHquHdRhLRHX0jDnz6AXG4gg3Njk+j85RtnnkMS9GL4+/F3drOWg6g5+A4BacbRtg
         eA6paPSGg3oEnqcuhx5m+lSWhPM8Tp7atmsTXs6Jeqx13FQhRlHyw0uBhZaI+rFe+XQ9
         5JOxa+69g7iRKCWGdgPwfeqf8m4gwNjtV3f19G+Tr5ATv1QTp4n8mV5L9dwDCMRh3pVj
         8kNN5aCemB0VtH1uPxNIoibwHDNaCVNR4jl1Ny+kna4PPosuLP5Z9+BqY37EciAmtUO/
         38qA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=qb7bpZBl/eNG/CmvYT5fRSAAlDZSaNmmm6XhlkQ+XsM=;
        fh=lpnd3z5WpCX5xsrOWgC6MjjcDg2SbdDBm41asacwiJI=;
        b=hgp2ByLO4a3E2CSFwKXmFAVVYkoz0tRVXQQpTRLIou8uFGDehXdfidd84lslKZ0gB/
         ZsVz05p18F5saIH7lctpt59WPnzAWWMe42dO80BnFdaq8+w3VOsdYHgJ7u3Eu/whPPbt
         jSqOE0V7b7k9B+Q/DrCvJECVYwXj2+i10aVmdjzPkEy6m5FP5130mkHyeB2FABFqOh0z
         TdZv0aBvM89aKpfC4KBLhU/o+GW2RR5/IWjIiLFRsW3QhousjhgFQfxyl7WbziLoMHgS
         p1LtAuCtwApQfs5YbJJ0lzqC+kd6U6SvAkSdHg1boIGueamuF4JDAjCvj6nE4qYKvgk7
         K3sA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=p7C4yM3w;
       spf=pass (google.com: domain of 3_ckjaagkcbedrizvmztxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3_CKJaAgKCbEdRiZVmZTXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--marievic.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753817855; x=1754422655; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=qb7bpZBl/eNG/CmvYT5fRSAAlDZSaNmmm6XhlkQ+XsM=;
        b=V8fJssqQEy7a8wQm0/JsM2B7kRKuVAbSGpgCCT3RdHgkqXdqtucLbbg7DwgC4ldTZ9
         ArGEqdM5GqbBs0sfMpHohs8yrYDzj/0BNGEGUISPB5y8By2BiPTfyyMs8lGa+MYKFoVt
         mSjIxachVvEmHGgNE857C3vWg5w6PyCfoxA73iwMYhv+RB/V0XEkf1OUDRBI0egobpVO
         aDeOmZr/1lxHM0nh1493pxfQ537opHl23oO0q77WSTBHmH/wKAMfuwWkJhBemLF8KfS+
         ECB5jekQ15SmGp5QWF1Ke7kEYTE/qz7gF6mSK41FaV3tyzw0Guu42iAZZ0ID8uqvX0+j
         g7ow==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753817855; x=1754422655;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=qb7bpZBl/eNG/CmvYT5fRSAAlDZSaNmmm6XhlkQ+XsM=;
        b=vKPKGJdjipl3zn41R4aekgxfCUAhlRKf3wgGv8yIlrAK/1LBE95qJXDlOPUAZMCwjy
         PiXaI/a3lo1C0ah9p5Iu+m6984jvS9pBwB+1gg0sNvhPSJIMfA1g9CjT7+TP8U2c+eot
         o7kObFYj/hvN8c6UcHvWqG4tE13H1OLAc7ryL3gKKgk76x9ABZqcBBgMqhaolOrYZJlb
         jWYu3sM6gQ1rpwiiAdmYbdH+oBzp4L0ZS7fpq1so/x8jb1wU3t2DRJnGll0uQlFsVMnN
         kQM28xGdSoHcAY6mOY+DFgjDJV/nrYGOTodM8SBoKXodycjMRzQIjXMchYptdwjqs0nT
         Xw4A==
X-Forwarded-Encrypted: i=2; AJvYcCUlbKM4YzFpeN/Jti4w8JtZm6zEs2PtyQoxf74V4VbFBRz79s6rZjU3wPb53QqG4DbtOuIwXQ==@lfdr.de
X-Gm-Message-State: AOJu0Yyd2NgbMq1OHKc6AMCIIlwzBYgI3JF3MPv/EIF84TyFFPGJfBIs
	+lop1S+Hg7k68zSSgz84vbamFO0Cbw1JP6+Zsc4OOwo69o/LL/VNVH4c
X-Google-Smtp-Source: AGHT+IHlo90NbVzWJKuEMADol35hlF8tOTRL+WCCb7fdgyaYh75NO8MRSdsUjc6uE1b8qAU7tBIsVQ==
X-Received: by 2002:a05:6a20:a123:b0:23d:6076:6388 with SMTP id adf61e73a8af0-23dc0699c52mr1037182637.14.1753817854833;
        Tue, 29 Jul 2025 12:37:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZehkBbluUL3GS1PjACroE+LWEsLxjMsg/42PFRrlHomJA==
Received: by 2002:a05:6a00:1702:b0:736:cffa:56ce with SMTP id
 d2e1a72fcca58-76abd77de3bls83491b3a.2.-pod-prod-00-us; Tue, 29 Jul 2025
 12:37:33 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXKznTGeqz2X+gkEn6AiYsQOE8L/scOfD2XCvwWqoyGj3hwwf7sXgQzMyDo3eupebT/gGz+3h9b9Yw=@googlegroups.com
X-Received: by 2002:a05:6a00:3e13:b0:74e:aaca:c32d with SMTP id d2e1a72fcca58-76ab8c4bd2amr945368b3a.10.1753817853402;
        Tue, 29 Jul 2025 12:37:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753817853; cv=none;
        d=google.com; s=arc-20240605;
        b=SXI4WHjGnYBNLkYGIPhQmxAXD3epT8fp1zjkHh5i/fk/PK52LxDP2VIci8Sf+/rYvC
         lPXIcR+6IskO0PtSw4YJH0oyq9sgh/c70P3LwGJAsW31Y6zVxGrRbJJyzMewTpWzoAhg
         Vv4gmbVvJ10XGn4JlPExjhxR6XXdu4on77/HSZ/tV8gjIKVhTCsUE6byL6aW7yFSTMKS
         h1l6GOUWsDUDdyEiMzM0fup6iyT1cinAKptcClzz+ogPys8IaxXDCCY6avD/L4DpjqbP
         UCS7RJIKhn+f/B6kIlTwpyV77QBoz0/CGl/17GrorZapWCOv+UxauS7N7myue+iSslMN
         WorA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=lH0YiEtTpPisQaiDPehvjIr4QLjg99NBvWegBL35AWY=;
        fh=uYZVxDAnldAWOb1FbyKEhOVg+oWN6oFzW911PSw6LkE=;
        b=ksawyDZI2XKl/Yrs48IyDM6uOl/2ueQkRO1FuG5wIMu2LDrZdCtV9gk/30h7MC0SGO
         F1KBA/y9Zh7oGSlXCBRddLQCzV6a1x5b2xbXRK+gZVBky6YAgdNbwHVJLiEoP82+BTai
         0tFGwii9SaE+vnGN5I5KnxYRc9tOvnxzX1mMjaU4BnnRXiIQtIUIjQIBC4hF0Pj8PT7A
         0TSSUmwbVGerB9x+xjNu7C12QuIeTlGJEf79WTe+QcFnlsCK5VsEk0OYW/hIQSII3rAt
         uO5jlGsexVUhD+A2L09TYhQz1WoY4WwQfIxHz2qx4iW222BA6t73wYYCsOuvLm830CyK
         y1ww==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=p7C4yM3w;
       spf=pass (google.com: domain of 3_ckjaagkcbedrizvmztxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3_CKJaAgKCbEdRiZVmZTXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--marievic.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-b3f7f649809si509396a12.3.2025.07.29.12.37.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 29 Jul 2025 12:37:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3_ckjaagkcbedrizvmztxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id d75a77b69052e-4ab5e2b96ecso114078651cf.3
        for <kasan-dev@googlegroups.com>; Tue, 29 Jul 2025 12:37:33 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVvZt9q9dzRFL7Sej8OkEWGH1Ej40Y1WgY/m33gN1JMv1Mp6k0T5n3UpI0pJweqrxHpgamy3R02DGk=@googlegroups.com
X-Received: from qtbbr10.prod.google.com ([2002:a05:622a:1e0a:b0:4ae:713e:cb10])
 (user=marievic job=prod-delivery.src-stubby-dispatcher) by
 2002:a05:622a:302:b0:4ab:5813:e8d with SMTP id d75a77b69052e-4aedbc739acmr14482571cf.32.1753817852434;
 Tue, 29 Jul 2025 12:37:32 -0700 (PDT)
Date: Tue, 29 Jul 2025 19:36:45 +0000
In-Reply-To: <20250729193647.3410634-1-marievic@google.com>
Mime-Version: 1.0
References: <20250729193647.3410634-1-marievic@google.com>
X-Mailer: git-send-email 2.50.1.552.g942d659e1b-goog
Message-ID: <20250729193647.3410634-8-marievic@google.com>
Subject: [PATCH 7/9] kunit: Add example parameterized test with shared
 resources and direct static parameter array setup
From: "'Marie Zhussupova' via kasan-dev" <kasan-dev@googlegroups.com>
To: rmoar@google.com, davidgow@google.com, shuah@kernel.org, 
	brendan.higgins@linux.dev
Cc: elver@google.com, dvyukov@google.com, lucas.demarchi@intel.com, 
	thomas.hellstrom@linux.intel.com, rodrigo.vivi@intel.com, 
	linux-kselftest@vger.kernel.org, kunit-dev@googlegroups.com, 
	kasan-dev@googlegroups.com, intel-xe@lists.freedesktop.org, 
	dri-devel@lists.freedesktop.org, linux-kernel@vger.kernel.org, 
	Marie Zhussupova <marievic@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: marievic@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=p7C4yM3w;       spf=pass
 (google.com: domain of 3_ckjaagkcbedrizvmztxffxcv.tfdbrjre-uvmxffxcvxiflgj.tfd@flex--marievic.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3_CKJaAgKCbEdRiZVmZTXffXcV.TfdbRjRe-UVmXffXcVXiflgj.Tfd@flex--marievic.bounces.google.com;
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

Add `example_params_test_with_init` to illustrate how to manage
shared resources across parameterized KUnit tests. This example
showcases the use of the new `param_init` function and its registration
to a test using the `KUNIT_CASE_PARAM_WITH_INIT` macro.

Additionally, the test demonstrates:
- How to directly assign a static parameter array to a test via
  `kunit_register_params_array`.
- Leveraging the Resource API for test resource management.

Signed-off-by: Marie Zhussupova <marievic@google.com>
---
 lib/kunit/kunit-example-test.c | 112 +++++++++++++++++++++++++++++++++
 1 file changed, 112 insertions(+)

diff --git a/lib/kunit/kunit-example-test.c b/lib/kunit/kunit-example-test.c
index 3056d6bc705d..5bf559e243f6 100644
--- a/lib/kunit/kunit-example-test.c
+++ b/lib/kunit/kunit-example-test.c
@@ -277,6 +277,116 @@ static void example_slow_test(struct kunit *test)
 	KUNIT_EXPECT_EQ(test, 1 + 1, 2);
 }
 
+/*
+ * This custom function allocates memory for the kunit_resource data field.
+ * The function is passed to kunit_alloc_resource() and executed once
+ * by the internal helper __kunit_add_resource().
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
+ * This function deallocates memory for the 'kunit_resource' data field.
+ * The function is passed to kunit_alloc_resource() and automatically
+ * executes within kunit_release_resource() when the resource's reference
+ * count, via kunit_put_resource(), drops to zero. KUnit uses reference
+ * counting to ensure that resources are not freed prematurely.
+ */
+static void example_resource_free(struct kunit_resource *res)
+{
+	kfree(res->data);
+}
+
+/*
+ * This match function is invoked by kunit_find_resource() to locate
+ * a test resource based on defined criteria. The current example
+ * uniquely identifies the resource by its free function; however,
+ * alternative custom criteria can be implemented. Refer to
+ * lib/kunit/platform.c and lib/kunit/static_stub.c for further examples.
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
+ * parameters.
+ */
+static void example_param_array_get_desc(const void *p, char *desc)
+{
+	const struct example_param *param = p;
+
+	snprintf(desc, KUNIT_PARAM_DESC_SIZE,
+		 "example check if %d is less than or equal to 3", param->value);
+}
+
+/*
+ * Initializes the parent kunit struct for parameterized KUnit tests.
+ * This function enables sharing resources across all parameterized
+ * tests by adding them to the `parent` kunit test struct. It also supports
+ * registering either static or dynamic arrays of test parameters.
+ */
+static int example_param_init(struct kunit *test)
+{
+	int ctx = 3; /* Data to be stored. */
+	int arr_size = ARRAY_SIZE(example_params_array);
+
+	/*
+	 * This allocates a struct kunit_resource, sets its data field to
+	 * ctx, and adds it to the kunit struct's resources list. Note that
+	 * this is test managed so we don't need to have a custom exit function
+	 * to free it.
+	 */
+	void *data = kunit_alloc_resource(test, example_resource_init, example_resource_free,
+					  GFP_KERNEL, &ctx);
+
+	if (!data)
+		return -ENOMEM;
+	/* Pass the static param array information to the parent struct kunit. */
+	kunit_register_params_array(test, example_params_array, arr_size,
+				    example_param_array_get_desc);
+	return 0;
+}
+
+/*
+ * This is an example of a parameterized test that uses shared resources
+ * available from the struct kunit parent field of the kunit struct.
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
+	/* Here we access the parent pointer of the test to find the shared resource. */
+	res = kunit_find_resource(test->parent, example_resource_alloc_match, NULL);
+
+	KUNIT_ASSERT_NOT_NULL(test, res);
+
+	/* Since the data field in kunit_resource is a void pointer we need to typecast it. */
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
@@ -296,6 +406,8 @@ static struct kunit_case example_test_cases[] = {
 	KUNIT_CASE(example_static_stub_using_fn_ptr_test),
 	KUNIT_CASE(example_priv_test),
 	KUNIT_CASE_PARAM(example_params_test, example_gen_params),
+	KUNIT_CASE_PARAM_WITH_INIT(example_params_test_with_init, NULL,
+				   example_param_init, NULL),
 	KUNIT_CASE_SLOW(example_slow_test),
 	{}
 };
-- 
2.50.1.552.g942d659e1b-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250729193647.3410634-8-marievic%40google.com.

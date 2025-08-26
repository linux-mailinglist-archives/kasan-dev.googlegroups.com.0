Return-Path: <kasan-dev+bncBC6OLHHDVUOBBUXVWXCQMGQEZMV45JI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 0FC07B3585D
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Aug 2025 11:13:56 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id e9e14a558f8ab-3ee9be8bc8bsf5428645ab.3
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Aug 2025 02:13:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756199634; cv=pass;
        d=google.com; s=arc-20240605;
        b=KElBiOvsJX2f5PVxvnhDPUCrg2yHsQunB1ID4WUqElXhHeTVAcC9hyhVn8DYWfL44E
         rha0xSFXYjKBvAOY5JJjbiQZnr3VJ6Q20EYskiwQVfhiaN91T3w/+0eOkY3+NZJq9rDg
         ldeXAaOWkpVWmsBdFihOh8xv3oEhQ2T/8/UUmHOC40oFMms71FfSyz8X3Pl9XRCX3ZEf
         Z2E9M4PR4UQgbqSg14pMYIPfv17paB6y8BUoY1Th0hFKje47RgdRhp50cX/zZ5X+HFg4
         YLmQxZkQ2oRQEz0Wx6VqdPnXXy8waoV2TcPqq0lfePihl14JxM/VCfjBoJnU4JkejKAv
         dgAQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=WGretzzd/qafJDRgFMIQN150u3aNVlD/FSGdmSucjLw=;
        fh=MabMxbj934AGBlVcfY+7h8pD8CSjQZvLhgd/1MXNZgU=;
        b=cJfcL1LlqfU5W1znZ9bZXowwwPtS1uUD1kH3l9+whWZtLH5YQLKB8KayJCYkgQ2Oem
         ccpo6U78Kt9IwOa8O3nbTJ6dJdnnOe8CX2vBwbhpXfbAeZ75EVr9JoyWzodUILuEQSqT
         hARqh/UlSwJuDDZODDNNloJpQ3Wvs6zVVrDrEN/XnNOR8pAmlujidh962EUDZY5LZOQW
         U8rpyRn2tSyviCGVkZH3Rd9RspIzRt1a8hAgcKHqFR1ns6o3bPd3E418WqcqG0zFAUCX
         milNp8PiMyl1ggNVejk6Ujma3kLDkLj5ipTHjdTi5WHxA3ZesRsgb4nIoQzJ4sv/yMAu
         879A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="j9/C78ff";
       spf=pass (google.com: domain of 30hqtaagkcccqn8vqt19t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::649 as permitted sender) smtp.mailfrom=30HqtaAgKCccqn8vqt19t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756199634; x=1756804434; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=WGretzzd/qafJDRgFMIQN150u3aNVlD/FSGdmSucjLw=;
        b=BAiWRZ231mpMawUnOXZyEPOLeTPjq9RW5MotDKTXo149VRKi06BilNtRmCnUTf9F84
         ELeqNlpWuY6y/b8YkDaPYaV2I72i8pyh7jtUCbgMK+iVumM9OZOgDLrZq+BLg+Va+ua/
         mag6BEOcc9+/s1AdVvpq6FpUAydV6XURWHkAtruCpcbarANSGFtbEfqko2JOOcarWXer
         1EJNcyAt0RGDSc42qHmjoEZgUymw3RPAXmndUFuViJezzIG+l6tAs6bCu5Pn8RBVNuCW
         dKtiIoCqPpOrdgZpudEai2KuCn5hSdV49Iojf7CXJXYXwn9Q0SUxlJgLiWjcVKnEKelS
         C0Xw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756199634; x=1756804434;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=WGretzzd/qafJDRgFMIQN150u3aNVlD/FSGdmSucjLw=;
        b=rMIpEBaqp2+jBoqWV8k0egrRWWvFNwnyCmaduCHXaOH9ZhF89pFbD/r8G8jEB1M9V+
         QojW7PLMb1fHzuE7ty/QiRZwHTEnt17IWJb7UtSzTZXRNg5CWFPaQWoUndPM62CBmsM4
         RnmRVnJgwDZzmd8kjKc+Yzsraulo6w+YU4ruW6jlF7DOuurqCGsY2uLVd4jm5nT8+JrI
         zCrv6BhUiJjvFGSpSAWVFzlfjfrkKcS152dOYd6FQFJeBGQX0lB+7dZsSC+9+wtH9JyM
         7VBLJdfEnIizP6G625AOUt5cxAgTubnZ88jM9ahmJlCGDTBUSSzIOj4RNkw/mjkn1eS0
         +svQ==
X-Forwarded-Encrypted: i=2; AJvYcCWb+UqOi9R5rvuOVKztyq3mscTzCyig0cnKthDnh/1PpmsfPsMKPJsCWjK/ggL29Erh4PxMgQ==@lfdr.de
X-Gm-Message-State: AOJu0YyIIep1dF/q5D8YxLE/HcENwnFVOMQEJeq21gDJ1+/KWyqLBkxG
	xmmh5ukgobfEEB3+MMjvS3m8scjItHjx3+dSWus1JRjrtDQCHEISY1Na
X-Google-Smtp-Source: AGHT+IE+Ec64wuOU0kEZthc5iziGGwxa+lXi9ArzK+LmKPnQUhjd0gK36/iwsmFl+BpGrUHXL+k92g==
X-Received: by 2002:a05:6e02:1d8b:b0:3ee:a2c9:e1ce with SMTP id e9e14a558f8ab-3eea2c9e2ebmr20912325ab.26.1756199634476;
        Tue, 26 Aug 2025 02:13:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZd/82WxtMVvvfZI0wFTnRcBX4BP24T7iv1nth/CWhC0mA==
Received: by 2002:a05:6e02:370f:b0:3ec:3033:7fb2 with SMTP id
 e9e14a558f8ab-3eed4eef13cls3403995ab.0.-pod-prod-09-us; Tue, 26 Aug 2025
 02:13:53 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXuGw42T4amsH1wxmTmeZXuyYNOfkc59ike4MWkU7qk3f7TYwiiotAchusXStwKLm2wRgoQ08zNdNo=@googlegroups.com
X-Received: by 2002:a05:6e02:1d8b:b0:3ee:a2c9:e1ce with SMTP id e9e14a558f8ab-3eea2c9e2ebmr20911755ab.26.1756199633434;
        Tue, 26 Aug 2025 02:13:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756199633; cv=none;
        d=google.com; s=arc-20240605;
        b=POOPGdK7LnyeGdZFuFWgEiYB+599s5FpJGHmUlAbcSQhyBlskIDvGWZTqAEt8+4DAj
         HiK4/liSk+K75goyCIbN0nF5GzkmFVbrNzTBhfbkpun4dKz7N9EtXz0vuX/XR56tNBFj
         gYJ9bP8oSSmt6Zgo2RgB/sabj8bkxfW58RxtA6inbYqKB1U2b9ivXom5zj02ODGtdqem
         FJjaD5SC98l1PsTFHkD77OsQZsbewopeRWGTz61hgphwFDmFropi9fPFilDNKu3D9Uk9
         PQEtH94aiHwSwiVUzY35gJCu5HJ+Z5K40EzQt8TWxZjsw9it20ytP/EYNFQY0wCXq7hM
         yONQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=E/DdI8QKaF0QvnOvsbrRP9RRgtoSroBxXesHs3tNY3s=;
        fh=TM/q3p0+asfjZnWmskBCfhEW+WZnKGhnS2JIC7UMfyU=;
        b=OvcLN0l6QsUKv857+UnzwML6lLrbjoRYOHLNvF22Jj8UX74TxMODz/89FkPNF7KPDr
         PRFrs+3RziM71gnFFroj9NfTVMyZjTloqrTuFz93f/7LUgYY6hhI2z2OlI2R6SKCg8Js
         Sp0oCXUUvQoiou1Puy1LQEYEJl5C7HpbrfxbMDu9Xw5h9LbMsSVzEeFLMiCkWBF01mqq
         mJ41WT3il68TWDZAgnyny+pl8Mcltg94adfA1ModC/TbbDYPQdEp8yWrQqko4aJcCtVO
         kqChL0wj2JKZ6UDnbz4nRTLpA38pVdEVEdObTlceDrdTgU1YmOMzQIZyDFnV0zUjcnca
         X/vA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="j9/C78ff";
       spf=pass (google.com: domain of 30hqtaagkcccqn8vqt19t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::649 as permitted sender) smtp.mailfrom=30HqtaAgKCccqn8vqt19t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x649.google.com (mail-pl1-x649.google.com. [2607:f8b0:4864:20::649])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3eecaa8eae3si418205ab.0.2025.08.26.02.13.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Aug 2025 02:13:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of 30hqtaagkcccqn8vqt19t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::649 as permitted sender) client-ip=2607:f8b0:4864:20::649;
Received: by mail-pl1-x649.google.com with SMTP id d9443c01a7336-24457f59889so56278325ad.0
        for <kasan-dev@googlegroups.com>; Tue, 26 Aug 2025 02:13:53 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUrLIl3NOjkypxq1HDd32Ne9lP5BwY5AO7wgTAndwxNiWoWcLDoHu4B7hlf0RWsK+JosOMvANsJRQ0=@googlegroups.com
X-Received: from pldp2.prod.google.com ([2002:a17:902:eac2:b0:237:cedc:1467])
 (user=davidgow job=prod-delivery.src-stubby-dispatcher) by
 2002:a17:902:ec87:b0:246:6a8b:8473 with SMTP id d9443c01a7336-2466a8b8672mr147539915ad.45.1756199632691;
 Tue, 26 Aug 2025 02:13:52 -0700 (PDT)
Date: Tue, 26 Aug 2025 17:13:35 +0800
In-Reply-To: <20250826091341.1427123-1-davidgow@google.com>
Mime-Version: 1.0
References: <20250826091341.1427123-1-davidgow@google.com>
X-Mailer: git-send-email 2.51.0.261.g7ce5a0a67e-goog
Message-ID: <20250826091341.1427123-6-davidgow@google.com>
Subject: [PATCH v4 5/7] kunit: Add example parameterized test with shared
 resource management using the Resource API
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
To: Marie Zhussupova <marievic@google.com>, marievictoria875@gmail.com, rmoar@google.com, 
	shuah@kernel.org, brendan.higgins@linux.dev
Cc: mark.rutland@arm.com, elver@google.com, dvyukov@google.com, 
	lucas.demarchi@intel.com, thomas.hellstrom@linux.intel.com, 
	rodrigo.vivi@intel.com, linux-kselftest@vger.kernel.org, 
	kunit-dev@googlegroups.com, kasan-dev@googlegroups.com, 
	intel-xe@lists.freedesktop.org, dri-devel@lists.freedesktop.org, 
	linux-kernel@vger.kernel.org, Stephen Rothwell <sfr@canb.auug.org.au>, 
	David Gow <davidgow@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="j9/C78ff";       spf=pass
 (google.com: domain of 30hqtaagkcccqn8vqt19t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::649 as permitted sender) smtp.mailfrom=30HqtaAgKCccqn8vqt19t11tyr.p1zxn5n0-qr8t11tyrt41725.p1z@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
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

From: Marie Zhussupova <marievic@google.com>

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
Signed-off-by: David Gow <davidgow@google.com>
---

No changes in v4:
v3: https://lore.kernel.org/linux-kselftest/20250815103604.3857930-6-marievic@google.com/

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
2.51.0.261.g7ce5a0a67e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250826091341.1427123-6-davidgow%40google.com.

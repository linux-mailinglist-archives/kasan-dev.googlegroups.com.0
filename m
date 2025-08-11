Return-Path: <kasan-dev+bncBDQ67ZGAXYCBBJ6Y5HCAMGQE2RUE33A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id 798B3B21820
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 00:18:17 +0200 (CEST)
Received: by mail-il1-x13c.google.com with SMTP id e9e14a558f8ab-3e3f0a3f62asf118265185ab.2
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Aug 2025 15:18:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754950696; cv=pass;
        d=google.com; s=arc-20240605;
        b=aNQkaeeud6aS6cbZZeswr6Vf/Kp5kA268Te9TjLAXESpWbWBTcJ1+Fh4I6HOuZ6Cfy
         ip4mHznTgLN0cTT+LOt9Jo6z0K2n0v30trnGhl0SDqZ+l1Z8Gzf5LuzPcv6i1ry5dJgt
         lEZ3kxQSLoZHRAgXO/ZZYpiyQbs6+BqrYuLjjoQ983GUmZYBslTELace3v2NDp8oZstY
         rPA8xA9B67Ys6yRao1cBWRedNmPmCPwQd72mhuq5fg4A9h6uckrz8408Nl8gmY/bj4+u
         gGbhdz0PNFMgfibawhLkMfjOgKanHfFFHadXJGKxbspTz2u1lGJVDmPqfXwCkOnivqYR
         Z1kA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=LQETHjbtWjAw5fzWlhib95pti3oYLtdJa5xW9wr+4gk=;
        fh=Oq2gjZlX857SSqNCXIlVccb9x0S+7KXM6eGvfAr6Mag=;
        b=GAJvS29MwohRU5ea8Qb2rAoaiDykkcdqbqOc2F1/VdvYJ+BfM6C0iwBpsh/F+hGzY4
         nPZeGJfsdg6cqtK5jrF31tK1zwpBE0vRhqT2QLLbcQd/0BhK4cAc8CvbyiMqd2dTFmdF
         j27edqE3+n86wSxtIZV/jnwddsADS+Me149QO07FGeklTpglY5oPK80uZMSD4KvGm4zN
         sg/PDW8Lkzt0RurF6RnhCdoLCGYspvykZUj3meBUIsW5rN5T0wPisrCrutqkXvdvc6uf
         XKSMG8ZR1a1D4yqNhPt1fQZ/aVL3mNIi/ctnnez67FQnR6c9FRCzxAVcjRh5d9ZWG2jd
         f6Yw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=DiL5coBy;
       spf=pass (google.com: domain of 3jmyaaagkcbmftkbxobvzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3JmyaaAgKCbMfTkbXobVZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--marievic.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754950696; x=1755555496; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=LQETHjbtWjAw5fzWlhib95pti3oYLtdJa5xW9wr+4gk=;
        b=TbRPQ+kMtacfZ/s1ZHiUflQk4FvLDASgHpWu7LSfSrijMYKjC/HrNhAGfQVZd/A1OZ
         cXlvjO5jUQ+exM3e7TE2JCCpLQYxxfh1HGOo+7Fi0P/BkOwWO285P8Ynm0wDXrSHFQZ6
         ueBufegpudSXZmWuPqOlsSvvYH2f+u2Pp3y45k8ok+OjwEA0qeAP4/5bEgp1BWnrFVDc
         ihRQsFw5JPqjBVsZ4UPH6WpDMrKulcCt2iSh7efg1yy8hU84+PAK/TT4oWSoaoHeM6GT
         nlf3oeBJOmZjZlj93RmJDuaCME0ApjCR3iV2B0UyeDKU1hHps90EhzzH/ZkMbK+AmJOq
         jD0Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754950696; x=1755555496;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=LQETHjbtWjAw5fzWlhib95pti3oYLtdJa5xW9wr+4gk=;
        b=MLk2c8ZoFbcDaNNuZiblNXH0oMeIfPDquExgxONH/34SPI/v+nvc0k4mKF2qRibNfM
         78jwwHApk1pYxlpaXLd3Pbc8/vK29KlpIKXZQ89V7uU96vnxRDBzeGOrGkK7k3k7kYsd
         ycjACKbw3rRDAO2TmbEtYsqVOSSVt1Kbplm0mM0IYgVu7NwSHBTX0MANgl0gsR1xkMe7
         NR2DRLGieaRY3STT33WpOHY2D7clB8KXXwvga4KgkIFP4kyZiydFEnVjocXA4MBHZFX3
         NHhcTH8QvwpLVptQ5w9YFqtkAzbZYwZfQkK9HVRDVb1u1RNyeXgCF3rAJrDkDO1CKsm1
         cmYg==
X-Forwarded-Encrypted: i=2; AJvYcCX36lLNZWTvqHwmwTmCFmrJkziZN3Q+VuEE32BMO3Gs7q9OpSnC3uGtnB0UXFkxKl+isMAXeQ==@lfdr.de
X-Gm-Message-State: AOJu0YzTFGnO7USP7J3SvzRkK7RU9/NKizBV9XLwftSHxqCzHEgKNVt2
	KMD6oihBVWt9foG9l7snjRvFnCUQTd+MAzWpkBoEDzPYQA/k6ySrzIqX
X-Google-Smtp-Source: AGHT+IGNKiMoCyOgGwZdVqNqisLDRB9Mifje5bZmyZmnAsh1tGFnan0VwbbdaZ9QOjT4Nzw3kOxtEQ==
X-Received: by 2002:a05:6e02:2787:b0:3e3:d197:b578 with SMTP id e9e14a558f8ab-3e55af451f5mr21754995ab.8.1754950696074;
        Mon, 11 Aug 2025 15:18:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdLgdsQVQpGRjNPtauu2O/ZoAwKNeGDFNQTxi2SOoaTqw==
Received: by 2002:a05:6e02:10:b0:3e5:50da:c386 with SMTP id
 e9e14a558f8ab-3e550dac764ls13537895ab.2.-pod-prod-05-us; Mon, 11 Aug 2025
 15:18:15 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXi/KyDP2ACgGPelXuC9bw5dihUCJo9sx0zb0GiaB2K3ik1TMrTCXjv6rdMV68CNAJbcHK1idJV1qQ=@googlegroups.com
X-Received: by 2002:a05:6e02:154d:b0:3e5:4bc5:539a with SMTP id e9e14a558f8ab-3e55b00831bmr19858075ab.19.1754950695221;
        Mon, 11 Aug 2025 15:18:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754950695; cv=none;
        d=google.com; s=arc-20240605;
        b=Gjda/H7ngrgL9yO2ps51PO80+X4Zcm0mKEouHlzWfHujs/fZ1fCqEBQS3Gxgr1Krgn
         sQsoqjm1Kqvjh05beX+QGhVeUWXot6GsIx5AfbXuSfkBXbS6lnoILU8AWOhwm0izZYAp
         X+GymMdJBiknpoiln0QFW84KIyMNyE0y/+dV+n/uAafi54wqdAaQZz060XhjpjdG6Xbq
         xsTHOd+kbzKsHvM1HnOTLN/mPvg5pEScQtoB7WH14GxEGxT7gPq67FQFnM7AES94FTcy
         QGZNkJHQ4dQe15YDoNjbkyHvtr6zKPCEp229x5Y/jtyQUOO/4HZBZndSeGa6IKTnAhvt
         ah+w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=fiy0G3ZehM6qHvT1KaF1SbtcEnbY2+UsDdYSolHQCqU=;
        fh=4umXy8P6tW/nV0nPP8YIBo8nLQ3+3OZvc3pZWd01qx0=;
        b=XbGsiFvpfESt9xhBL1TBcmXGSNj2mIOwE4Byj0mipZt1uuWS4UH8/QB8MCcUUIThU2
         dMoMiMDDMRk+6rjXkxEnXJ4BtiqqA9SrW9LfHsfR9f82DzbBlAMlZkJVvo/Tmk/4pAZB
         liUMBQhaj5MiwcWir4i4sYZpHZl7L0cKal5EK8bGfoR2WxS2YjVkhqmoWifWRGI/b1j9
         y35tucTJRzlJKAOKC443HzekMR/USA9lRcLptZc2TsyXwq9MDncS0qwe3OcwoZNuipUv
         Ih6LuDNLpWoJ7xQhlXUhms7BD90ekruoHl32tw4YObXLSbvB34Lznp6hJul0aCncwwt8
         WMAA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=DiL5coBy;
       spf=pass (google.com: domain of 3jmyaaagkcbmftkbxobvzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3JmyaaAgKCbMfTkbXobVZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--marievic.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-50ae9bcf019si410305173.5.2025.08.11.15.18.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 11 Aug 2025 15:18:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3jmyaaagkcbmftkbxobvzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id d75a77b69052e-4b0791a8e8dso137455191cf.2
        for <kasan-dev@googlegroups.com>; Mon, 11 Aug 2025 15:18:15 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX/dd0s+p7nbKu/o/+xkTd5Ok8sjvdlXU8IqA8Ht1JHcGerMBotCjcz29UtQBNvXGmsSQ5L1Tzuf7s=@googlegroups.com
X-Received: from qknwc5.prod.google.com ([2002:a05:620a:7205:b0:7e8:51a1:6a28])
 (user=marievic job=prod-delivery.src-stubby-dispatcher) by
 2002:a05:620a:4843:b0:7e8:1718:daf4 with SMTP id af79cd13be357-7e82c65c638mr1611302285a.16.1754950694498;
 Mon, 11 Aug 2025 15:18:14 -0700 (PDT)
Date: Mon, 11 Aug 2025 22:17:38 +0000
In-Reply-To: <20250811221739.2694336-1-marievic@google.com>
Mime-Version: 1.0
References: <20250811221739.2694336-1-marievic@google.com>
X-Mailer: git-send-email 2.51.0.rc0.205.g4a044479a3-goog
Message-ID: <20250811221739.2694336-7-marievic@google.com>
Subject: [PATCH v2 6/7] kunit: Add example parameterized test with direct
 dynamic parameter array setup
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
 header.i=@google.com header.s=20230601 header.b=DiL5coBy;       spf=pass
 (google.com: domain of 3jmyaaagkcbmftkbxobvzhhzex.vhfdtltg-wxozhhzexzkhnil.vhf@flex--marievic.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3JmyaaAgKCbMfTkbXobVZhhZeX.VhfdTlTg-WXoZhhZeXZkhnil.Vhf@flex--marievic.bounces.google.com;
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

Introduce example_params_test_with_init_dynamic_arr(). This new
KUnit test demonstrates directly assigning a dynamic parameter
array, using the kunit_register_params_array() macro, to a
parameterized test context.

It highlights the use of param_init() and param_exit() for
initialization and exit of a parameterized test, and their
registration to the test case with KUNIT_CASE_PARAM_WITH_INIT().

Signed-off-by: Marie Zhussupova <marievic@google.com>
---

Changes in v2:

- kunit_array_gen_params() is now explicitly passed to
  KUNIT_CASE_PARAM_WITH_INIT() to be consistent with
  the parameterized test being defined by the existence
  of the generate_params() function.
- param_init() was changed to output a log at the start
  of a parameterized test.
- The parameter array was changed to be allocated
  using kunit_kmalloc_array(), a KUnit memory allocation
  API, as that would be the preferred/easier method. To
  still demonstrate a use of param_exit(), it now outputs
  a log at the end of the parameterized test.
- The comments and the commit message were changed to
  reflect the parameterized testing terminology. See
  the patch series cover letter change log for the
  definitions.

---
 lib/kunit/kunit-example-test.c | 104 +++++++++++++++++++++++++++++++++
 1 file changed, 104 insertions(+)

diff --git a/lib/kunit/kunit-example-test.c b/lib/kunit/kunit-example-test.c
index f2819ee58965..ff21511889a4 100644
--- a/lib/kunit/kunit-example-test.c
+++ b/lib/kunit/kunit-example-test.c
@@ -393,6 +393,107 @@ static void example_params_test_with_init(struct kunit *test)
 	kunit_put_resource(res);
 }
 
+/*
+ * Helper function to create a parameter array of Fibonacci numbers. This example
+ * highlights a parameter generation scenario that is:
+ * 1. Not feasible to fully pre-generate at compile time.
+ * 2. Challenging to implement with a standard generate_params() function,
+ * as it only provides the previous parameter, while Fibonacci requires
+ * access to two preceding values for calculation.
+ */
+static void *make_fibonacci_params(struct kunit *test, size_t seq_size)
+{
+	int *seq;
+
+	if (seq_size <= 0)
+		return NULL;
+	/*
+	 * Using kunit_kmalloc_array here ties the lifetime of the array to
+	 * the parameterized test i.e. it will get automatically cleaned up
+	 * by KUnit after the parameterized test finishes.
+	 */
+	seq = kunit_kmalloc_array(test, seq_size, sizeof(int), GFP_KERNEL);
+
+	if (!seq)
+		return NULL;
+	if (seq_size >= 1)
+		seq[0] = 0;
+	if (seq_size >= 2)
+		seq[1] = 1;
+	for (int i = 2; i < seq_size; i++)
+		seq[i] = seq[i - 1] + seq[i - 2];
+	return seq;
+}
+
+/*
+ * This is an example of a function that provides a description for each of the
+ * parameters.
+ */
+static void example_param_dynamic_arr_get_desc(struct kunit *test, const void *p, char *desc)
+{
+	const int *fib_num = p;
+
+	snprintf(desc, KUNIT_PARAM_DESC_SIZE, "fibonacci param: %d", *fib_num);
+}
+
+/*
+ * Example of a parameterized test param_init() function that registers a dynamic
+ * array of parameters.
+ */
+static int example_param_init_dynamic_arr(struct kunit *test)
+{
+	size_t seq_size;
+	int *fibonacci_params;
+
+	kunit_info(test, "initializing parameterized test\n");
+
+	seq_size = 6;
+	fibonacci_params = make_fibonacci_params(test, seq_size);
+
+	if (!fibonacci_params)
+		return -ENOMEM;
+
+	/*
+	 * Passes the dynamic parameter array information to the parameterized test
+	 * context struct kunit. The array and its metadata will be stored in
+	 * test->parent->params_array. The array itself will be located in
+	 * params_data.params.
+	 *
+	 * Note that you will need to pass kunit_array_gen_params() as the
+	 * generator function to KUNIT_CASE_PARAM_WITH_INIT() when registering
+	 * a parameter array this route.
+	 */
+	kunit_register_params_array(test, fibonacci_params, seq_size,
+				    example_param_dynamic_arr_get_desc);
+	return 0;
+}
+
+/*
+ * Example of a parameterized test param_exit() function that outputs a log
+ * at the end of the parameterized test. It could also be used for any other
+ * teardown logic.
+ */
+static void example_param_exit_dynamic_arr(struct kunit *test)
+{
+	kunit_info(test, "exiting parameterized test\n");
+}
+
+/*
+ * Example of test that uses the registered dynamic array to perform assertions
+ * and expectations.
+ */
+static void example_params_test_with_init_dynamic_arr(struct kunit *test)
+{
+	const int *param = test->param_value;
+	int param_val;
+
+	/* By design, param pointer will not be NULL. */
+	KUNIT_ASSERT_NOT_NULL(test, param);
+
+	param_val = *param;
+	KUNIT_EXPECT_EQ(test, param_val - param_val, 0);
+}
+
 /*
  * Here we make a list of all the test cases we want to add to the test suite
  * below.
@@ -414,6 +515,9 @@ static struct kunit_case example_test_cases[] = {
 	KUNIT_CASE_PARAM(example_params_test, example_gen_params),
 	KUNIT_CASE_PARAM_WITH_INIT(example_params_test_with_init, kunit_array_gen_params,
 				   example_param_init, NULL),
+	KUNIT_CASE_PARAM_WITH_INIT(example_params_test_with_init_dynamic_arr,
+				   kunit_array_gen_params, example_param_init_dynamic_arr,
+				   example_param_exit_dynamic_arr),
 	KUNIT_CASE_SLOW(example_slow_test),
 	{}
 };
-- 
2.51.0.rc0.205.g4a044479a3-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250811221739.2694336-7-marievic%40google.com.

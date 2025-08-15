Return-Path: <kasan-dev+bncBDQ67ZGAXYCBBKM37TCAMGQENH4YPYQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53b.google.com (mail-pg1-x53b.google.com [IPv6:2607:f8b0:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id 9A251B27E60
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Aug 2025 12:36:27 +0200 (CEST)
Received: by mail-pg1-x53b.google.com with SMTP id 41be03b00d2f7-b471737c5efsf1245794a12.1
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Aug 2025 03:36:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755254186; cv=pass;
        d=google.com; s=arc-20240605;
        b=RxrL0eAPrhVM3pE7b4qwPccjUOP8S1mkrb6QpfERjCQ9YE3qB3l7TnIZrcYeML+YMM
         5c+Q/1MXWhw7/l3YNcz329atzY3c47ADzTmNlsvsub7jikSxwR5bnvGVWBrIoW/iIkmt
         w89RB6JCQZQCuvwuYQUJdJ1JlVuo/Y7vzxTCsT8F7fjJrIEy9twZlojP5RJkf5e5IV55
         ZDZvmsvJEGabC0nFXzO21jebG8GjvkyMip/ujVqMebf1bwpPd0dXmuNDM2aSd0r8xDcS
         Mrko5CuH1hYXvRvjTgwwFD0cXdLUfEOfhBEb3/6q7pYQHeBtb7Vvj3JnwWSSlkLIXqXm
         jW9g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=P1g6wp4Bp3wdT3PGRtJWo8CJFsTg0RQIG7TvBGYBess=;
        fh=w9BxbFvwhn+i0ev4G68zZkrNTX3dM9JHdA3lOTOIceA=;
        b=Kv2V2bc512Vqu5yMTbtqH6B57eX142f1H/7ZiaYf0PuryTjp3YyhotGsNtCVVzJXEx
         GP2413FjoJOQ/ljE+T9zHPOH0vsm9OM945PPqaNFUnaPiS5W8UrMwR1vVc8UJPM/xIcV
         TFNV4x4RW+O2djwoJ3wAneEnpmghbamdJV3HR2DD1oSFvYjats/mfPtuRKXUWljCy36l
         fzqZhmafSyUz9vurx/5OX1YiSywTr875m7/q2qYs9q7uaQLZneeOdvGlhcAhDFERKDuo
         oK1oHozJSsMZR+jWmsF5sN3+S64rxAGd5bMHwOghLmyHnO9oiJ5mUsiLvoSBtCm+zBTo
         Vnlg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=VcRBMDOP;
       spf=pass (google.com: domain of 3pw2faagkcyo0o5ws9wqu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3pw2faAgKCYo0o5ws9wqu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--marievic.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755254186; x=1755858986; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=P1g6wp4Bp3wdT3PGRtJWo8CJFsTg0RQIG7TvBGYBess=;
        b=i0zzbCqAGOhiBxvU1PVrdM4QSPeyeT/6vjrT4FxcOhZIojwlBQmOuWodYVUdZAU1sr
         Uc+9SbfMhyoUYzfes0VivfmRtx4dtqCnXXtZ6/Y8b2YG9O1kG1t7yYpxKLoARuzQhR/O
         FOz/7upiu78erI2A1kXURLqJHFNFQWPIFkx7hoMiy9wlbSrd0ht9x1eDsQQNPKB5JXz0
         rjD0goqiiRA1i+NVQm/rnWywEV1kghfnVScA9cWMuKbqwS+dAGu+EhxJauBOazjMrZQt
         coG8qXQVmOo+mHdjvq8HEb+vJqNdlAuMlNqT7yshCTKkA1RLMeL2QhjCkYEazau8bvS1
         X9AA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755254186; x=1755858986;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=P1g6wp4Bp3wdT3PGRtJWo8CJFsTg0RQIG7TvBGYBess=;
        b=EQrKfUqtl0AnXK7R51BkvMlIuS006Q4jgY5IWO4OGa+NGyIUlrb6UQ8LEsWopGspn9
         nljkq6APwkg2CpkHkrRJCSK2C2gjoaxI56TLzmHF9RzI8xuUrCem6nVsn97I1cDE8wgn
         Hv1wSnOP134/a0hfe+cBdO9r40H5GZP1s3H/mwHnbOtg2QHTnZbcaNdIN6NxDkCZ5OmD
         6rYeXoq90i4LF3xMQ4qnUGOJ0pmttPNbwFpDFn0GQ3GlWXMs/sDhVOLVQh2Ie/SRRRWb
         SIkVi7evoHpbNd0lfkzrV9wlXi5hR2HUyGY9nVlVi1Mf79dZL8ZY+ZwSSHMwdkxE9cI4
         QVPw==
X-Forwarded-Encrypted: i=2; AJvYcCW5FZL8BgmmX+3hlbksSniO1Gx00a7mhX8yEQMU4BlMXVAJenqRy7PFc0i/DIDvW8H1FMBSig==@lfdr.de
X-Gm-Message-State: AOJu0YyJZ3GzRO0h5MZ5sQJOesNaLaH9eZ/V27tO4fD1740iiigJ8uyz
	4fSm6uGI8lDoN/3p/I3JWRBM06K5NkFG8pOH9z9KtIwvieh8lzhg0E5b
X-Google-Smtp-Source: AGHT+IHyGXQFoIWIfHn9xVBd7QgQS1km6bNtkfbFJKQKzm7Daz2bZ/xRgm3wrdfeKS+JoqWq5mlhUw==
X-Received: by 2002:a17:90b:380b:b0:31f:6ddd:eef with SMTP id 98e67ed59e1d1-32341ececcamr2412130a91.21.1755254186008;
        Fri, 15 Aug 2025 03:36:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdhRFyZm8ThTdY5eAPZHLC/Zg4RBaiOnS+z76tsuf2nsw==
Received: by 2002:a17:90b:4a8a:b0:311:b6ba:c5da with SMTP id
 98e67ed59e1d1-32326bf76abls2070798a91.1.-pod-prod-05-us; Fri, 15 Aug 2025
 03:36:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUewSbcxmPm/VvwFOTV6rpz/CpBV/KcoROGNRXiIz5yqL4s0oey2R1mWkGwif9JQlkw1dfpiI5PGN4=@googlegroups.com
X-Received: by 2002:a17:90b:2f8d:b0:31e:8203:4b9d with SMTP id 98e67ed59e1d1-32341ef0a75mr2419755a91.29.1755254184742;
        Fri, 15 Aug 2025 03:36:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755254184; cv=none;
        d=google.com; s=arc-20240605;
        b=ZpGJ+D/nUTaEHBbHqfQ+0UKggDZ2uvIO4AMMX5ZZR0e1R+2DSqGiYSS1Jl10z6k+JF
         PWgB0kkdoFq0s95qfk/gmXcUO71eglejmgrmdCwJ1LOYyITPqmOqB4px4DT8dT/p6WDH
         CM/r9rV86+uqDszYMyrpFV90FHFVVHn27W3c2bKCVGJf0v0V2SexL7acmq1Cnstm4vdR
         /MMYk9Fwc1QliDp+b0AAlOd/JVV1pGIdhoX2sOxmLh4rtt/KwLZEjv+4DgCInbF6k+89
         BXUgfj4dJyef/vdTuGvtYobUpGaFzLIulau7640QOlemmShewIbJB9zEAlX6BPu0zuRP
         DiSg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=N5BvlszSrzL55yCb3EusIjjVMhIlB9YqkU/uZs3QISs=;
        fh=RA4ajpFmE2Dv23H5S0++D57RjvHm6rmrbwAbdcTkEOw=;
        b=Clgjs4xNj/v82gfdf+FaUAgsojyhha12mnXvN3d2L7U7dtrhV2np+Tbzkf9ij0RbTB
         Z/omJe5IwBYesG7YJey3tVig43kp6T0dTQxKHYxjkR0U1XeJ13XBe5sgxcq54MgUUFDh
         PlGXtb/O45qt7Don4DtOw78iZQd6USEIQHb8ZM1m/d82tF+9TO+1klg80nM6mBkP/IRl
         PV06eRHAjglI9rNRHWg+XMcR1OxymEiQHidO1+Q53S9gEeEh8OfXW2tcP0fxxANvO2ux
         UUDRPK7d/WC2Lpb7G8PBRPaX3PsEg0V2JxA3AURKCW7yf+29nF+5vQ3vIZI6PFu6nIo7
         l5Ow==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=VcRBMDOP;
       spf=pass (google.com: domain of 3pw2faagkcyo0o5ws9wqu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3pw2faAgKCYo0o5ws9wqu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--marievic.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-32330f3d7f8si161425a91.1.2025.08.15.03.36.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Aug 2025 03:36:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3pw2faagkcyo0o5ws9wqu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id 6a1803df08f44-70a9f534976so56538626d6.2
        for <kasan-dev@googlegroups.com>; Fri, 15 Aug 2025 03:36:24 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWkQVsbKIwgUNDAomCDVLY9MJ3JogyDDOwEVqs0k4tY5FB0Cp1mzBLhwwL06vmkVfSvb9Nk0x2L/Ks=@googlegroups.com
X-Received: from qvbfo14.prod.google.com ([2002:ad4:5f0e:0:b0:709:b8bf:588f])
 (user=marievic job=prod-delivery.src-stubby-dispatcher) by
 2002:a05:6214:1c85:b0:709:e492:e0da with SMTP id 6a1803df08f44-70ba7cb68c6mr14801986d6.49.1755254183707;
 Fri, 15 Aug 2025 03:36:23 -0700 (PDT)
Date: Fri, 15 Aug 2025 10:36:03 +0000
In-Reply-To: <20250815103604.3857930-1-marievic@google.com>
Mime-Version: 1.0
References: <20250815103604.3857930-1-marievic@google.com>
X-Mailer: git-send-email 2.51.0.rc1.167.g924127e9c0-goog
Message-ID: <20250815103604.3857930-7-marievic@google.com>
Subject: [PATCH v3 6/7] kunit: Add example parameterized test with direct
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
 header.i=@google.com header.s=20230601 header.b=VcRBMDOP;       spf=pass
 (google.com: domain of 3pw2faagkcyo0o5ws9wqu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--marievic.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3pw2faAgKCYo0o5ws9wqu22uzs.q20yo6o1-rs9u22uzsu52836.q20@flex--marievic.bounces.google.com;
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

Reviewed-by: Rae Moar <rmoar@google.com>
Reviewed-by: David Gow <davidgow@google.com>
Signed-off-by: Marie Zhussupova <marievic@google.com>
---
Changes in v3:
v2: https://lore.kernel.org/all/20250811221739.2694336-7-marievic@google.com/
- No changes.

Changes in v2:
v1: https://lore.kernel.org/all/20250729193647.3410634-9-marievic@google.com/
- kunit_array_gen_params() is now explicitly passed to
  KUNIT_CASE_PARAM_WITH_INIT() to be consistent with the parameterized test
  being defined by the existence of the generate_params() function.
- param_init() was changed to output a log at the start of a parameterized
  test.
- The parameter array was changed to be allocated using kunit_kmalloc_array(),
  a KUnit memory allocation API, as that would be the preferred/easier method.
  To still demonstrate a use of param_exit(), it now outputs a log at the end
  of the parameterized test.
- The comments and the commit message were changed to reflect the
  parameterized testing terminology. See the patch series cover letter
  change log for the definitions.

---
 lib/kunit/kunit-example-test.c | 104 +++++++++++++++++++++++++++++++++
 1 file changed, 104 insertions(+)

diff --git a/lib/kunit/kunit-example-test.c b/lib/kunit/kunit-example-test.c
index 3e858367be01..9452b163956f 100644
--- a/lib/kunit/kunit-example-test.c
+++ b/lib/kunit/kunit-example-test.c
@@ -388,6 +388,107 @@ static void example_params_test_with_init(struct kunit *test)
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
@@ -409,6 +510,9 @@ static struct kunit_case example_test_cases[] = {
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
2.51.0.rc1.167.g924127e9c0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250815103604.3857930-7-marievic%40google.com.

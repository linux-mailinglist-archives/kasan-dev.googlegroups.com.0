Return-Path: <kasan-dev+bncBC6OLHHDVUOBBU7VWXCQMGQEOZWOL3Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id DAC21B3585F
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Aug 2025 11:13:57 +0200 (CEST)
Received: by mail-pf1-x43c.google.com with SMTP id d2e1a72fcca58-771e2f5b5dcsf2861962b3a.0
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Aug 2025 02:13:57 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756199636; cv=pass;
        d=google.com; s=arc-20240605;
        b=R5lBAiEBRDvv1/WUXkk4uryxVbwwb6kpIVEe1Je7nqIhJmqvigZc11BHAcu/ZCzITw
         N9vaKR90eU33T0xHlJ3KSnMeidDT62iOc6PazmaVXk28J3NjC3U8IrEEHR3u+S6RhFRY
         WgMPAbT5ggoDBnSbrNr3Yi4VMGjLFxL4+7VQhy7sSpjHDSTSt1j9OhrMtpBKT0vTIuIe
         LzHwXbQfvhZaqAncBMXverWmD0XyF8vqUUVL6oTZpR1eAaUTSZrP5zoU4SqTXMIMs8LM
         FwojICpNRJtnEyQfjoeliYpGPhU0suY/jlX9mWl7GfQn8ez+O4n8uCsHoMY0fSIkArV5
         WkoQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=+OVC7T5e+oaIPZotqUjwNlyzpidDLDOFxe54t5RPWFU=;
        fh=LHwwqfkeDhZ4Qa+WfTvBvYUjnPXMM7UG1PnxgaAS444=;
        b=EZXQCENfMA2GYO85AQ2quv+Ph3vOmAHnwX7fzDcja4WBef9ugYXDDLDasbJg8RgR+C
         vagAEzPgs651u4f8K9LnjfbPrVBOxarcVVM1IkUlPS20ylHsCAzAmPq0iLRjqhP1mH5+
         S8Ec1RO0mx/8rleij93nHSdjEeU8M+g4ZtSPh2F3k4UvrY1Xc5izpK3uhG7YqupNReNS
         vkRCBAzHHlVaPoXMkh2+HgTZc7Rd4JZ9g3bEXIw44VIxMbl7LONKbHFyhy7WWEdZayxl
         1PfLgJdL/CrFko84QVSJSxAXyeI+7pYUZb8/dIRzxub478+VoVAq9CEmNMXGAWvVdfAA
         3k0w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=OwmrJ6SQ;
       spf=pass (google.com: domain of 30nqtaagkcckspaxsv3bv33v0t.r31zp7p2-stav33v0tv63947.r31@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::549 as permitted sender) smtp.mailfrom=30nqtaAgKCckspAxsv3Bv33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756199636; x=1756804436; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=+OVC7T5e+oaIPZotqUjwNlyzpidDLDOFxe54t5RPWFU=;
        b=ccrDe1xOTnXXv2ujrsk+8k89A9yUY/cc/gkB2kuJ7TOB60EJJP3BcvkedNuTlMzlIr
         uIAJD1gB/jXSUuksMiM3xBSDYl8t+G3N+umN+ypjyh58kZrOYEYA6SwP74GjYHkQK0dG
         sV8r7Uh0Phe0Je/Ta3nRUwLVluaMk71GJ+tjzDK4gkS15adBcuCptcFIK1pwzF/Q5ube
         KHBSYDG7Teu/grcdEQzvFNEUEwGKulVQ7f7aSMWtafcohgm/HFKUz8a2NBiXxO++k3yW
         IfU4sTg7yPFwyDn/BUdny3Heutl2qFHWpwAZUyghPHY3MmVFnbJj47ugVS1ZYjfuPgaG
         UYRw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756199636; x=1756804436;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+OVC7T5e+oaIPZotqUjwNlyzpidDLDOFxe54t5RPWFU=;
        b=ky0I/C2YRQt3y1YhonodAnJzPa5tQpi3rzbfVMljJkvxrgKnQRn0EqBz3FdIP42BvZ
         b26/C/l7/mzoAz6cUWDDL29knMf31M2IFelqH1kxMGHr8BN6kMMXzqWPc6x/s+o6G7a+
         8syYeTaJqQkc9fckuJGIZnfawsHASKkCfQe5jEVxAcsKB6w/28wXjKbwKfEAe6OOLIVw
         sRqqun80tpaO63YK99TsJcaSWPtkyoMjY4PqadO4Cp23N5CYG8pah1k14aZ6pliGl+mO
         GB90DrhIxZrO5Q5/ez26abmOtIGV9My4TAm3w0s2UjajeWJmD7rdqOZ448+SsEphuME6
         z0iA==
X-Forwarded-Encrypted: i=2; AJvYcCV6W+X4VhVxVheGN1i4O9eqL+X/tUIDz4HhUL2G822DQEk4rkat027JYNOEhuYEC3PTScN1kw==@lfdr.de
X-Gm-Message-State: AOJu0YzclxBf6AMJ/xt2Q1V8hob9Yx69avlw7HlV2ydRerIhLFhW1VFw
	pYJ3mScI65/oljDA+/IyWTZa0oO6Qfnk9J5imGUn1d/wl6fy3fBBqI9j
X-Google-Smtp-Source: AGHT+IFJCyR1U12veU5WsM55la72KQDn/5R6MpKK1WrIY7KX/7RHqgU9V3cJTsBja5/bXN32L+iOjA==
X-Received: by 2002:a05:6a00:bd12:b0:76b:f0ac:e7b2 with SMTP id d2e1a72fcca58-7702fa09c62mr20788844b3a.13.1756199636148;
        Tue, 26 Aug 2025 02:13:56 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfWYGBdYya94wulKDSH83X2LdqlRUhb8ztO8ve1QkzA1w==
Received: by 2002:a05:6a00:7705:b0:771:f987:3f6b with SMTP id
 d2e1a72fcca58-771f9874085ls585629b3a.0.-pod-prod-08-us; Tue, 26 Aug 2025
 02:13:54 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVDzwvJ0lkJ1f2G0vdKFhBwSwpNen0mH/JQZhioddLPHEqXxTm8JBhetzPp9sP+/IVSFgk+kfaVZr0=@googlegroups.com
X-Received: by 2002:a05:6a20:1582:b0:240:9126:2bde with SMTP id adf61e73a8af0-24340d5e4cemr22022735637.46.1756199634645;
        Tue, 26 Aug 2025 02:13:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756199634; cv=none;
        d=google.com; s=arc-20240605;
        b=cqogRQBgIfjb1D6zTf9N79wBNMlYeRKKTYYPCZF4EJfu2W1xGNuQ0wVTzNuF39FrBc
         +FWb+V9rork/GAIeKnMFvVM+8vMSFMlI+jc7bP/SnFdBwygdIU3Z3l+7AO0V5tiZbVhU
         ahBDT8d8U0mtYd0WTUinEzvqjiBYjDjGJcZgIwLXoR/R+ccN36fpWhtiuTadpqCnBDYZ
         h4HI2dQSdj05r3zYHSePLwr4jP70KgE3RbRRpRXlrY2RHfvx1QjKP7Q8/7K0pasUOKv5
         cLaA3NvggmEmXsIASvHxVZcEofhCVxfnN6YalxYp5lO6g/gL16puAtvrCLnji2cOddYE
         hEPg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=r6YJBLokWG2Gb5OXsNbbrh9Xzkxl6kNwLj7uGaP0ytI=;
        fh=LadUp5W1pV6YC68k0t0bMaD/n9sUpvbLyZOcOsKcioM=;
        b=P5Tr7ZXXne1XjVGM7FTUQjmLLriKq8b2zsoIcRADy03LWIPbjNdzr8KHM8InF7Z/B/
         voM2qqHoQKs/BAumH16d88gJBiPAfPx0VMFqJs1wdGTrrPWPmXmXlXULRkHqxZWpxyni
         5Tt/G0FOF5ScSW+70k6QeI4lYcS8Xdi9qXVCet3nmJ04te/Spk1YPzcpQOSyT3uS7WUh
         BC09He3eLBtRTS3HPce0dHB5QrCTXYShqnVdIVDndJTkAmuBpztzeBJ04CMX5EZGr73q
         /Zorpc/iOIa+j5+1PiMa7YVcvWaWgXyJZ8FE/JMh5ddSJuOh9YF/J2742Ocq2Nq2Qfu4
         GAkQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=OwmrJ6SQ;
       spf=pass (google.com: domain of 30nqtaagkcckspaxsv3bv33v0t.r31zp7p2-stav33v0tv63947.r31@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::549 as permitted sender) smtp.mailfrom=30nqtaAgKCckspAxsv3Bv33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x549.google.com (mail-pg1-x549.google.com. [2607:f8b0:4864:20::549])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-b49ddd31e93si306836a12.1.2025.08.26.02.13.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Aug 2025 02:13:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of 30nqtaagkcckspaxsv3bv33v0t.r31zp7p2-stav33v0tv63947.r31@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::549 as permitted sender) client-ip=2607:f8b0:4864:20::549;
Received: by mail-pg1-x549.google.com with SMTP id 41be03b00d2f7-b4c32f731e7so330424a12.0
        for <kasan-dev@googlegroups.com>; Tue, 26 Aug 2025 02:13:54 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUxvTGegN96OZNKfpPbEuq6VtqVbBGrU07+Cr+T4RAnkXP5YN+JbhaflnYEzJ1iRN07Mlkjq4EZgUU=@googlegroups.com
X-Received: from pjbpm5.prod.google.com ([2002:a17:90b:3c45:b0:31f:6ddd:ef5])
 (user=davidgow job=prod-delivery.src-stubby-dispatcher) by
 2002:a05:6a20:c202:b0:243:6f08:86b4 with SMTP id adf61e73a8af0-2436f088fe5mr8170082637.39.1756199634209;
 Tue, 26 Aug 2025 02:13:54 -0700 (PDT)
Date: Tue, 26 Aug 2025 17:13:36 +0800
In-Reply-To: <20250826091341.1427123-1-davidgow@google.com>
Mime-Version: 1.0
References: <20250826091341.1427123-1-davidgow@google.com>
X-Mailer: git-send-email 2.51.0.261.g7ce5a0a67e-goog
Message-ID: <20250826091341.1427123-7-davidgow@google.com>
Subject: [PATCH v4 6/7] kunit: Add example parameterized test with direct
 dynamic parameter array setup
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
 header.i=@google.com header.s=20230601 header.b=OwmrJ6SQ;       spf=pass
 (google.com: domain of 30nqtaagkcckspaxsv3bv33v0t.r31zp7p2-stav33v0tv63947.r31@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::549 as permitted sender) smtp.mailfrom=30nqtaAgKCckspAxsv3Bv33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--davidgow.bounces.google.com;
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
Signed-off-by: David Gow <davidgow@google.com>
---
Changes in v4:
v3: https://lore.kernel.org/linux-kselftest/20250815103604.3857930-7-marievic@google.com/
- No changes.

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
2.51.0.261.g7ce5a0a67e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250826091341.1427123-7-davidgow%40google.com.

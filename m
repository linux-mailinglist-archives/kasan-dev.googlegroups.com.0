Return-Path: <kasan-dev+bncBC6OLHHDVUOBBTPVWXCQMGQEJSIJ4TY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3a.google.com (mail-oa1-x3a.google.com [IPv6:2001:4860:4864:20::3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 13BCEB35856
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Aug 2025 11:13:51 +0200 (CEST)
Received: by mail-oa1-x3a.google.com with SMTP id 586e51a60fabf-30ccebc5babsf1337619fac.3
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Aug 2025 02:13:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756199630; cv=pass;
        d=google.com; s=arc-20240605;
        b=Qvlrhlb4wCwhkYPOzEib7kro6FrRVTQ/cp9mri49DwGWNQeoFFW+sGZnGm2wiHSOqC
         x6MykLOz1Zxi/ufK0p7j2pkhblc27AZbO7vwKRgUsiKQzww7gp4dHICXXIN4tWvqRYAX
         N2l+duf25S/P5oqpYWTrOE27GSNFILFhUYYGFMIxf63SzpZ4JMy3dAApBsl+cNQ7Cgq+
         j4IcCEg+70ENZ4TSPu7hi5QAUl58f7iMge5MGBz+yzS4QXqrfmqwODzon9RtiEiS5K8j
         qCeWLX70Mxa1UEkMQ2Cl2FSEqjGW6k7AOtoIIKFPQgWQMm8SatMkays4u3IpuVOEvBp3
         p8Uw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=utJpYrqPMA7tZgViv0+5fRMyS0NGw5jSdkAvu1s95TE=;
        fh=NuHWyB1/7aNP4p5194avanWp/Klixp8+1Im28hbEuxo=;
        b=PxcIkdUyluZzPqaY7dGMcxKGeeSJBSSpZ8zh9atFswTEuued1BN9qFbut0Iz02osQQ
         QncymCXIIZLH0G9B3PEigXtjKGwIcex7tE/0VFffUaKZC5RpnLEKkprwIdn0PgOtUPYs
         FWgW5IpVf1lAD6q+D9x6iK04WI3nDHGwzjAKAQjhysI+qYvMz+z7/rTdGH/V62lee1ih
         yuex/LmwvuglHPPzKsZZd9oAT/AqGOf0RmYOoEak8sBwXDws7DaDedLhX6oMKBPew4iB
         go4jl4itfdpaL1OwDe8R1cH67EcUb80KFAMBZ7d1DvL/YDm2gbntgaThfg7aEPc+gld9
         +1lQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=3HKuXxAQ;
       spf=pass (google.com: domain of 3y3qtaagkccili3qlow4owwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::549 as permitted sender) smtp.mailfrom=3y3qtaAgKCcIli3qlow4owwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756199629; x=1756804429; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=utJpYrqPMA7tZgViv0+5fRMyS0NGw5jSdkAvu1s95TE=;
        b=JndtR5pXPGEt/gEjeBzKgDXXzlznTy3BHw01j2XAk5OnozRU8XeEHzSJ579Z3hlLCE
         Ae6MkumeNbPxek3Zt9ZcsWHb1zd+lCOGe+SUG8t7gURZtw7lcVoPM0NLxOA5Ebl4dLiW
         t/C1d9XE8opN9whacfWR4R7IVIgQQrTC+ZRn+66/NurRvirVNRjqwc+2VNx8nMDqufuR
         wPtXO8GgaDM/UBhT2fkCnMHePnOK/8zOk1LHugf+xaBmyicKPswwpa6BxN6c8qtj7idq
         CF4BDPTQ+A48CWs3wBbOkxekVS7DhYjegbDkHGHxo8OwvWALt30xeebdPzThgMCsP1+I
         np0Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756199629; x=1756804429;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=utJpYrqPMA7tZgViv0+5fRMyS0NGw5jSdkAvu1s95TE=;
        b=AgB9FsDoR3jRI9Mi9k+Zg878pZlV3cCZVLDTLeRj4NThg7xoj1upC+JXTboMJ/KaKo
         SbYNzv1cLDl85xB+6xgxGOD1kbMMlifqgwfe3wOuyF4CXzNAZMcwwruvtQe+H6ROOD1j
         p1M6sg4vJluzwntqkzencohBK5Z1jS5D+bUA8yDcsfyN+5x+mNq3Bk/nLzXXGYBFr9Ol
         c2knaMKEsZGko3b+Cxm0lvwJScGt3/gS6fRCPwfIYQp7JdYPYeGDme828HFWi6GqO20x
         gP/rUG88IJU2yg2oxeMF1W5SEvCFNtFHXziBBUMm/usDkdOfG6pWidvom0dUd138U6E+
         WDOw==
X-Forwarded-Encrypted: i=2; AJvYcCV9kCx3/ntfLZEpwtwDZF596qAm33XhIAzpTZO/zvx1YMpXxR5eYdYkxmp7/UrKWadRNTyICw==@lfdr.de
X-Gm-Message-State: AOJu0Yy+sY9WppMu+g1QlXmxgEFVO6OFCI7fVaagP3GiSfIOcZajJRt6
	SLE/Qvi2HRtvQKJ0kS3TTJBa3wiwAYz1RYlwwzIQgSem5+HeZ92bICUh
X-Google-Smtp-Source: AGHT+IE+mDYKy3pKZ4XQvIdXahv8uQg+UEaDafdSdwd/ruiPlL9ySb126yFA/rRX5IKgYmjaWc+4Nw==
X-Received: by 2002:a05:6871:289:b0:30b:8cb9:e70d with SMTP id 586e51a60fabf-314dcaa4d6emr8756827fac.4.1756199629660;
        Tue, 26 Aug 2025 02:13:49 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZf9t7yQ6t2ny2bfjt2AgAAF8AlUqy3DYSyxKCvDsONDdw==
Received: by 2002:a05:6871:e008:b0:2ef:3020:be7e with SMTP id
 586e51a60fabf-314c225e2edls1507769fac.1.-pod-prod-06-us; Tue, 26 Aug 2025
 02:13:48 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUjclXx2WgUM1lXmR1DWeL6d/Fkqrv/JehBS4Xpxpkfx/I8fQkRwjCyETJmKe83vKi7smIo9FJLI4I=@googlegroups.com
X-Received: by 2002:a05:6808:5092:b0:437:761b:9623 with SMTP id 5614622812f47-437853906a3mr7005385b6e.50.1756199628655;
        Tue, 26 Aug 2025 02:13:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756199628; cv=none;
        d=google.com; s=arc-20240605;
        b=IDur0BMfIMMyet+5g9NZ/d/buiecS6vZ9fpLhGvYmwTXN1ZafBQoUE79KGh8hUb2VZ
         KZxW/cGtc50FVYLwZYTuTZUBrAHZrg+IwIrRZ1MkLvhV8IeF/U0eH1eguOM/83qLD0QV
         k5AfvkaDEUK5GHWY6PZ0RuzixCzN9LED44c6DoPzRAH/C4oNdTcYwoK3+BNwxVQTSQiL
         kCYoznL82Fgra9cmPnKVfRlP45dgKYb7DD7gMtNzkm3DH2lTWpv5bm0+LwRsHEm6XA7Y
         61vjBik0PgUDLowUPOaouegKRAu0hQnoU5BgTzuRdOT/LFeI6okfKr93QlHmY4ruBUav
         z5Iw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=QTTACq/njMLngdxpMSOXC5XIjUnoWbM4E4SA6Lndzr0=;
        fh=y298QwBkIojM6aNELIci3JDij3tn+SEgYmizUXFOpQw=;
        b=aYWUtedAeGgFkyw2pG/gO5VzAJ0COJf59OgXPdXR/VKLAO1pP9JAKq7bWJ22oTENAs
         kmZrkqQ7q4aSTS98edM3Krb2hI5mSycAL4gvdRFu0QH6mIUI/M9PnGL7n2YFf8Irue3C
         GhYFbNYYAntLNdMr2cZZ1z9af6TLO2Ow/bOr2cUKcRsfJRi0n1d5x58STSNbUylLb2/u
         fW3cysR5ACFdoDNf+eyZROqwMTovThrbChtB/UxiopKmeL7D4wnR7M7+It1X/ErZ0o/u
         5v9GyFZup4rPUL+OCzrnPjvO2vfFlbxnEzD0fs11IEb7VvbPiKJi0ZaIVJZAJ2btUMyh
         FxCg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=3HKuXxAQ;
       spf=pass (google.com: domain of 3y3qtaagkccili3qlow4owwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::549 as permitted sender) smtp.mailfrom=3y3qtaAgKCcIli3qlow4owwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x549.google.com (mail-pg1-x549.google.com. [2607:f8b0:4864:20::549])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-437963df630si277427b6e.0.2025.08.26.02.13.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Aug 2025 02:13:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3y3qtaagkccili3qlow4owwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::549 as permitted sender) client-ip=2607:f8b0:4864:20::549;
Received: by mail-pg1-x549.google.com with SMTP id 41be03b00d2f7-b4716fc56a9so8219357a12.0
        for <kasan-dev@googlegroups.com>; Tue, 26 Aug 2025 02:13:48 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU/hOttElRdJvCS2A7juWpx5rwCd7qCBvXrpV3R48mdjcx6dqJYBqzzye5iy527MSqzSU06knic9w4=@googlegroups.com
X-Received: from plpj12.prod.google.com ([2002:a17:903:3d8c:b0:246:1edd:3919])
 (user=davidgow job=prod-delivery.src-stubby-dispatcher) by
 2002:a17:902:ccc4:b0:248:79d4:939e with SMTP id d9443c01a7336-24879d49812mr6538095ad.39.1756199627892;
 Tue, 26 Aug 2025 02:13:47 -0700 (PDT)
Date: Tue, 26 Aug 2025 17:13:32 +0800
In-Reply-To: <20250826091341.1427123-1-davidgow@google.com>
Mime-Version: 1.0
References: <20250826091341.1427123-1-davidgow@google.com>
X-Mailer: git-send-email 2.51.0.261.g7ce5a0a67e-goog
Message-ID: <20250826091341.1427123-3-davidgow@google.com>
Subject: [PATCH v4 2/7] kunit: Introduce param_init/exit for parameterized
 test context management
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
 header.i=@google.com header.s=20230601 header.b=3HKuXxAQ;       spf=pass
 (google.com: domain of 3y3qtaagkccili3qlow4owwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::549 as permitted sender) smtp.mailfrom=3y3qtaAgKCcIli3qlow4owwotm.kwusi0iv-lm3owwotmozw2x0.kwu@flex--davidgow.bounces.google.com;
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

Add (*param_init) and (*param_exit) function pointers to
`struct kunit_case`. Users will be able to set them via the new
KUNIT_CASE_PARAM_WITH_INIT() macro.

param_init/exit will be invoked by kunit_run_tests() once before and once
after the parameterized test, respectively. They will receive the
`struct kunit` that holds the parameterized test context; facilitating
init and exit for shared state.

This patch also sets param_init/exit to None in rust/kernel/kunit.rs.

Reviewed-by: Rae Moar <rmoar@google.com>
Reviewed-by: David Gow <davidgow@google.com>
Signed-off-by: Marie Zhussupova <marievic@google.com>
Signed-off-by: David Gow <davidgow@google.com>
---

No changes in v4:
v3: https://lore.kernel.org/linux-kselftest/20250815103604.3857930-3-marievic@google.com/

Changes in v3:
v2: https://lore.kernel.org/all/20250811221739.2694336-3-marievic@google.com/
- kunit_init_parent_param_test() now sets both the `struct kunit_case`
  and the `struct kunit` statuses as failed if the parameterized test
  init failed. The failure message was also changed to include the failure
  code, mirroring the kunit_suite init failure message.
- A check for parameter init failure was added in kunit_run_tests(). So,
  if the init failed, the framework will skip the parameter runs and
  update the param_test statistics to count that failure.
- Commit message formatting.

Changes in v2:
v1: https://lore.kernel.org/all/20250729193647.3410634-3-marievic@google.com/
- param init/exit were set to None in rust/kernel/kunit.rs to fix the
  Rust breakage.
- The name of __kunit_init_parent_test was changed to
  kunit_init_parent_param_test and its call was changed to happen only
  if the test is parameterized.
- The param_exit call was also moved inside the check for if the test is
  parameterized.
- KUNIT_CASE_PARAM_WITH_INIT() macro logic was change to not automatically
  set generate_params() to KUnit's built-in generator function. Instead,
  the test user will be asked to provide it themselves.
- The comments and the commit message were changed to reflect the
  parameterized testing terminology. See the patch series cover letter
  change log for the definitions.


---
 include/kunit/test.h | 25 +++++++++++++++++++++++++
 lib/kunit/test.c     | 27 ++++++++++++++++++++++++++-
 rust/kernel/kunit.rs |  4 ++++
 3 files changed, 55 insertions(+), 1 deletion(-)

diff --git a/include/kunit/test.h b/include/kunit/test.h
index 9766403afd56..fc8fd55b2dfb 100644
--- a/include/kunit/test.h
+++ b/include/kunit/test.h
@@ -92,6 +92,8 @@ struct kunit_attributes {
  * @name:     the name of the test case.
  * @generate_params: the generator function for parameterized tests.
  * @attr:     the attributes associated with the test
+ * @param_init: The init function to run before a parameterized test.
+ * @param_exit: The exit function to run after a parameterized test.
  *
  * A test case is a function with the signature,
  * ``void (*)(struct kunit *)``
@@ -128,6 +130,8 @@ struct kunit_case {
 	const char *name;
 	const void* (*generate_params)(const void *prev, char *desc);
 	struct kunit_attributes attr;
+	int (*param_init)(struct kunit *test);
+	void (*param_exit)(struct kunit *test);
 
 	/* private: internal use only. */
 	enum kunit_status status;
@@ -218,6 +222,27 @@ static inline char *kunit_status_to_ok_not_ok(enum kunit_status status)
 		  .generate_params = gen_params,				\
 		  .attr = attributes, .module_name = KBUILD_MODNAME}
 
+/**
+ * KUNIT_CASE_PARAM_WITH_INIT - Define a parameterized KUnit test case with custom
+ * param_init() and param_exit() functions.
+ * @test_name: The function implementing the test case.
+ * @gen_params: The function to generate parameters for the test case.
+ * @init: A reference to the param_init() function to run before a parameterized test.
+ * @exit: A reference to the param_exit() function to run after a parameterized test.
+ *
+ * Provides the option to register param_init() and param_exit() functions.
+ * param_init/exit will be passed the parameterized test context and run once
+ * before and once after the parameterized test. The init function can be used
+ * to add resources to share between parameter runs, and any other setup logic.
+ * The exit function can be used to clean up resources that were not managed by
+ * the parameterized test, and any other teardown logic.
+ */
+#define KUNIT_CASE_PARAM_WITH_INIT(test_name, gen_params, init, exit)		\
+		{ .run_case = test_name, .name = #test_name,			\
+		  .generate_params = gen_params,				\
+		  .param_init = init, .param_exit = exit,			\
+		  .module_name = KBUILD_MODNAME}
+
 /**
  * struct kunit_suite - describes a related collection of &struct kunit_case
  *
diff --git a/lib/kunit/test.c b/lib/kunit/test.c
index 587b5c51db58..0fe61dec5a96 100644
--- a/lib/kunit/test.c
+++ b/lib/kunit/test.c
@@ -641,6 +641,20 @@ static void kunit_accumulate_stats(struct kunit_result_stats *total,
 	total->total += add.total;
 }
 
+static void kunit_init_parent_param_test(struct kunit_case *test_case, struct kunit *test)
+{
+	if (test_case->param_init) {
+		int err = test_case->param_init(test);
+
+		if (err) {
+			kunit_err(test_case, KUNIT_SUBTEST_INDENT KUNIT_SUBTEST_INDENT
+				"# failed to initialize parent parameter test (%d)", err);
+			test->status = KUNIT_FAILURE;
+			test_case->status = KUNIT_FAILURE;
+		}
+	}
+}
+
 int kunit_run_tests(struct kunit_suite *suite)
 {
 	char param_desc[KUNIT_PARAM_DESC_SIZE];
@@ -678,6 +692,11 @@ int kunit_run_tests(struct kunit_suite *suite)
 			kunit_run_case_catch_errors(suite, test_case, &test);
 			kunit_update_stats(&param_stats, test.status);
 		} else {
+			kunit_init_parent_param_test(test_case, &test);
+			if (test_case->status == KUNIT_FAILURE) {
+				kunit_update_stats(&param_stats, test.status);
+				goto test_case_end;
+			}
 			/* Get initial param. */
 			param_desc[0] = '\0';
 			/* TODO: Make generate_params try-catch */
@@ -714,10 +733,16 @@ int kunit_run_tests(struct kunit_suite *suite)
 				param_desc[0] = '\0';
 				curr_param = test_case->generate_params(curr_param, param_desc);
 			}
+			/*
+			 * TODO: Put into a try catch. Since we don't need suite->exit
+			 * for it we can't reuse kunit_try_run_cleanup for this yet.
+			 */
+			if (test_case->param_exit)
+				test_case->param_exit(&test);
 			/* TODO: Put this kunit_cleanup into a try-catch. */
 			kunit_cleanup(&test);
 		}
-
+test_case_end:
 		kunit_print_attr((void *)test_case, true, KUNIT_LEVEL_CASE);
 
 		kunit_print_test_stats(&test, param_stats);
diff --git a/rust/kernel/kunit.rs b/rust/kernel/kunit.rs
index 41efd87595d6..b1c97f8029c7 100644
--- a/rust/kernel/kunit.rs
+++ b/rust/kernel/kunit.rs
@@ -210,6 +210,8 @@ pub const fn kunit_case(
         status: kernel::bindings::kunit_status_KUNIT_SUCCESS,
         module_name: core::ptr::null_mut(),
         log: core::ptr::null_mut(),
+        param_init: None,
+        param_exit: None,
     }
 }
 
@@ -229,6 +231,8 @@ pub const fn kunit_case_null() -> kernel::bindings::kunit_case {
         status: kernel::bindings::kunit_status_KUNIT_SUCCESS,
         module_name: core::ptr::null_mut(),
         log: core::ptr::null_mut(),
+        param_init: None,
+        param_exit: None,
     }
 }
 
-- 
2.51.0.261.g7ce5a0a67e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250826091341.1427123-3-davidgow%40google.com.

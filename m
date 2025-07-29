Return-Path: <kasan-dev+bncBDQ67ZGAXYCBB4GFUTCAMGQEVRE7NOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3e.google.com (mail-oa1-x3e.google.com [IPv6:2001:4860:4864:20::3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 8E11BB15389
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Jul 2025 21:37:22 +0200 (CEST)
Received: by mail-oa1-x3e.google.com with SMTP id 586e51a60fabf-2e94cfbbbc1sf3121225fac.3
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Jul 2025 12:37:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753817841; cv=pass;
        d=google.com; s=arc-20240605;
        b=bOUQ0xcU6Yqs3ZNmI3DBp5ACyScGdL/K5J7OVE0U1i1ePdcZN70LP5PH5NYGuvaVUl
         G8BUUajxSxmrmyJ3sALiq+dlAbEjJP2KIlHviTYEQGxtpOMSHnieFJqvtXU5TvykFM8n
         VJf9ZRuSQ8/BPbBiy5B2aYJF5SEbqxCGtPZpuL0xBqV8oHiVwAjPWxA/aJm/Gstjjroz
         N1MwmVOb4lAaFM4EagNWYDLXh8An5t1mu7FHClEmmYB5P3Ki0GroJjjKr4xOCeHeNd5W
         tuk/MLsFnUDnfIb5uqQ8/N5XZGJHjWa9WUSImOuxtE/Fk6x1ZWqW3neZiIBZ9oyB4BUi
         bh7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=C+xwoKboYx/470KW98fBHOhDXwU01XW/5ckhf/q6gCU=;
        fh=tIlf8aa3yI/7ImXjyjupC8f+qWu1SEq1zmpTObobTKk=;
        b=XJTUwWX7JcMQlknr/Vogr3ZuuVKMS+09WUK6M3MTljCcKpTSqOM0YLMjsG6aAUH8Sp
         3TOXTQcPQbSUHXHV02J+q0BjihqmioM+nbil9JokljG1y0F+dAlxGQi/+IFbhhNU5vSl
         rn8EsnWoJGROC/kWoWZLajM6gAxX/7gTeZJZ8ebPvEDg3A1op1ryXodIVn28XtZO1Oxx
         fXnlwbmr/bblESCqqD9S/F8ugXzebcARulEgDLxsaMZnt+ZIyfW+HOIKp9fKFcQJrknR
         cnEvVUROvb2HBkpYrjz/MhsrNyOhHcyS+ut1zlW9XcYEMox5tfET0wZcQPVvKbEBEKqF
         /GTQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="Jv/hlilD";
       spf=pass (google.com: domain of 37ykjaagkcaqqevmizmgksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=37yKJaAgKCaQQEVMIZMGKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--marievic.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753817841; x=1754422641; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=C+xwoKboYx/470KW98fBHOhDXwU01XW/5ckhf/q6gCU=;
        b=CFR4pk51HC0lW5Scvxit/7EqnUC6hJL0+pzZTExWGgL4lzKYCr2E6LxZ3ovpuLS33M
         svr3peFlXzVS057JFr6rULlVzcSToqx/bNoS+hBYayPhl1HCuKHTiU2TAfeAe6UY6Ais
         w6mufIxLQOcWzUj17vDjij/TdipB7SHPr3whVuMi5odiaJJRgOQ3UTn5sRQ23ktKm77r
         t+OaRATSZa9Nkw77KRpJUV0jVDBw6BoAP2u4U40ocCjp1zFHX/dPjh5X2Mw6wPxuHA2k
         degECjh62nlYY+fJuPBhxEJTtf+irJa3D6c0AqP30OPsLvU9uh/QoEwKXYHiDgWEZkI7
         6sfg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753817841; x=1754422641;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=C+xwoKboYx/470KW98fBHOhDXwU01XW/5ckhf/q6gCU=;
        b=ugP7TPYTMQnQlyuwscO7f4QyD/SGQRqW0Fn+j1uGFhqJ+GoTZrk2Wf0aJpYNyUDv2/
         vIFvupJu+9Ly5kuGZIvlZ1PaxPhBuH5+XJt6R2ZvzeUdkxtu6EEAwTouwNmKLNkoKDAb
         DCmk89vDGcuEh9pz2Dlb5KqC8Gzwe0w4RABjJMnKdY5U0KwDhCEfgk0eYsXwIAjw3f+D
         oWq6BRWQuFoIcz5LIAqojjaILe1RrLMIA3hGWQDsuiX56KK0INirkR8nXKc6lWIpq51E
         BdKhLKN+31ijCrd1LTazr3GK+qHTo44ptwJivBub5Qx1FOYlIgG+TEM04ELhtgKABnl3
         WCXA==
X-Forwarded-Encrypted: i=2; AJvYcCUeJENp3WGkgGAn7ybuZDcgDmVhqPUkQISnCDc0iDx2ntJZD7r8HNByXTQyQxmCAxCNomj/PQ==@lfdr.de
X-Gm-Message-State: AOJu0Yw1t/bbnvrblL1R8L8VtHzr+iFhBhFI/e2536DAnXXBj8PTgUtH
	1JtJHME4TcR0uG44W8PEz6cjc91qnE2jSU4yQgIbkkBHPB853dfix9RK
X-Google-Smtp-Source: AGHT+IFlwu43g2v5lY3f2S8ua/Lv6MDVRmXTpetOumz3pzGd+Lk3gsXxzOCYd999lXtyDdOGHIicbA==
X-Received: by 2002:a05:6870:31c7:b0:2d8:957a:5178 with SMTP id 586e51a60fabf-30785c8ad1dmr333266fac.21.1753817841146;
        Tue, 29 Jul 2025 12:37:21 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfpmaVAWzQ847trar4QdE/jahpjUhXp0R+EgWf9I5NEug==
Received: by 2002:a05:6870:4011:b0:2ef:51df:c05d with SMTP id
 586e51a60fabf-306dd7191c7ls1647097fac.0.-pod-prod-02-us; Tue, 29 Jul 2025
 12:37:20 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX4PS3L/CRDKyPhUiWdC4CjTEs/8m2nRVzDypZcdyJk4gRvKH2rWkFVt8qrZyL0jxPRJJVzr4F1i54=@googlegroups.com
X-Received: by 2002:a05:6808:19a9:b0:424:5a12:202e with SMTP id 5614622812f47-4319ba10939mr536860b6e.29.1753817840394;
        Tue, 29 Jul 2025 12:37:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753817840; cv=none;
        d=google.com; s=arc-20240605;
        b=AXmVTk28RMq7qkyOKYuMeU4sVOe643up6guvnK6ik7fwDj0ilNtvX/uL/rm3MQ+0hz
         +0FtSeBBOGxaofmrVmEnKAPWSSRlgrFrdv4KpfmbF5/B2iOz9l1L15qGQdtVCDOJ8/qU
         59RB5SCgBCoUkxI4OF1npghLbyLnY+6PxDK9jgVkkBuZcWESPilXeI9q+nuhgcbTT33b
         Vr9gEP1szzyIFzqb34j1yVO2gpu15CmgA6jcAzzwFYUe+N4TiomsV90I7JRtx4oWLxqJ
         dlE4w7ojOQOEOy4uNq9WayK0xoZyGT8xuYkW4/r0TD2Jw2u41YlbbOpPfWccMQOO79Fu
         NvsQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=tISY+xBUYYz9JGsqhSxSDiuo5pXcWFPbk33bCR9svy4=;
        fh=63RkRohnbvGXqvn5xVpefPqAwhIuj11PEm4eiYjGDPE=;
        b=lVOjs3FPTN4BIfw6hV5naoTYYAuN9NsPPblDnRBzPlkqKdcPKnSlUaNUO+xbPel+JO
         B9p3gPSzhOQehKw2EMFF00AIVp+T6OT7l1TSxzVdd/VVuPp502s5MZzGFV86iowEZZbx
         iSGTgHeqZYWo5M0eDUF258zgiWd8omFIJCPmJqx3ozYaHgAIJh2J7Yoek2EA1+UbTLq8
         TDVGXioeKaUAH3QP7eMg8wgbCfILCDObiv+vQqCseqcXDeuVWeb1c9RB2q1VeHZKxIwX
         Gavj2FZbeStc+VluorQB0+l87VykvcZQKwpTTvCgZt7GDe7KhwynLN+OordtlzU9PuKr
         Z3Vg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="Jv/hlilD";
       spf=pass (google.com: domain of 37ykjaagkcaqqevmizmgksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=37yKJaAgKCaQQEVMIZMGKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--marievic.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id 5614622812f47-42c7dea1eb8si348628b6e.3.2025.07.29.12.37.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 29 Jul 2025 12:37:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of 37ykjaagkcaqqevmizmgksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id d75a77b69052e-4ab60125e3dso137420731cf.0
        for <kasan-dev@googlegroups.com>; Tue, 29 Jul 2025 12:37:20 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWi4QXsqQCf3qS3UosIwdstqcT3B4JWOLkNz+Ns6AcxNhcH99s+Et9FWfn2WG6mngxYvlEXb6gWPN8=@googlegroups.com
X-Received: from qtbcf19.prod.google.com ([2002:a05:622a:4013:b0:4ab:9556:af14])
 (user=marievic job=prod-delivery.src-stubby-dispatcher) by
 2002:a05:622a:ca:b0:4a8:19d5:f8a5 with SMTP id d75a77b69052e-4aedbc45df3mr13576391cf.35.1753817839732;
 Tue, 29 Jul 2025 12:37:19 -0700 (PDT)
Date: Tue, 29 Jul 2025 19:36:40 +0000
In-Reply-To: <20250729193647.3410634-1-marievic@google.com>
Mime-Version: 1.0
References: <20250729193647.3410634-1-marievic@google.com>
X-Mailer: git-send-email 2.50.1.552.g942d659e1b-goog
Message-ID: <20250729193647.3410634-3-marievic@google.com>
Subject: [PATCH 2/9] kunit: Introduce param_init/exit for parameterized test
 shared context management
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
 header.i=@google.com header.s=20230601 header.b="Jv/hlilD";       spf=pass
 (google.com: domain of 37ykjaagkcaqqevmizmgksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--marievic.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=37yKJaAgKCaQQEVMIZMGKSSKPI.GSQOEWER-HIZKSSKPIKVSYTW.GSQ@flex--marievic.bounces.google.com;
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

Add `param_init` and `param_exit` function pointers to
`struct kunit_case`. Users will be able to set them
via the new `KUNIT_CASE_PARAM_WITH_INIT` macro.

These functions are invoked by kunit_run_tests() once before
and once after the entire parameterized test series, respectively.
They will receive the parent kunit test instance, allowing users
to register and manage shared resources. Resources added to this
parent kunit test will be accessible to all individual parameterized
tests, facilitating init and exit for shared state.

Signed-off-by: Marie Zhussupova <marievic@google.com>
---
 include/kunit/test.h | 33 ++++++++++++++++++++++++++++++++-
 lib/kunit/test.c     | 23 ++++++++++++++++++++++-
 2 files changed, 54 insertions(+), 2 deletions(-)

diff --git a/include/kunit/test.h b/include/kunit/test.h
index a42d0c8cb985..d8dac7efd745 100644
--- a/include/kunit/test.h
+++ b/include/kunit/test.h
@@ -92,6 +92,8 @@ struct kunit_attributes {
  * @name:     the name of the test case.
  * @generate_params: the generator function for parameterized tests.
  * @attr:     the attributes associated with the test
+ * @param_init: The init function to run before parameterized tests.
+ * @param_exit: The exit function to run after parameterized tests.
  *
  * A test case is a function with the signature,
  * ``void (*)(struct kunit *)``
@@ -129,6 +131,13 @@ struct kunit_case {
 	const void* (*generate_params)(const void *prev, char *desc);
 	struct kunit_attributes attr;
 
+	/*
+	 * Optional user-defined functions: one to register shared resources once
+	 * before the parameterized test series, and another to release them after.
+	 */
+	int (*param_init)(struct kunit *test);
+	void (*param_exit)(struct kunit *test);
+
 	/* private: internal use only. */
 	enum kunit_status status;
 	char *module_name;
@@ -218,6 +227,27 @@ static inline char *kunit_status_to_ok_not_ok(enum kunit_status status)
 		  .generate_params = gen_params,				\
 		  .attr = attributes, .module_name = KBUILD_MODNAME}
 
+/**
+ * KUNIT_CASE_PARAM_WITH_INIT() - Define a parameterized KUnit test case with custom
+ * init and exit functions.
+ * @test_name: The function implementing the test case.
+ * @gen_params: The function to generate parameters for the test case.
+ * @init: The init function to run before parameterized tests.
+ * @exit: The exit function to run after parameterized tests.
+ *
+ * Provides the option to register init and exit functions that take in the
+ * parent of the parameterized tests and run once before and once after the
+ * parameterized test series. The init function can be used to add any resources
+ * to share between the parameterized tests or to pass parameter arrays. The
+ * exit function can be used to clean up any resources that are not managed by
+ * the test.
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
@@ -269,7 +299,8 @@ struct kunit_suite_set {
  * @priv: for user to store arbitrary data. Commonly used to pass data
  *	  created in the init function (see &struct kunit_suite).
  * @parent: for user to store data that they want to shared across
- *	    parameterized tests.
+ *	    parameterized tests. Typically, the data is provided in
+ *	    the param_init function (see &struct kunit_case).
  *
  * Used to store information about the current context under which the test
  * is running. Most of this data is private and should only be accessed
diff --git a/lib/kunit/test.c b/lib/kunit/test.c
index 4d6a39eb2c80..d80b5990d85d 100644
--- a/lib/kunit/test.c
+++ b/lib/kunit/test.c
@@ -641,6 +641,19 @@ static void kunit_accumulate_stats(struct kunit_result_stats *total,
 	total->total += add.total;
 }
 
+static void __kunit_init_parent_test(struct kunit_case *test_case, struct kunit *test)
+{
+	if (test_case->param_init) {
+		int err = test_case->param_init(test);
+
+		if (err) {
+			kunit_err(test_case, KUNIT_SUBTEST_INDENT KUNIT_SUBTEST_INDENT
+				"# failed to initialize parent parameter test.");
+			test_case->status = KUNIT_FAILURE;
+		}
+	}
+}
+
 int kunit_run_tests(struct kunit_suite *suite)
 {
 	char param_desc[KUNIT_PARAM_DESC_SIZE];
@@ -668,6 +681,8 @@ int kunit_run_tests(struct kunit_suite *suite)
 		struct kunit_result_stats param_stats = { 0 };
 
 		kunit_init_test(&test, test_case->name, test_case->log);
+		__kunit_init_parent_test(test_case, &test);
+
 		if (test_case->status == KUNIT_SKIPPED) {
 			/* Test marked as skip */
 			test.status = KUNIT_SKIPPED;
@@ -677,7 +692,7 @@ int kunit_run_tests(struct kunit_suite *suite)
 			test_case->status = KUNIT_SKIPPED;
 			kunit_run_case_catch_errors(suite, test_case, &test);
 			kunit_update_stats(&param_stats, test.status);
-		} else {
+		} else if (test_case->status != KUNIT_FAILURE) {
 			/* Get initial param. */
 			param_desc[0] = '\0';
 			/* TODO: Make generate_params try-catch */
@@ -727,6 +742,12 @@ int kunit_run_tests(struct kunit_suite *suite)
 
 		kunit_update_stats(&suite_stats, test_case->status);
 		kunit_accumulate_stats(&total_stats, param_stats);
+		/*
+		 * TODO: Put into a try catch. Since we don't need suite->exit
+		 * for it we can't reuse kunit_try_run_cleanup for this yet.
+		 */
+		if (test_case->param_exit)
+			test_case->param_exit(&test);
 		/* TODO: Put this kunit_cleanup into a try-catch. */
 		kunit_cleanup(&test);
 	}
-- 
2.50.1.552.g942d659e1b-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250729193647.3410634-3-marievic%40google.com.

Return-Path: <kasan-dev+bncBDQ67ZGAXYCBBHU37TCAMGQEU3UKBTA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13c.google.com (mail-il1-x13c.google.com [IPv6:2607:f8b0:4864:20::13c])
	by mail.lfdr.de (Postfix) with ESMTPS id A539DB27E56
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Aug 2025 12:36:16 +0200 (CEST)
Received: by mail-il1-x13c.google.com with SMTP id e9e14a558f8ab-3e56ffea78fsf23495365ab.1
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Aug 2025 03:36:16 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755254175; cv=pass;
        d=google.com; s=arc-20240605;
        b=I3RAlw0aSLFavjPkwsOHbZ+G4aDnltHiWd5NxGcbdt+w1iK8CCPYyy8vDSh2AgMAG8
         FyXMbQRJR07WmhLrqcUw314sgDWK4F9SEvftyZs9RCT4KTz1QP3wE9uHxYaYQOEw4Ywt
         RL9bFMPSd8tlyCddTR6qjJ+tqMyPrl90cxmjRMXb8vscKE8Lju7kMF25jDxQH63hADaR
         7T0Lue+iytbbd8ET8rIpDYRGYZj6Vtl3jJ9VjOrgjo1x3hBzx6xKNgtSs/1PKwc+yXll
         rpMKGpR/5XePEr4tdYjN68skmf9v2hLQ34sbrqkxh13EE5la5p9h1LjxGvNzAjraK0nT
         mn1w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=yiZc63e2TTIyaNUFLcq/jiZssGZpsYa5XpVmuAnnu1Y=;
        fh=9qcpKHRBGCcCv//iUmvc1ke6j0IqH57GFCVvO+JU9BE=;
        b=RP1YVGK7V84sgY2B3ARhevfkYlsu+m9FUtLNKW/Eso73uttKlNnFT9wjhhIw21S9u1
         OdzQvG3zQuqUi6LmOJkFj2Gq3FNsEpX7Y1hqTJDcb5+TuNp01TElFITWCxEQV4TQma9Y
         2puNSpKdJE4BvaLvzh8uSWJGJZPz3ihD1sOKihcuu76xS4kl4oJ5cJhPo3yFWqYKS1T+
         0LKPFWKCr2xH0YHkDMnHx7Fqgyhcti3AUKkD7L/sulQTvFX8GRzPKqOlya5KkgdBgMTM
         H/D+FqZdTmw38mN7HPSzAqtTufXerLJFuaXKxIHhaMJGos/rwKFkRbm3nkgGZ6+89K35
         cC5g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=noCBwnIp;
       spf=pass (google.com: domain of 3nq2faagkcyaqevmizmgksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3nQ2faAgKCYAqevmizmgksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--marievic.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755254175; x=1755858975; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=yiZc63e2TTIyaNUFLcq/jiZssGZpsYa5XpVmuAnnu1Y=;
        b=FA6+a4/2vOBY0rsos625c7cPecR/7cWpqQM79h/rK5nHcBuR/n9oblFgdDEiasGqVq
         s7htmD3evuGKt0xAtQgNSwinUMoKkky0FbcUhm24CJShIhoGBnMktX58MUZSxafGKfC/
         cv9VSGAp/tVk14eDjRTMmJtaLYn1TteJ3kTbQElRbezDznrVLMhZJvnpkE2csIFjthw+
         jzXNt+cxf10PdwVzP6nHoW6NA0Ez9LHanzLMZG1UStiENE6c5YKdvBrkPM49aAX6o0Ll
         we8E6bPxW5JL/3rV3reo8/CjaTzJUamDwITaEeuZBEkw9Op1snb3O1zCe0q1OFbk7R7a
         uoUg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755254175; x=1755858975;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=yiZc63e2TTIyaNUFLcq/jiZssGZpsYa5XpVmuAnnu1Y=;
        b=ot6IW1xcfu8W7SnFPL/Pq/vQtFtcf+rIIbULx51Fd0n/78DNYDQnCKe9zWpcO4wrNZ
         zU0tRskkwVomfKXRA7zVNFTKMIndIlpheIxQBN53SOX3L/VbRQ/fwKP2XWepU3Oo7bFD
         rxxZWYcynLHeEF1RI7GNW9vF9dGNTgRW3m/ztUoPX5iJQcSESyLTpAu1+PyP+ltOPo9y
         /09oCx3luR5aDlp9Mq+AVZRapEM3XfZRvxvU6XhOYaRDeqDLxaZx84i55/WcfvvLjH6u
         HP0RcCSNsBeRmEfCt/usy0+wVmgypDnVsZhj8Cz0gU7/kMxsR76KynuI+BIo6JSXlchM
         sjAQ==
X-Forwarded-Encrypted: i=2; AJvYcCXhEKmn0gVC31v5Zj46sRg/EtsROob9NujiWA5fB2umnsr3SiFJuNcIyJaSlzLamzcsdCaCIg==@lfdr.de
X-Gm-Message-State: AOJu0YxrbAC4JeBZLubUoCTH5TJ+fPkfwAjuMGJeXVGvL4u6wZuynwMw
	SonHNDzImMIbEPFW/I68SAZ2uK52qCb3fEHr2F8+LJKHtalk0qCYsAuZ
X-Google-Smtp-Source: AGHT+IHyBCsplUeZBW3chwS77hLt7JXGfRWlt4A17REh0jJc1Vn5vF6y1ypPVL2lgfmZlCgvDAKFYg==
X-Received: by 2002:a05:6e02:16ca:b0:3e5:5269:89be with SMTP id e9e14a558f8ab-3e57e8a5c97mr26064975ab.15.1755254175055;
        Fri, 15 Aug 2025 03:36:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZfroUommLWDMxAP7id7NJxksli01d3hr+hqEnGG4/4sRA==
Received: by 2002:a05:6e02:4719:b0:3e5:7e3c:6fd6 with SMTP id
 e9e14a558f8ab-3e57e3c7081ls2588965ab.0.-pod-prod-06-us; Fri, 15 Aug 2025
 03:36:14 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWBGrL92OS0R1bzcP4Huhhy/NFiynte6FQzJZvdAMENePsldRvXW3zHnYvx7yw4Tx9tTw6/xmYsLmY=@googlegroups.com
X-Received: by 2002:a05:6e02:2148:b0:3e5:3ce4:6953 with SMTP id e9e14a558f8ab-3e57e9c4a78mr22810505ab.22.1755254174272;
        Fri, 15 Aug 2025 03:36:14 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755254174; cv=none;
        d=google.com; s=arc-20240605;
        b=X/j1/P1+u86DdwIC4QEy2xmmbQEd8egA+nMwIjkv5IPLb5WnG1a6V/LkzQPAFna6dO
         l3MMCKqXUhZeMWJZlx68Aw2YfEymAxgKOQQ0hAbM8LH0rgGmRCtAe8nEaPUW6EBNo93x
         O2NrCfmko4+wECEzTAcwSPL0ZS8IV2hVqK03ydJsSzfgu5Z0qdpXy6hJ1pbesAm1bE/H
         ieBrGkHz/dZLyPQp1Xbaq2jaGu87xsEVMCDhZTOZ3q2WZZzaV07Zifp8PlrFHFEJHg4w
         O5mi81cdY/Up7CV4lBOvJyEFkd7WLtcA204azquIIGhL8PRPmKVE4LrAxaPLf9qxtVmG
         oYEA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=sAGiMmlsvvRAyIRtfIkliO7s5pzV7dahw9GOcGCzEKA=;
        fh=JUWLqkbYX0mpL7OVUyZCX+0E5rCRXWKS+6P+PVS8z68=;
        b=bMD97KOKIu7Su/TQsiK0PpeC1aOBpO65pspRAT48QjMrVD8U0WDqefT/oBaxxGWXZB
         nPX62oU4xR6RkRWaLLcjg6VGwvF4HFjN3LCMOwPwL6bJmpU4PL6d0/AsknqL31SzYLE0
         JeU4dhuMND/pcRUT+iQ2L75luzpAngjuR1y4NteNLFe8NCB3jQ3Yzt1tRyLKuBFCormb
         h/ay4khLKQ7rr86BVs8M3+2N3A6E9OnQtNr8JtNXli+w1JW8QJV5+3PXt5Abjj2/CQmt
         d9iPbLKfssSQ1TkWe0pQZUaf2R4PIsa+vnxTLzQd8224IVW1Ac3tyZ682RaqNClGWt6O
         hN+Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=noCBwnIp;
       spf=pass (google.com: domain of 3nq2faagkcyaqevmizmgksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3nQ2faAgKCYAqevmizmgksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--marievic.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x849.google.com (mail-qt1-x849.google.com. [2607:f8b0:4864:20::849])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3e57e76f512si370905ab.3.2025.08.15.03.36.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Aug 2025 03:36:14 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3nq2faagkcyaqevmizmgksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::849 as permitted sender) client-ip=2607:f8b0:4864:20::849;
Received: by mail-qt1-x849.google.com with SMTP id d75a77b69052e-4b109c382aaso54348121cf.3
        for <kasan-dev@googlegroups.com>; Fri, 15 Aug 2025 03:36:14 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUq9Tg4eKma2BeWgvP35Vronotqru/KPXxHKIirtCQap2cCgTrieOTuoDq1+F/2RGjm2/pAgEEkEBA=@googlegroups.com
X-Received: from qth25.prod.google.com ([2002:a05:622a:9019:b0:4af:205f:b347])
 (user=marievic job=prod-delivery.src-stubby-dispatcher) by
 2002:a05:622a:19a7:b0:4b0:6f65:4622 with SMTP id d75a77b69052e-4b11e100b18mr13704771cf.2.1755254173610;
 Fri, 15 Aug 2025 03:36:13 -0700 (PDT)
Date: Fri, 15 Aug 2025 10:35:59 +0000
In-Reply-To: <20250815103604.3857930-1-marievic@google.com>
Mime-Version: 1.0
References: <20250815103604.3857930-1-marievic@google.com>
X-Mailer: git-send-email 2.51.0.rc1.167.g924127e9c0-goog
Message-ID: <20250815103604.3857930-3-marievic@google.com>
Subject: [PATCH v3 2/7] kunit: Introduce param_init/exit for parameterized
 test context management
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
 header.i=@google.com header.s=20230601 header.b=noCBwnIp;       spf=pass
 (google.com: domain of 3nq2faagkcyaqevmizmgksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--marievic.bounces.google.com
 designates 2607:f8b0:4864:20::849 as permitted sender) smtp.mailfrom=3nQ2faAgKCYAqevmizmgksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--marievic.bounces.google.com;
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

Add (*param_init) and (*param_exit) function pointers to
`struct kunit_case`. Users will be able to set them via the new
KUNIT_CASE_PARAM_WITH_INIT() macro.

param_init/exit will be invoked by kunit_run_tests() once before and once
after the parameterized test, respectively. They will receive the
`struct kunit` that holds the parameterized test context; facilitating
init and exit for shared state.

This patch also sets param_init/exit to None in rust/kernel/kunit.rs.

Reviewed-by: Rae Moar <rmoar@google.com>
Signed-off-by: Marie Zhussupova <marievic@google.com>
---

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
index b47b9a3102f3..d2e1b986b161 100644
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
index 14a8bd846939..917df2e1688d 100644
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
index 4b8cdcb21e77..cda64574b44d 100644
--- a/rust/kernel/kunit.rs
+++ b/rust/kernel/kunit.rs
@@ -207,6 +207,8 @@ pub const fn kunit_case(
         status: kernel::bindings::kunit_status_KUNIT_SUCCESS,
         module_name: core::ptr::null_mut(),
         log: core::ptr::null_mut(),
+        param_init: None,
+        param_exit: None,
     }
 }
 
@@ -226,6 +228,8 @@ pub const fn kunit_case_null() -> kernel::bindings::kunit_case {
         status: kernel::bindings::kunit_status_KUNIT_SUCCESS,
         module_name: core::ptr::null_mut(),
         log: core::ptr::null_mut(),
+        param_init: None,
+        param_exit: None,
     }
 }
 
-- 
2.51.0.rc1.167.g924127e9c0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250815103604.3857930-3-marievic%40google.com.

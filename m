Return-Path: <kasan-dev+bncBDQ67ZGAXYCBBD6Y5HCAMGQEGELV2RQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf39.google.com (mail-qv1-xf39.google.com [IPv6:2607:f8b0:4864:20::f39])
	by mail.lfdr.de (Postfix) with ESMTPS id EE833B21815
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 00:17:52 +0200 (CEST)
Received: by mail-qv1-xf39.google.com with SMTP id 6a1803df08f44-7074cb63bccsf96648316d6.1
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Aug 2025 15:17:52 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754950671; cv=pass;
        d=google.com; s=arc-20240605;
        b=Sd03C3iwemOEIuB5s1egS+a9rqcIiw8G3gI8hJwatVLic68Pnt8lXO9WYWVO2h6jyZ
         DCUdqGiawHSVlC4n/5i4CgPVI9Ko3UFPOvMHV2OQtZFGye2ECLKKtymEDkmABgxqPHfz
         zlc4UPYndbLKrJd81UOOrzwwdrbOV385zQ4dSdXXutd4JH1irr/Kw0KW5NNoc4SPZGBe
         mqK7rIUSyUFofZ/hXdxxEST0E53fewyKIm46VQk5F6ZyEULhf7q0OViqVmgRTHFnMSye
         1+ZnvUHagjY0FWdYQRRqF7/C34VC8ou/NFVK5ewIB/p0mT4HcW9tpeuIDNgczk9C12jB
         vFvQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=La/WukQdGPYwWZgpmHXR+cQVRI+bX5F6iHDZQvBNK6U=;
        fh=cEBxGIW88uWhKXp9EQju5cMi1REIsAeRy5kINAaaW5o=;
        b=UJW2rRpkv98XoBPB0DLOlTAmB1fe6E+LKTeiolBWqDY2akjyB2C3noDxWb22O5cq7/
         lwRExHNjpa51jMEVrojY2OTEhc+pqMTakh9j9NYraHk3ii3OWOzQzzhs77JYd1Ajjz8T
         Zb7A2qhyc4YLpRE0GnYb1WOnTcL/02CeIGvKAwHWMyGgK59U3hzkUIifwgJBtB0s26mS
         xTSeuT8tTGSNxAVJ9ExOXRvUpJUKM5VmSZFoPWIMp3KZQNJG8M8x6PbGRYs0tfzt5cCb
         b0aLN8tQL4IVMF8kvpDGCi6R1mUlTKQhhe2eA2sZ6OtFkM3BSEkmSkrKZegprozWn61M
         0e9Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=HPa+XQ3+;
       spf=pass (google.com: domain of 3dwyaaagkczog4lc8pc6aiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3DWyaaAgKCZoG4LC8PC6AIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--marievic.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754950671; x=1755555471; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=La/WukQdGPYwWZgpmHXR+cQVRI+bX5F6iHDZQvBNK6U=;
        b=RJZuD3hiWEgOSoAHfhai/tN2m0CE88bNO4e6IQcDBIXcfkJY7YWEuYUcK8Udmzqq8M
         NDvZa02wBczJ9Gx8tIqtySFdkADhN5/La/+FoTpRMF/4lr0wZ0FfsKaaQFFVqEi3u5Rd
         8BCFUS+I5nngKbJGVu9+wUy8U13RrN87w6IYnOXTW3OuU4LcA3tZgn4uVOL48tGTaboi
         VP9fzXFhueb44DLb4EtVEHTHdu+2nM0J8HCU0wuBEJhz4AFQ9VZ3eGrS6c8bsGokERh+
         m6SQGBDy1gZpsuxjBlijdPhYVZUapZft9mWjj+pcLSUmfQ7XHN3WD82qDFGcqWe6kYUB
         aMmg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754950671; x=1755555471;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=La/WukQdGPYwWZgpmHXR+cQVRI+bX5F6iHDZQvBNK6U=;
        b=dh4bO31wrXUR4FyR/DD1rE8DnXEs03Do7okPEOWwJAwOolgFrKEniLYttDE1I61dDm
         LJKpEzVMsOlvLnaLPag2onP3YprhSifdjCw0xPQXGLNTzMQh3JNAqB6xj0yXVkcT0G4e
         h4rygDm1Aj3WLcWB+8ko0z3CjfFVURJXx6zH2MWM1FBbDKa4osJBJKtSetIJzMPOlOhc
         pPY4WK84d02QETVvHN44hUg3aqRH1l11JcKy598Ewhhj/uB+sJhSr6dJ8PHGLdSR8iFr
         o+JLSeRTwwBxVitJovcia9zmxVvJShEvJO0X+xvEMfX1mSOl3D1UgBnsq2W5jWY4nf6u
         xfwQ==
X-Forwarded-Encrypted: i=2; AJvYcCUDZbEoesnbnScmECUfvCJeuvAdV56u5W2KbowHsUcnEamFO0kDgJuC5i476f78pNlP9ki+hw==@lfdr.de
X-Gm-Message-State: AOJu0Ywq6cl3GvLhP7BZJgPxmr8bbhOxVnct+UJuRb7HuCaxzonWrpFH
	kxT6ainj52gHmXWVAlMnX64YwYRY1YEULM9CGZC2u+CUktg9oUM7jFLj
X-Google-Smtp-Source: AGHT+IGyo/lvqucBHZot1JBADDaVUeUgedImBVfFLEthW97OhHO/xz3tF442nG01PscAaAMq1zzIrg==
X-Received: by 2002:ad4:5dea:0:b0:704:8db8:d3cd with SMTP id 6a1803df08f44-709d5c76484mr18925926d6.8.1754950671517;
        Mon, 11 Aug 2025 15:17:51 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZf/2NaV5fqnQmtmyEM36HGE+9wMs2/Xrod5hNvZMvne1g==
Received: by 2002:a05:6214:2129:b0:6fa:be38:256 with SMTP id
 6a1803df08f44-709880a5fcfls79843246d6.0.-pod-prod-02-us; Mon, 11 Aug 2025
 15:17:50 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVKkSXZs98cufVFpNWMMTiioqeOVcWaUtypu2l1gYh4WAm1uXY1NZwLyfNpeFJoQ3mzoKK499fqSrY=@googlegroups.com
X-Received: by 2002:a05:6122:1d06:b0:539:1dd2:22fa with SMTP id 71dfb90a1353d-53afad3c6fdmr447611e0c.1.1754950670521;
        Mon, 11 Aug 2025 15:17:50 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754950670; cv=none;
        d=google.com; s=arc-20240605;
        b=N+YrkWpeaicpqn0tPJlvNOwCpIVsjI76lXYms1KtWwNyjGME4j7iadLYoqY3VOQmZA
         fbDyiHfAB6khs3RuhWcrewJ34CSVoh1UlObU/XBk0FYJ3WTN2BT+W/EEgYFGIaFIbzcc
         CJXOzEX4KBpZ8GOtH4gcpp0QKFKhMJxQV9kidGjBbuCHcDpWUyYfAsxRT8cRhjmZa0vE
         gWCGn3Hp45L75aa9Pp7lyXupWInSrnlcX0+r+RJ1RDd4jIQ0m13JZHiTiKvqJ8aAp8zn
         chOzMvAFZcdvsrIxObEdj9PHtNZGuhagDWl0dL/AnyL9+gutWOttxK/MzkJbA0mz4wii
         zkZA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=tOKMohtGJshnbgrwq7yuoLuH6EcijO5VHFU8Cl1yLsQ=;
        fh=/S9WXuBl3Fsave/APflfd3JlMC+oYZvduIj0CNF0FWY=;
        b=gJZLcps5edZAYsvwUhq5s51SVC3zumTJ3D90dlmJbCxvJHDBYrrj3W/UMvl6ZUDFr+
         /43lhmPZQyFv2xS9XNMclPwgLwQQ7h0+24ycQS5MaEwznCe3lB8E8BA2n5XG1pbWPfzU
         OevFdNbHxhZzC24EztOMbLrbcu+6s53cXEmNL+lV/nUC6fIaSqwitUkGefNAjbhdy+8J
         bDS3uXLo7Sfr1SjPFG1JLclWAgwHPlvAr//jFoQiLikUTnQka9gdQ9xgNPmgu40CbVQG
         l5GBaLH/oZ4nKw2h6ShOzZMYm2U7vUS5tZ5g1JdtqbpGBByQtch4nkRk3lHXTeZ1bQYB
         phiQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=HPa+XQ3+;
       spf=pass (google.com: domain of 3dwyaaagkczog4lc8pc6aiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3DWyaaAgKCZoG4LC8PC6AIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--marievic.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-539b003907fsi594465e0c.0.2025.08.11.15.17.50
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 11 Aug 2025 15:17:50 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3dwyaaagkczog4lc8pc6aiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id af79cd13be357-7e69b0ec62cso981007485a.3
        for <kasan-dev@googlegroups.com>; Mon, 11 Aug 2025 15:17:50 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWE3AQrcjUczia9XEV6CGD0Rn1OIwuOSp8KdjSDgsLVDd9BLN3CKh4P5rZVkQkr+Lrcn7gJdOXAuuo=@googlegroups.com
X-Received: from qkfw14.prod.google.com ([2002:ae9:e50e:0:b0:7e8:1e34:1791])
 (user=marievic job=prod-delivery.src-stubby-dispatcher) by
 2002:a05:620a:414f:b0:7e6:8751:96ae with SMTP id af79cd13be357-7e8588965a6mr233742085a.31.1754950669987;
 Mon, 11 Aug 2025 15:17:49 -0700 (PDT)
Date: Mon, 11 Aug 2025 22:17:34 +0000
In-Reply-To: <20250811221739.2694336-1-marievic@google.com>
Mime-Version: 1.0
References: <20250811221739.2694336-1-marievic@google.com>
X-Mailer: git-send-email 2.51.0.rc0.205.g4a044479a3-goog
Message-ID: <20250811221739.2694336-3-marievic@google.com>
Subject: [PATCH v2 2/7] kunit: Introduce param_init/exit for parameterized
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
 header.i=@google.com header.s=20230601 header.b=HPa+XQ3+;       spf=pass
 (google.com: domain of 3dwyaaagkczog4lc8pc6aiiaf8.6ige4m4h-78paiiaf8aliojm.6ig@flex--marievic.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3DWyaaAgKCZoG4LC8PC6AIIAF8.6IGE4M4H-78PAIIAF8ALIOJM.6IG@flex--marievic.bounces.google.com;
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
`struct kunit_case`. Users will be able to set them
via the new KUNIT_CASE_PARAM_WITH_INIT() macro.

param_init/exit will be invoked by kunit_run_tests() once before
and once after the parameterized test, respectively.
They will receive the `struct kunit` that holds the parameterized
test context; facilitating init and exit for shared state.

This patch also sets param_init/exit to None in
rust/kernel/kunit.rs.

Signed-off-by: Marie Zhussupova <marievic@google.com>
---

Changes in v2:

- param init/exit were set to None
  in rust/kernel/kunit.rs to fix the Rust breakage.
- The name of __kunit_init_parent_test was
  changed to kunit_init_parent_param_test and
  its call was changed to happen only if the
  test is parameterized.
- The param_exit call was also moved inside
  the check for if the test is parameterized.
- KUNIT_CASE_PARAM_WITH_INIT() macro logic was changed
  to not automatically set generate_params() to KUnit's
  built-in generator function. Instead, the test user
  will be asked to provide it themselves.
- The comments and the commit message were changed to
  reflect the parameterized testing terminology. See
  the patch series cover letter change log for the
  definitions.

---
 include/kunit/test.h | 25 +++++++++++++++++++++++++
 lib/kunit/test.c     | 20 ++++++++++++++++++++
 rust/kernel/kunit.rs |  4 ++++
 3 files changed, 49 insertions(+)

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
index 14a8bd846939..49a5e6c30c86 100644
--- a/lib/kunit/test.c
+++ b/lib/kunit/test.c
@@ -641,6 +641,19 @@ static void kunit_accumulate_stats(struct kunit_result_stats *total,
 	total->total += add.total;
 }
 
+static void kunit_init_parent_param_test(struct kunit_case *test_case, struct kunit *test)
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
@@ -678,6 +691,7 @@ int kunit_run_tests(struct kunit_suite *suite)
 			kunit_run_case_catch_errors(suite, test_case, &test);
 			kunit_update_stats(&param_stats, test.status);
 		} else {
+			kunit_init_parent_param_test(test_case, &test);
 			/* Get initial param. */
 			param_desc[0] = '\0';
 			/* TODO: Make generate_params try-catch */
@@ -714,6 +728,12 @@ int kunit_run_tests(struct kunit_suite *suite)
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
2.51.0.rc0.205.g4a044479a3-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250811221739.2694336-3-marievic%40google.com.

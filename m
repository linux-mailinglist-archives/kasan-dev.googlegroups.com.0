Return-Path: <kasan-dev+bncBDQ67ZGAXYCBB3WFUTCAMGQETDTOQ5Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13a.google.com (mail-il1-x13a.google.com [IPv6:2607:f8b0:4864:20::13a])
	by mail.lfdr.de (Postfix) with ESMTPS id DC06FB15386
	for <lists+kasan-dev@lfdr.de>; Tue, 29 Jul 2025 21:37:19 +0200 (CEST)
Received: by mail-il1-x13a.google.com with SMTP id e9e14a558f8ab-3e29ee0fb2dsf56112325ab.3
        for <lists+kasan-dev@lfdr.de>; Tue, 29 Jul 2025 12:37:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1753817838; cv=pass;
        d=google.com; s=arc-20240605;
        b=exJY71HWi19l5KKQFDoIDk6WTp3SUNGtwexMCoopNOGAp2HqeZvd7EzFtW3TXEMY8N
         +nr14y4qYmbJ1Mor+i55xzrJBdKuQLrpmge8JQMv4aj2RwSThrGzab4g9gSWeWe7Ernx
         CATUqJ9lMdLelXzfSjOtOdUbdAAuqiQEkVIgf3PA9KHRja+k/vGkPf2j8epv0QaL+FY1
         eXgltq83aG+ltI4cQEdn9CokGLscnJJxILiZI7uaRw3I3+PveqQRJ3MxGl32bCQTwdRF
         K9G5WFkAaQVKjzhC+kdgsm4GpSy4buWfRtjE9Dtq7iqcDxVvBbawpKuJtBa9sMmHakjf
         TFrw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=u9b1FyoOQzipLuLAPon/OIoHob2ojDTivNHGeP2oQb4=;
        fh=R4ksbsfWCj6UbskmCQ2Cza4YdIBjW+UcQ6lyFeZlUV8=;
        b=hCOnROoZmSvz5YKREhzoB44MKeGWezBz2SlhNAwUKg9QTyST/uHv3FjS5UgY6hseOd
         0NZdbGuNKBFZXHlUVQZumSbrnk0QMg8BdExSEuMPToEZ1geWSPrbgL46Wbnt1Rbn/HOV
         Vc856vDKGR5pkMcLLUeJCoCD8IQ+EFjtDblCIuoeRftluwjmqQ+sUNUP//n6Njr06QkX
         0hVXXJzxwFNuicFzDozPd/DaO0/vS3BI5jI276iYkNy70Y3SFNfPNZ1AiaxOeiVj1bui
         S8BRNGUBqBSw/udSJE2nmQsW+qEmrMrojUlLo1bhWQdf9gzkNGc9hh9lmkEjc+asiOyB
         v4kg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=1SVZJydC;
       spf=pass (google.com: domain of 37ckjaagkcaenbsjfwjdhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=37CKJaAgKCaENBSJFWJDHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--marievic.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1753817838; x=1754422638; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=u9b1FyoOQzipLuLAPon/OIoHob2ojDTivNHGeP2oQb4=;
        b=p93ku+tsPb0E9dDtSrTvJkNJEg4F4pm0C6LX45yM7LHDkIw3GeXgx55k2wT7aBFlh6
         00V69VLCgLS4bCNfXS7+Hide7nYpw7DOUkpbohCCn5LoyriU2fmpBKCYuVrN81YhlH5F
         5KDbaKq8tQ2bLC5tSuU5sjRbMT60oUaPJACGWrcxHW5aHf/Pl/DzhwaBJ7jqbEabj/YV
         Tm4n5Hw5DxgWALdF8Nxco8L3joSMsS4SYw4SyM1DOSYLqhH68V0kCf7Gm81pdYCSZ4IL
         Xe1uHinGltvXUvYjWCS4Go1HgTwsDcKUh1u2E++FIu+pi7WBzM5ajRwrn9K7q30emSis
         6WqA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1753817838; x=1754422638;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=u9b1FyoOQzipLuLAPon/OIoHob2ojDTivNHGeP2oQb4=;
        b=VKA6VefdznIds1U279aNo4lo8ker7LTORzaSdYGdFuC1xythaJ7u5CfMcRVbcONxv4
         02VsiSU2JKYMxvQDKtvhHfrmAHDUo0h92pp6MBRmFjugsPcQly65U+ix1i60cRevgHgq
         OCv8dMXd/+2YShzwSFrfO/OKX2ME7aqI8psExGIxCbCV+vjxxsc+H8SJHJ3AS6fHffLy
         R0Tx7AomLFRcHib6phJR1I/hscfHwvgx6/RQPV0eeGpFg4KcCQNnUOn8H6BlEIegRHTA
         t+lFxUK1Vr2axpns3MlecfQqxYEjZKYypR+RH/M9ok5CSr2sMs9KkInG91tffD6HdPtJ
         Aqhw==
X-Forwarded-Encrypted: i=2; AJvYcCVEpKmoZuNYSQnLJNf4Y3vs1o0zhWK63YP57105v7Hc9zzXRM4JrZqKWC1Oofx6Ne2JWQjKTw==@lfdr.de
X-Gm-Message-State: AOJu0YybvbK9Mcs3ppjz4gXGaYkfF8NYrPl4D6Xe0XDd8k8EKSjXZArg
	/LS6crh5gB4j9QTIA0jQ/c4dfkDDtwpOz/P5lggZKf92pSl0lqaRnAv8
X-Google-Smtp-Source: AGHT+IG304VfLIxBtS+xoN5LSOWBURpnjk8KO0E4BsQZOpE/TankcLAOLytpb9KqsM6zoNxgwPLPJg==
X-Received: by 2002:a05:6e02:746:b0:3de:287b:c445 with SMTP id e9e14a558f8ab-3e3f5db42a1mr11862765ab.0.1753817838408;
        Tue, 29 Jul 2025 12:37:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeE+WcuMlJeFKE0goIMUygqmfL4TNlzDGjldTNy58zQiA==
Received: by 2002:a05:6e02:4618:b0:3dd:be50:e1f8 with SMTP id
 e9e14a558f8ab-3e3b5180f79ls54840205ab.1.-pod-prod-07-us; Tue, 29 Jul 2025
 12:37:17 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUxQFSlRVuLU6UDbfbZGhWhL+73O7XLRjL9g9lpJju3djfQyFDcTdD4w7id84DFRYKvgAwq94Cl/Gk=@googlegroups.com
X-Received: by 2002:a05:6602:6d04:b0:87c:1237:cef7 with SMTP id ca18e2360f4ac-88138c1ad48mr123552139f.13.1753817837482;
        Tue, 29 Jul 2025 12:37:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1753817837; cv=none;
        d=google.com; s=arc-20240605;
        b=OGBZvXpA7TEbfW9bI8YNjuOsgM/E/0FBFlRv1ZXv47F983EcrhEss/dzYuhQrQtKP2
         K4ToZuMI64Oly8fozJxTTJttM+PEqeZtgMdoSBkd66h8Vp20mUvivbh0dIsPCXuCYx+G
         40y2+K124fba4dlhvVK63jop1eN6pBWyPMO4UhNDHiMbZhACX15crK/Y4Ngw1NSdrbcS
         DQJKg7bf1e3NKU37VyqKe+LET0piH7Amzg5tYISS6BSICfIoa65qDmlDiNAcswZeFH1N
         sjHnselcyqSEjaEMjdA/snhp+ZG31SwasXHToyq0ZspBw1BSd8EQNUO2wViC+l1V52KJ
         xo3Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=7t36RxdzKGiVmpStJKp3ep3ZJUIKeCeGyRBEDxUk+R0=;
        fh=mDHajNrEd61bEpRLS2G/jZa7KzIriH1IOiaJijFQa9s=;
        b=eGG6S8jSh/rpmrK5z7y9VhOfVs76kOIhb9GtUbtokJAkPaiXpu0CCwEu8UCscxvmR4
         LVeM9knZIhoRRAqAFNB+4akhaHFDoujboWblwusTM5iqss0ig+x/koxA1DgUjesYptPf
         3dPTz8T5hpx3HkRwaGXeiNYEEHt1mf2Y7QCwBGkNSmf5sq+Ua8KBrmqLLo0jUABrESTg
         KrZuwuE5P5fxklljecBSlHCpHINY2yxH8pqYJk/JAII0/Hmf3pAPMmV1JjzmyLhaG2C3
         UySCwkQHqt9hPfpWobVchvyuFre5BvFF5aT4qkv6m4B8/NC7ewTXYrNCYNjef6vyDZgK
         XYLg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=1SVZJydC;
       spf=pass (google.com: domain of 37ckjaagkcaenbsjfwjdhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=37CKJaAgKCaENBSJFWJDHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--marievic.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-880f7a4400fsi59095239f.4.2025.07.29.12.37.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 29 Jul 2025 12:37:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of 37ckjaagkcaenbsjfwjdhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id af79cd13be357-7e2c8137662so1206113085a.2
        for <kasan-dev@googlegroups.com>; Tue, 29 Jul 2025 12:37:17 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVezdw1zErLtM5vJ6nPISpcj2Z00JbeKNQGulfDUDtyytA5i7kPRKf4RJ47c0S5lEjOvLw4PCCczuM=@googlegroups.com
X-Received: from qtbfh7.prod.google.com ([2002:a05:622a:5887:b0:4ab:d41d:ce0c])
 (user=marievic job=prod-delivery.src-stubby-dispatcher) by
 2002:ae9:e008:0:b0:7e1:9c2d:a862 with SMTP id af79cd13be357-7e66f3534ffmr75742185a.39.1753817836908;
 Tue, 29 Jul 2025 12:37:16 -0700 (PDT)
Date: Tue, 29 Jul 2025 19:36:39 +0000
In-Reply-To: <20250729193647.3410634-1-marievic@google.com>
Mime-Version: 1.0
References: <20250729193647.3410634-1-marievic@google.com>
X-Mailer: git-send-email 2.50.1.552.g942d659e1b-goog
Message-ID: <20250729193647.3410634-2-marievic@google.com>
Subject: [PATCH 1/9] kunit: Add parent kunit for parameterized test context
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
 header.i=@google.com header.s=20230601 header.b=1SVZJydC;       spf=pass
 (google.com: domain of 37ckjaagkcaenbsjfwjdhpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--marievic.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=37CKJaAgKCaENBSJFWJDHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--marievic.bounces.google.com;
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

Currently, KUnit parameterized tests lack a mechanism
to share resources across individual test invocations
because the same `struct kunit` instance is reused for
each test.

This patch refactors kunit_run_tests() to provide each
parameterized test with its own `struct kunit` instance.
A new parent pointer is added to `struct kunit`, allowing
individual parameterized tests to reference a shared
parent kunit instance. Resources added to this parent
will then be accessible to all individual parameter
test executions.

Signed-off-by: Marie Zhussupova <marievic@google.com>
---
 include/kunit/test.h | 12 ++++++++++--
 lib/kunit/test.c     | 32 +++++++++++++++++++-------------
 2 files changed, 29 insertions(+), 15 deletions(-)

diff --git a/include/kunit/test.h b/include/kunit/test.h
index 39c768f87dc9..a42d0c8cb985 100644
--- a/include/kunit/test.h
+++ b/include/kunit/test.h
@@ -268,14 +268,22 @@ struct kunit_suite_set {
  *
  * @priv: for user to store arbitrary data. Commonly used to pass data
  *	  created in the init function (see &struct kunit_suite).
+ * @parent: for user to store data that they want to shared across
+ *	    parameterized tests.
  *
  * Used to store information about the current context under which the test
  * is running. Most of this data is private and should only be accessed
- * indirectly via public functions; the one exception is @priv which can be
- * used by the test writer to store arbitrary data.
+ * indirectly via public functions; the two exceptions are @priv and @parent
+ * which can be used by the test writer to store arbitrary data or data that is
+ * available to all parameter test executions, respectively.
  */
 struct kunit {
 	void *priv;
+	/*
+	 * Reference to the parent struct kunit for storing shared resources
+	 * during parameterized testing.
+	 */
+	struct kunit *parent;
 
 	/* private: internal use only. */
 	const char *name; /* Read only after initialization! */
diff --git a/lib/kunit/test.c b/lib/kunit/test.c
index f3c6b11f12b8..4d6a39eb2c80 100644
--- a/lib/kunit/test.c
+++ b/lib/kunit/test.c
@@ -647,6 +647,7 @@ int kunit_run_tests(struct kunit_suite *suite)
 	struct kunit_case *test_case;
 	struct kunit_result_stats suite_stats = { 0 };
 	struct kunit_result_stats total_stats = { 0 };
+	const void *curr_param;
 
 	/* Taint the kernel so we know we've run tests. */
 	add_taint(TAINT_TEST, LOCKDEP_STILL_OK);
@@ -679,36 +680,39 @@ int kunit_run_tests(struct kunit_suite *suite)
 		} else {
 			/* Get initial param. */
 			param_desc[0] = '\0';
-			test.param_value = test_case->generate_params(NULL, param_desc);
+			/* TODO: Make generate_params try-catch */
+			curr_param = test_case->generate_params(NULL, param_desc);
 			test_case->status = KUNIT_SKIPPED;
 			kunit_log(KERN_INFO, &test, KUNIT_SUBTEST_INDENT KUNIT_SUBTEST_INDENT
 				  "KTAP version 1\n");
 			kunit_log(KERN_INFO, &test, KUNIT_SUBTEST_INDENT KUNIT_SUBTEST_INDENT
 				  "# Subtest: %s", test_case->name);
 
-			while (test.param_value) {
-				kunit_run_case_catch_errors(suite, test_case, &test);
+			while (curr_param) {
+				struct kunit param_test = {
+					.param_value = curr_param,
+					.param_index = ++test.param_index,
+					.parent = &test,
+				};
+				kunit_init_test(&param_test, test_case->name, test_case->log);
+				kunit_run_case_catch_errors(suite, test_case, &param_test);
 
 				if (param_desc[0] == '\0') {
 					snprintf(param_desc, sizeof(param_desc),
 						 "param-%d", test.param_index);
 				}
 
-				kunit_print_ok_not_ok(&test, KUNIT_LEVEL_CASE_PARAM,
-						      test.status,
-						      test.param_index + 1,
+				kunit_print_ok_not_ok(&param_test, KUNIT_LEVEL_CASE_PARAM,
+						      param_test.status,
+						      param_test.param_index,
 						      param_desc,
-						      test.status_comment);
+						      param_test.status_comment);
 
-				kunit_update_stats(&param_stats, test.status);
+				kunit_update_stats(&param_stats, param_test.status);
 
 				/* Get next param. */
 				param_desc[0] = '\0';
-				test.param_value = test_case->generate_params(test.param_value, param_desc);
-				test.param_index++;
-				test.status = KUNIT_SUCCESS;
-				test.status_comment[0] = '\0';
-				test.priv = NULL;
+				curr_param = test_case->generate_params(curr_param, param_desc);
 			}
 		}
 
@@ -723,6 +727,8 @@ int kunit_run_tests(struct kunit_suite *suite)
 
 		kunit_update_stats(&suite_stats, test_case->status);
 		kunit_accumulate_stats(&total_stats, param_stats);
+		/* TODO: Put this kunit_cleanup into a try-catch. */
+		kunit_cleanup(&test);
 	}
 
 	if (suite->suite_exit)
-- 
2.50.1.552.g942d659e1b-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250729193647.3410634-2-marievic%40google.com.

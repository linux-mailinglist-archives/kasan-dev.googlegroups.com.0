Return-Path: <kasan-dev+bncBDQ67ZGAXYCBBHM37TCAMGQE3YSZMBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x137.google.com (mail-il1-x137.google.com [IPv6:2607:f8b0:4864:20::137])
	by mail.lfdr.de (Postfix) with ESMTPS id A21E5B27E54
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Aug 2025 12:36:15 +0200 (CEST)
Received: by mail-il1-x137.google.com with SMTP id e9e14a558f8ab-3e56fe805d8sf47237095ab.0
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Aug 2025 03:36:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755254174; cv=pass;
        d=google.com; s=arc-20240605;
        b=BYbRlkmEtQnAeEVPMo4LAmYjyaIMCPcCC+QBCjL2IMuebZpg4gISFpMRUgaaO5MCGw
         7CTXDBmaIJUhngL0P4JGBFO678LurcFRWGfaHNVQLAVqGid0OnWExPIxEaY7wCU4ekSM
         e2DXnLPIsEp8vAwuWfXeytv3bKZxofKiSsq8Gf1aIKe/IdRIc76JMwGmdMOkgcd7eX/c
         nsAwrIfceB7wdYlbzTNayK4cM6F4YQOVAr2HfyE1X0DQ9I5IqljgqmAKDFlL0vrTV44G
         c4eHcQrpny/CydEg2CbAybmcFh8siQoOwOlyQCbF+emPqfAKm3hQBrTp9yl/OGEthebf
         A67Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=1n8V8XrV5LESOqcLKegEvgxtxHW9nkTkxB8rUO+IMJo=;
        fh=aKsgacILf9sYkejWv2alR7CS5Reb9Wb0Mi6XgL1np7w=;
        b=EnLnYAhvx8GFMPA03ebqGtBiJYFI/xY/c36vdK8Dn9sAHEcOebFiJZRvJ3bGN5wzeN
         7h6Cprzguw+aiuulXvwVDtC3aGOCKxmQxl89HMXIq+N1Uh9HPEn4eiRBw8lkJgGu5fgI
         p13uusvE0fCctBiPyK4cKlU+2v3CZ3Ow3v5m/EAbdvkZzLYgl9GnGYB8b3V4MDt5xTRi
         ITjzrHBsRXiXpv5JOKHy2DDWyE/e8HJyUzBRbsNL9qO1ag86Mz0vTnshF0THOTaMA4m4
         xFIseUXX8lCAkfbZ6A+P2p4lZesnJikQjnzxyU7Zo+Cyk8Jt3C7303MsAQyQFbd/P+cY
         pwaw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ZcV4hbBF;
       spf=pass (google.com: domain of 3mw2faagkcx4octkgxkeiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3mw2faAgKCX4octkgxkeiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--marievic.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755254174; x=1755858974; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=1n8V8XrV5LESOqcLKegEvgxtxHW9nkTkxB8rUO+IMJo=;
        b=jDK9uweJYp6Lv6Ulgda8zBAxkUIGenA6Xo/2N9kjlpV09fTkwJqoS5KmOPkg7iOcax
         Fp66d9f4CIXi1oHEdeq30nPytxkuNyyR9KIPHXSNHJmPGyOWmADK4JyMRSvsRfRHnFOu
         +mvMECVIgjw/IlaAi+vwUKMhqhMGZZ0KkPWt29FCIlVZ43iQ8Hz3StKnPuiaoGxzylhu
         yq77ipy/Gv1TJxEK+8eDSLt5eE8gAzRlk78fWRUUWbNmBEDQUafQaHnuRhr4alLDGyFi
         xx8SKgON/nuTWVbbY26NFBAnis/2Plak9pGBQcByB7IzkaHcajeL3dkvm7dCB7DI5K4q
         YNDg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755254174; x=1755858974;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=1n8V8XrV5LESOqcLKegEvgxtxHW9nkTkxB8rUO+IMJo=;
        b=dxF4JyPiGFGjE9JNTfBNqgOaE9zSsSEfNkQlkeRQmnz16fs+Khq5Kx+VliNo5NdAOk
         85h/Rby24Bmze5VUzvhQ6ET64iolCDZRPWUA2nK8vT5QtkKr3U6QcVn/HszN0jKypKLn
         x/3vDWtTThZNjcctcN1thAOosZnmJ2GglnxMypRCaD7885u7fW5n6YGcs6z/vYenqNUA
         kziAKkaRwabwlyF8qCTx4fXd25vrkky2IAESQl62h3uwwdHjmABgWvKEjf6X7N1IVYYK
         sknwm+LzxrmzHYRoGOvX6XZ5hONDkIqot4QN1ovEwV2qQRcIw+cmw3ERIIN5WKGA2ZMr
         qryA==
X-Forwarded-Encrypted: i=2; AJvYcCVvkGqgDnCL1Q8GDgBvDRbsDWcuvXKi+T8lc0FRZ5xGEkEVBTWP41TIfxMBBRH3SxUCde7T8w==@lfdr.de
X-Gm-Message-State: AOJu0YzfbGMteDPZuPL7ChHNt06t2r6ftitMMWoQxtZf2rqwXhbCIvGk
	tnvKzuP/szZLzmO2IzqZTP3mK6bRj74g1sBjNC0/lAkoql/jZhW40IqE
X-Google-Smtp-Source: AGHT+IGlqDjV64QqWh0cWFNM8BQ0qli7Ip4st0ErDdVl9RkBe4LJrdyihqa2HV0nBDyWmVP5VwQEiw==
X-Received: by 2002:a05:6e02:16c7:b0:3e5:5c80:2cdc with SMTP id e9e14a558f8ab-3e57e809e23mr24679985ab.2.1755254174165;
        Fri, 15 Aug 2025 03:36:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZehdg7TPn/PUvzbaeIc//mgIBHeIjo8Rz+L8LjBzYERNw==
Received: by 2002:a05:6e02:5e09:b0:3e2:b055:6934 with SMTP id
 e9e14a558f8ab-3e56f8ea4dels10433575ab.2.-pod-prod-01-us; Fri, 15 Aug 2025
 03:36:12 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX164N9XYc9g0+IQ5kTyHsDaaYS4F8PgkTbnnyduGK0jkj5Vne41AipSsel07i3fkk5wTFev88ROsE=@googlegroups.com
X-Received: by 2002:a05:6e02:1fc9:b0:3e5:7437:13d3 with SMTP id e9e14a558f8ab-3e57e9ceb31mr30970005ab.23.1755254171811;
        Fri, 15 Aug 2025 03:36:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755254171; cv=none;
        d=google.com; s=arc-20240605;
        b=YF7yXeYD7N8uC2TEWclQJPwTdTfBqxZ6iqXLAJRmjVL0Jci1kdFAxTHpzFlfxo/R21
         tLZwkDmYBV1vGq5jswaug28GKcPH3mrGOajxkNperUBjWzh7mp8iqhiehHe1dB+11ycd
         pSQVULTxGdXq4PoS7kkg+8W25MBcEz4VBTetBZpwa9h7SKAiAlWxyT7prBnkXW3TP4qJ
         w/jQo11OdEsBKNI7maWW6W+UO6F9/DA+tHq+bVeVOC2jECRZ1YZsZh1he3gKFHeq4NpR
         4RucRXB1FQfd/GeCbDwpxGg3vJ10m5pL7Xws6/2cVtMB/LGDbD/rlmAMUeQplIsna0qc
         v9bQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=9cK185h9gxNmOTBKXZc10qbmIH62I7BV6bECtC8O9ek=;
        fh=vDzFEQPLz5ENsylMf0oDh6MnCIW+yyy3R2k2wE2ARYQ=;
        b=eGNM1iL28N7z95MB0FjPfcwMmsqXqhe03bLQ3BXjP1QF2R4O6cZ9I5HQtswM2qEDl6
         2Oi2QmTdHn4zDGXv2VBfqYauNLn4WXNvG9HTGILrMX/sz0p2YyWEE00vFoIP8Jkw+wgX
         qNr4qaZiRlJQIpy8bt1+rUVxtSqTkBJ+7DoBdcJe/5WxR7zi6kuy2B5ZyL4GkgBpu2ry
         da4dnim9KAFPoF3OU2OYdl+y2xysukphy70skPPpMez0uNqakjzSiDdF63GydA4zCFS9
         TiBbpJ0MXLtVKYDaW1VfdNhNDIDLOCZ9MMiqKNm5H3DVFKus0Gytfb9NEdoP0Xy3XTZ+
         nzig==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ZcV4hbBF;
       spf=pass (google.com: domain of 3mw2faagkcx4octkgxkeiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3mw2faAgKCX4octkgxkeiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--marievic.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3e57e76f512si370895ab.3.2025.08.15.03.36.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Aug 2025 03:36:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3mw2faagkcx4octkgxkeiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id d75a77b69052e-4b109ab2cbaso49956721cf.1
        for <kasan-dev@googlegroups.com>; Fri, 15 Aug 2025 03:36:11 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWKzoCupF7jedkjlW0TJMxAGXoN+NQrFT23wdUCNnkR/9o2i0TOuPC5soUeQjM1qoE7M7FsrUrMTdg=@googlegroups.com
X-Received: from qtbih9.prod.google.com ([2002:a05:622a:6a89:b0:4b0:9663:7cc6])
 (user=marievic job=prod-delivery.src-stubby-dispatcher) by
 2002:a05:622a:1b12:b0:4b0:616f:919b with SMTP id d75a77b69052e-4b11e21e941mr15083281cf.39.1755254171112;
 Fri, 15 Aug 2025 03:36:11 -0700 (PDT)
Date: Fri, 15 Aug 2025 10:35:58 +0000
In-Reply-To: <20250815103604.3857930-1-marievic@google.com>
Mime-Version: 1.0
References: <20250815103604.3857930-1-marievic@google.com>
X-Mailer: git-send-email 2.51.0.rc1.167.g924127e9c0-goog
Message-ID: <20250815103604.3857930-2-marievic@google.com>
Subject: [PATCH v3 1/7] kunit: Add parent kunit for parameterized test context
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
 header.i=@google.com header.s=20230601 header.b=ZcV4hbBF;       spf=pass
 (google.com: domain of 3mw2faagkcx4octkgxkeiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--marievic.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3mw2faAgKCX4octkgxkeiqqing.eqomcucp-fgxiqqingitqwru.eqo@flex--marievic.bounces.google.com;
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

Currently, KUnit parameterized tests lack a mechanism to share
resources across parameter runs because the same `struct kunit`
instance is cleaned up and reused for each run.

This patch introduces parameterized test context, enabling test
users to share resources between parameter runs. It also allows
setting up resources that need to be available for all parameter
runs only once, which is helpful in cases where setup is expensive.

To establish a parameterized test context, this patch adds a
parent pointer field to `struct kunit`. This allows resources added
to the parent `struct kunit` to be shared and accessible across all
parameter runs.

In kunit_run_tests(), the default `struct kunit` created is now
designated to act as the parameterized test context whenever a test
is parameterized.

Subsequently, a new `struct kunit` is made for each parameter run, and
its parent pointer is set to the `struct kunit` that holds the
parameterized test context.

Reviewed-by: David Gow <davidgow@google.com>
Reviewed-by: Rae Moar <rmoar@google.com>
Signed-off-by: Marie Zhussupova <marievic@google.com>
---

Changes in v3:
v2: https://lore.kernel.org/all/20250811221739.2694336-2-marievic@google.com/
- Commit message formatting.

Changes in v2:
v1: https://lore.kernel.org/all/20250729193647.3410634-2-marievic@google.com/
- Descriptions of the parent pointer in `struct kunit` were changed to
  be more general, as it could be used to share resources not only
  between parameter runs but also between test cases in the future.
- When printing parameter descriptions using test.param_index was changed
  to param_test.param_index.
- kunit_cleanup(&test) in kunit_run_tests() was moved inside the
  parameterized test check.
- The comments and the commit message were changed to reflect the
  parameterized testing terminology. See the patch series cover letter
  change log for the definitions.

---
 include/kunit/test.h |  8 ++++++--
 lib/kunit/test.c     | 34 ++++++++++++++++++++--------------
 2 files changed, 26 insertions(+), 16 deletions(-)

diff --git a/include/kunit/test.h b/include/kunit/test.h
index 39c768f87dc9..b47b9a3102f3 100644
--- a/include/kunit/test.h
+++ b/include/kunit/test.h
@@ -268,14 +268,18 @@ struct kunit_suite_set {
  *
  * @priv: for user to store arbitrary data. Commonly used to pass data
  *	  created in the init function (see &struct kunit_suite).
+ * @parent: reference to the parent context of type struct kunit that can
+ *	    be used for storing shared resources.
  *
  * Used to store information about the current context under which the test
  * is running. Most of this data is private and should only be accessed
- * indirectly via public functions; the one exception is @priv which can be
- * used by the test writer to store arbitrary data.
+ * indirectly via public functions; the two exceptions are @priv and @parent
+ * which can be used by the test writer to store arbitrary data and access the
+ * parent context, respectively.
  */
 struct kunit {
 	void *priv;
+	struct kunit *parent;
 
 	/* private: internal use only. */
 	const char *name; /* Read only after initialization! */
diff --git a/lib/kunit/test.c b/lib/kunit/test.c
index f3c6b11f12b8..14a8bd846939 100644
--- a/lib/kunit/test.c
+++ b/lib/kunit/test.c
@@ -647,6 +647,7 @@ int kunit_run_tests(struct kunit_suite *suite)
 	struct kunit_case *test_case;
 	struct kunit_result_stats suite_stats = { 0 };
 	struct kunit_result_stats total_stats = { 0 };
+	const void *curr_param;
 
 	/* Taint the kernel so we know we've run tests. */
 	add_taint(TAINT_TEST, LOCKDEP_STILL_OK);
@@ -679,37 +680,42 @@ int kunit_run_tests(struct kunit_suite *suite)
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
-						 "param-%d", test.param_index);
+						 "param-%d", param_test.param_index);
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
+			/* TODO: Put this kunit_cleanup into a try-catch. */
+			kunit_cleanup(&test);
 		}
 
 		kunit_print_attr((void *)test_case, true, KUNIT_LEVEL_CASE);
-- 
2.51.0.rc1.167.g924127e9c0-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250815103604.3857930-2-marievic%40google.com.

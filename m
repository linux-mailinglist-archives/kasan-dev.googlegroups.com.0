Return-Path: <kasan-dev+bncBC6OLHHDVUOBBTHVWXCQMGQE575URNI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3d.google.com (mail-qv1-xf3d.google.com [IPv6:2607:f8b0:4864:20::f3d])
	by mail.lfdr.de (Postfix) with ESMTPS id A189BB35854
	for <lists+kasan-dev@lfdr.de>; Tue, 26 Aug 2025 11:13:49 +0200 (CEST)
Received: by mail-qv1-xf3d.google.com with SMTP id 6a1803df08f44-70d9a65c386sf80886016d6.1
        for <lists+kasan-dev@lfdr.de>; Tue, 26 Aug 2025 02:13:49 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756199628; cv=pass;
        d=google.com; s=arc-20240605;
        b=MFDO3d96ha/pmN3vTSLfoPqRBO3ZJ/QXsFjL8UUraI/wsZ8yjBeClSrBvWBje3PQ+U
         l7nQ+fx5ukgBsaknPym1NfvujKJhcpjtrZywaASRgiWLI26GbSmomVnnlUB6rXad0+Is
         AMZi6j2b5TfM6ZMQhPJJJg8EXfapoBxztMDqmWt0+KzLMkapoJ4GgnrWjJQDtS2NnVxZ
         fS0B/0tMQF/8WKHHu7127fh2AkKyZlV+0tdyHbzgOTpupjJNTqxko4u/o+H+HNb7rGqh
         VzOj5rJ6UkeK9oQc0vQuW4yr1q0N0/dC3xUgthJyGRaxzPjGRqzS0tvdn/PGqnczI1+4
         DENA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=8c0930ZCfHvZU/AYLylyeshyiqDSsWN2Rk3eZO1lyTs=;
        fh=8zW6/YaYUxt6c0Y78jugzyWCYva8OF5aOkGDu4IjW4c=;
        b=hwK7ejZCr/iG8K48WEcfq40cSd469m4AgE6T13fj1+bw8JJiIjl7doODr+jT6Uzeyi
         KGciGcZjBWPVDC2PTLhQLFENmzqCxLQAaSpnP0GRuT++G4Nljl/4LdgHprkO9naeXGiL
         HtC3KIaBvZdJfEmrbWnDg9IM7k0zd3P8unoTBonjt0dqEslM022LLT49EULsNMn3tAs6
         xIjlU7QqnslJVY3vDCM0i0bjZ1Jjqr64e0Bskzf0/dhmp4ZTwWl65y+B5rQPYruY22qm
         K6i5PmcqssOQlvWmWnV+ygd2IxxxKOdH6BNejXzWhaNxib+5DfTTXMslvWsnsZtmL0hS
         kCwA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=lbpygjHi;
       spf=pass (google.com: domain of 3ynqtaagkccekh2pknv3nvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::44a as permitted sender) smtp.mailfrom=3ynqtaAgKCcEkh2pknv3nvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756199628; x=1756804428; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=8c0930ZCfHvZU/AYLylyeshyiqDSsWN2Rk3eZO1lyTs=;
        b=Q/UC+wc3w+FfZdXczgqQXm2uCYRN1g+cE+qUxBSzmJ2AZAbMqV5C457arKaVaCSItA
         IrIDu4yDsLXHugV9zrN5hHb9oZateTGjX+ghmtbr6MlbFR68BZgX3UqNagQO7gO7rm2y
         WYWQXyIuShoINxMXN1QkFcYZEJgVfIAwsw3cVxtx4bSy6a7cU8Cvm4g7DaljkS1ch9Q9
         gnTOMm8R8N51uAyhstWjDn1mJrLn/mbuO1P+PVsBxVkOwb1hWrorX4YdMqyUKow2oCJ9
         +TsIjlkISzB7J+eYnhwPpRs7K+7R1qFALly9wDehnkP0wlmABhFsqlbdRgPHGR25HLf5
         ykdg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756199628; x=1756804428;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=8c0930ZCfHvZU/AYLylyeshyiqDSsWN2Rk3eZO1lyTs=;
        b=J4Oc/YeKb+Oy2KYQtNG6P3CigSEMGqv0u3lQWXH+2tnduiWIJnT3cImwKto09UQmVK
         szgraqX8gme5If+u/LSMbauBbYPlvqEWEz8W05muNKtNWtI+/FhyxyFZlmVcqCni6BDQ
         M3nhR7jqE9k4FXjTElhlMXNp9/NOngL4mcHGok4llvw4919rkAijUpkgPLJAHCpzWBNp
         gAN4C9q4BF8D8gSR2BJSzMrFq7XZzrvBqmjQLLpeZPkDu0tnCHp2OQ89iTMUT3wCCbOG
         fm/XxBuEJiiEDm88VxCgFcyw2zK8LlejGWoOvRLkhOsfLa1iiprJLV5gjPlyaV6FVmGx
         CVAw==
X-Forwarded-Encrypted: i=2; AJvYcCUuoF/k+d6XoAGgEDzJdOpZddFCu9dGmyfhr9IT3J8H6xlcwqeXzP0P+QUVEfd6FAhSC4XVFQ==@lfdr.de
X-Gm-Message-State: AOJu0YwUEJmYQthAPTXyf/IXp4JkgEzFGquZ7mnDy8KmlgzQF1T/WWhK
	R7RugRMI/1ZJecJ+6rTVRnFmtItlUF+r0A4kxgDB9lvKjAU9F9GslIrQ
X-Google-Smtp-Source: AGHT+IHLUyxldQa8F+9Zy7kjMM6DRn3onCxPPKwk5eDSH+e2L+VRXkrJY7EHeeqRV1kBXy4GAjJOcg==
X-Received: by 2002:a05:6214:2b0b:b0:70d:c4c3:cdea with SMTP id 6a1803df08f44-70dc4c3d737mr61914686d6.36.1756199628417;
        Tue, 26 Aug 2025 02:13:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdwEE1KLzD2Y++rpj5zWWJFvs3ielkzNe9Y2lnVH9fOfw==
Received: by 2002:a05:6214:2129:b0:707:56ac:be47 with SMTP id
 6a1803df08f44-70da819701bls44015206d6.0.-pod-prod-01-us; Tue, 26 Aug 2025
 02:13:47 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXhfVWi6UeM2T5c55ayXplsieBs8GRyXUPDGtt1Q9E84aikA6qI0eu0T4pWZSOzrApBKMRiGkVvbTQ=@googlegroups.com
X-Received: by 2002:a05:6122:a0e:b0:537:3faf:9b43 with SMTP id 71dfb90a1353d-53c8a432496mr4202585e0c.12.1756199627334;
        Tue, 26 Aug 2025 02:13:47 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756199627; cv=none;
        d=google.com; s=arc-20240605;
        b=Bml0oC3Riyg5cZkUebuIwP/VZ2sYcgrLQ5eqppiYeWHZVWEDZpFB3ra3mmWB/HfrHu
         MC90O5+IqFbyDZarBwP8GOfP5MTl2hlq0/F7E0yJn5IFmCtmpQpd7N41PkV0jwKd7GuT
         VBV165mpzbQzcZzmUiUsWFHeqhHvdNJ9XxtYQ2XSgpnasvnLaY3GxZ7zZlBagLgPvpC+
         OqtmV6VDHJgzOtl3lKiU1U7R29eCQ8G9Bb+wDpR8mfYAmWdEIXyDgOXmk74WvqRvhx1k
         PaEowK5vo+L78bofZR38NjJj+pMKRXKoY5ZFT7g043Ku4IXNATbYvmRtu0bijIB8wzPF
         YRjQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=Z06H7nQAXuGVWeGBmy7rHwPZSCBDj75F7L0FEZo0y1s=;
        fh=NC9WaOcsGhu8ywnNr9FTAxlqw0ZVMT4YHT147jKRpk0=;
        b=AnV9C+gJ69RYzfCqopMHZbnL66XD1WLK0nzxvgMGTdD52gPr/waXJLZCk5X/LXZcX2
         A398W+mO+VPLGYeUN3o15PPurI5Xya2HI5g1IZbuch0SHkOGj6GgHpZmsDy8zAL5Jt6Q
         LXmPwUyHtW9KkG+j8qbqrRyx2phAeUK1oBPh+cpZyuKCQpMDOuAh4XrK5lW9pfcszV+H
         1UsuVR0UaV1gcCMrkQK+WaCQg6flrLODR0EXblUxOCJ1puwu0qXRcPxx4wcmdeOvy0qE
         0W0Egzu9skOciyrOe4CKkHHfdPLzgsWi5vFyYrgNgCUtlVdlQwoY5Iwo1OxAoGOr4fWE
         qKzQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=lbpygjHi;
       spf=pass (google.com: domain of 3ynqtaagkccekh2pknv3nvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::44a as permitted sender) smtp.mailfrom=3ynqtaAgKCcEkh2pknv3nvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pf1-x44a.google.com (mail-pf1-x44a.google.com. [2607:f8b0:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id 71dfb90a1353d-5423a81a165si143884e0c.3.2025.08.26.02.13.47
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 26 Aug 2025 02:13:47 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ynqtaagkccekh2pknv3nvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::44a as permitted sender) client-ip=2607:f8b0:4864:20::44a;
Received: by mail-pf1-x44a.google.com with SMTP id d2e1a72fcca58-76e2ea9366aso4912737b3a.2
        for <kasan-dev@googlegroups.com>; Tue, 26 Aug 2025 02:13:47 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCVdRYc303IFdulibzdgVPf2VV7B4pzMxp+UXfRLCN5kKd9wvyhO2fqnftfeUhbLCnnrzzfRx77NsA4=@googlegroups.com
X-Received: from pfx51.prod.google.com ([2002:a05:6a00:a473:b0:771:e00d:cee])
 (user=davidgow job=prod-delivery.src-stubby-dispatcher) by
 2002:a05:6a00:4b56:b0:76e:7ae9:e869 with SMTP id d2e1a72fcca58-7702fb00068mr18610618b3a.25.1756199626242;
 Tue, 26 Aug 2025 02:13:46 -0700 (PDT)
Date: Tue, 26 Aug 2025 17:13:31 +0800
In-Reply-To: <20250826091341.1427123-1-davidgow@google.com>
Mime-Version: 1.0
References: <20250826091341.1427123-1-davidgow@google.com>
X-Mailer: git-send-email 2.51.0.261.g7ce5a0a67e-goog
Message-ID: <20250826091341.1427123-2-davidgow@google.com>
Subject: [PATCH v4 1/7] kunit: Add parent kunit for parameterized test context
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
 header.i=@google.com header.s=20230601 header.b=lbpygjHi;       spf=pass
 (google.com: domain of 3ynqtaagkccekh2pknv3nvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::44a as permitted sender) smtp.mailfrom=3ynqtaAgKCcEkh2pknv3nvvnsl.jvtrhzhu-kl2nvvnslnyv1wz.jvt@flex--davidgow.bounces.google.com;
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
Signed-off-by: David Gow <davidgow@google.com>
---

No changes in v4:
v3: https://lore.kernel.org/linux-kselftest/20250815103604.3857930-2-marievic@google.com/

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
index d958ee53050e..9766403afd56 100644
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
index d2bfa331a2b1..587b5c51db58 100644
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
2.51.0.261.g7ce5a0a67e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250826091341.1427123-2-davidgow%40google.com.

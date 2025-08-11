Return-Path: <kasan-dev+bncBDQ67ZGAXYCBBDOY5HCAMGQERKB6O2A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id E867BB21813
	for <lists+kasan-dev@lfdr.de>; Tue, 12 Aug 2025 00:17:51 +0200 (CEST)
Received: by mail-pf1-x437.google.com with SMTP id d2e1a72fcca58-76c47324232sf3034367b3a.0
        for <lists+kasan-dev@lfdr.de>; Mon, 11 Aug 2025 15:17:51 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1754950670; cv=pass;
        d=google.com; s=arc-20240605;
        b=EXLEtAQZow7MOPvDaJhjAVtWhgdAi//+rFzU/V0sbc+oYWgD5GYb+k5yWU8i1/h8t4
         gqJ47JSTqiryDnofgHSYrzSZZYvGlLePESMXzN0nvFeqBoTgEKpDMiZ/oXbZFxkA8wh7
         oMDHLyyHz7Td4mJ6zVgTDzLu1nqiTqF1yJjtc6XmO+gIbY8rVuYzsbOcWwcZiQs4p6Bj
         NVmnm+jR9VvCi1kkmr+qBvqSWDsxD2MyQgRrHq0O0iYNacM9yPDZAmcnkUaGFqEYmI0I
         AwrXIO6R902ctY1uHjsZyCPnf4U9ixfei9xindEsa0207/HB207EC+05LQfVxK2RXl1m
         Kyhw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=MNkg+X0yeInZDgN7QKsg9G2g2kVd3pxyNXI6JLgpYtE=;
        fh=T4/0xK5AWnI2pLBKgt4iprXFZnVHS5ZtWHsd589pqVM=;
        b=bzGYVVgyJZWxr7d8hG9IyQEOXBCT4JaFkkzKG90Dsb1RbIWqkDIfjDBBHVb7u9Juf7
         uLgmk1isa5ciH9BEWTZZW8zDDTKuia28ey2aqI3y//Vw53unBE394XPwWOQb9kgLMWRv
         KQzdXAqhqN/icdB36o9fnEU+Cx4eoeXJ7EFOEqEt2pYYAx2Cn4deCcq/fNXVRTzkfVnj
         lTS4Soc2MBQ8ccMG2V8AqRVN1j6hdhab3EQ+bfu4+E/f9Qk4LayOi067R4Hw7sRflioQ
         N/umQ1EcqtmrFD7b0qglnYmJ66BOR4A3r6LziABgQPzXgn0oUfO9fe50vQvDJznFDEyJ
         Rxpg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Eyb5EtDF;
       spf=pass (google.com: domain of 3c2yaaagkczge2ja6na48gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3C2yaaAgKCZgE2JA6NA48GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--marievic.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1754950670; x=1755555470; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=MNkg+X0yeInZDgN7QKsg9G2g2kVd3pxyNXI6JLgpYtE=;
        b=JnjOI16uUTfd21SLZyMknHa9QEG6UosO4DIrILXwLsnqVggmP8HG/qwmgzbecW+ziI
         MIafYZKmw+zWjeVhxt6HK83OgZk3tjC74QEVvpPATMv/0mrNYrXvN3qxuObEdy+NHMvS
         ZyPmP2H1iYZh17XLltXoBk+O2RRlNfJx7ZyRbZo1Yk+JSfM8HYsCosLONX5NjPTO4DE7
         xHUZ27N8e5n8xBB6HopA3vNfDyt6bJQ4iiQw+Is7RHCRib+EvHpEM0WY96DaGwrHQi7j
         aAgsseJT5wunY+HzOAdPdyseMIyjffYe22mT0VoMHPOlQuUDs1Bgzf4S0QcZRDYEb9q6
         xeoA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1754950670; x=1755555470;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=MNkg+X0yeInZDgN7QKsg9G2g2kVd3pxyNXI6JLgpYtE=;
        b=khRvwl23Wf7xf+1p63UgzUpIJUQBRaNoiEWT9wrgqoyjUGDeHe+3KmF6WWUWw7z3Bn
         t7d24JCzqdYPhUJRIr8LGaGASKsaQUb/+YlpdO+xtZ792HPLPsudyUAEV0nP3yIRja+T
         kxphqBRnTiYdTh3uWvsrObnGhZYkNhKEcUAqvbR4htUp7DQDjeNSN1iWVP6Lr+mdzsBJ
         MwAuUEp5M5qcB4T6rdB2icEqGD4YiQHiJ/yMk06wGwvwBUBPi4omagxeOcO0PF7sTGHx
         Ttt+CrUiFLQ0mDlyGCLaDkLBxQraWNooWNdAnYYokh9oLl2cw9ucRjZSI7/Szsmb+dhi
         U5Uw==
X-Forwarded-Encrypted: i=2; AJvYcCXS/h0LcEkbl7Zb8b3AbDMSSS+5MqELNiIe6+Cdwhz3NDXaIVF1lziPrXPe9Hsf5MZ+dgP+tg==@lfdr.de
X-Gm-Message-State: AOJu0YyX78h/oLPul8tvZkuVPY8NPG7Co4UUXMa8gaSzWtYklfYeOPKY
	J98//48dGwnfPWeCkcJsX+vJJQ67ondQwVBGIjW6hzN9twn9/jrj/GOk
X-Google-Smtp-Source: AGHT+IEaSX8n9cu3N0xoPA89ZcoYkwKKCEb6h1jTxNE4RmzBnwAWCvvsy2fIT6OJJbTcaipB+pmKFQ==
X-Received: by 2002:a05:6a20:5493:b0:204:4573:d855 with SMTP id adf61e73a8af0-240550162ebmr23340347637.9.1754950670052;
        Mon, 11 Aug 2025 15:17:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcfaH6X54MIetsR4P0CpOdPRyI/y9K986ozgexOJezFJQ==
Received: by 2002:a05:6a00:498f:b0:736:b063:5041 with SMTP id
 d2e1a72fcca58-76c3704c4dals2453306b3a.2.-pod-prod-07-us; Mon, 11 Aug 2025
 15:17:48 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUcXFLpXTM3/ovNMpo40eBvpprD766sFY+eUSEtYwYatOmUJJdpYPuDSzt19/fH2gE+2sbZrDX10fc=@googlegroups.com
X-Received: by 2002:a05:6a21:9988:b0:23d:781f:1516 with SMTP id adf61e73a8af0-240551604f0mr22537397637.22.1754950668597;
        Mon, 11 Aug 2025 15:17:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1754950668; cv=none;
        d=google.com; s=arc-20240605;
        b=ah5Eo1DGhPD/IGJNejAmxjFrpDovI4g5JbFl1cB7USsgtha/4IKGoNXpPzIrY4xJN9
         Uq6CwTTDHSM3ikB+voFwtwz7PTjU/LIU0H/22etjZ0dZXDU9bMAbQoysYe9BIe3abhe7
         Tpj9GQQANMDyaOdsYgZvHaUq0kfZUA9Sae6M0LqDiZavZwU0eRu1OyZ2kgWE80OKPpE7
         F5BI8oiIwAizeHs1+tPcU6mhqkOb6ndqzOxoy6AfESyj6ti4doTwDTC9YiKCWFw5EZ1l
         1H+sQnAfh3yafcCOS2q2QfdbU1frt6KgzXv4wSqVHH7nUgxR8PlzMeBAAmXzv2yp5r0n
         efxg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=ai73eVBeTV1L+LH/Eg2uYJxn5nX9nX6extQG0PIgIeU=;
        fh=hVIQNC985pS6gl6JKf4NkcwAyuSWIhrKVaK23tey/mA=;
        b=TmuvIYzI4oKmRtXJUstJd5+xikphwkr54Hxa9/byJAJTtxTanFQQDHQOFZoDP5VxEE
         WkdOJSkeBuWBAaSVXY1v7hGke/gy+9iYUkc7mFmR+LLisYjzXB3NQIolQNNWpm2+n42d
         o0+cYp/Oa3bZMX+v69mlXp0f/vG88Hsgd3SI/Me2InMvRvlQx+Wc9LLrHUXE0qfXncej
         yxWBoGUTVCiRuEWsaCCGENUQspPvF2m7BQQsDT0dOFSa3+LmW2e1Ap2V7RcA4ALcdKI4
         P7wlWMkPvr7i5qGFTLiKVuV5e/zZewFV/rRsh1IGAY4FpCGa57eLtfDuBOQP4y9jRYqc
         z6ag==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Eyb5EtDF;
       spf=pass (google.com: domain of 3c2yaaagkczge2ja6na48gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3C2yaaAgKCZgE2JA6NA48GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--marievic.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf4a.google.com (mail-qv1-xf4a.google.com. [2607:f8b0:4864:20::f4a])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-b422b8a91c5si1123056a12.4.2025.08.11.15.17.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 11 Aug 2025 15:17:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3c2yaaagkczge2ja6na48gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--marievic.bounces.google.com designates 2607:f8b0:4864:20::f4a as permitted sender) client-ip=2607:f8b0:4864:20::f4a;
Received: by mail-qv1-xf4a.google.com with SMTP id 6a1803df08f44-70738c24c4fso44436946d6.1
        for <kasan-dev@googlegroups.com>; Mon, 11 Aug 2025 15:17:48 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCX0wU3GnWrqHwSBGvnms4VuSYPaF31GtP/l+R6z4v8HxroweaO9dNUqt+YCzCa1S/cQ/s05FSo/5Mk=@googlegroups.com
X-Received: from qvad7.prod.google.com ([2002:a0c:f107:0:b0:707:34cf:dea8])
 (user=marievic job=prod-delivery.src-stubby-dispatcher) by
 2002:a05:6214:2522:b0:707:3c17:8e8b with SMTP id 6a1803df08f44-7099a5022e3mr203449086d6.50.1754950667602;
 Mon, 11 Aug 2025 15:17:47 -0700 (PDT)
Date: Mon, 11 Aug 2025 22:17:33 +0000
In-Reply-To: <20250811221739.2694336-1-marievic@google.com>
Mime-Version: 1.0
References: <20250811221739.2694336-1-marievic@google.com>
X-Mailer: git-send-email 2.51.0.rc0.205.g4a044479a3-goog
Message-ID: <20250811221739.2694336-2-marievic@google.com>
Subject: [PATCH v2 1/7] kunit: Add parent kunit for parameterized test context
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
 header.i=@google.com header.s=20230601 header.b=Eyb5EtDF;       spf=pass
 (google.com: domain of 3c2yaaagkczge2ja6na48gg8d6.4gec2k2f-56n8gg8d68jgmhk.4ge@flex--marievic.bounces.google.com
 designates 2607:f8b0:4864:20::f4a as permitted sender) smtp.mailfrom=3C2yaaAgKCZgE2JA6NA48GG8D6.4GEC2K2F-56N8GG8D68JGMHK.4GE@flex--marievic.bounces.google.com;
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
to share resources across parameter runs because the
same `struct kunit` instance is cleaned up and
reused for each run.

This patch introduces parameterized test context,
enabling test users to share resources between
parameter runs. It also allows setting up resources
that need to be available for all parameter runs only once,
which is helpful in cases where setup is expensive.

To establish a parameterized test context, this
patch adds a parent pointer field to `struct kunit`.
This allows resources added to the parent `struct kunit`
to be shared and accessible across all parameter runs.

In kunit_run_tests(), the default `struct kunit`
created is now designated to act as the parameterized
test context whenever a test is parameterized.

Subsequently, a new `struct kunit` is made
for each parameter run, and its parent pointer is
set to the `struct kunit` that holds the
parameterized test context.

Signed-off-by: Marie Zhussupova <marievic@google.com>
---

Changes in v2:

- Descriptions of the parent pointer in `struct kunit`
  were changed to be more general, as it could be
  used to share resources not only between parameter
  runs but also between test cases in the future.
- When printing parameter descriptions using
  test.param_index was changed to param_test.param_index.
- kunit_cleanup(&test) in kunit_run_tests() was moved
  inside the parameterized test check.
- The comments and the commit message were changed to
  reflect the parameterized testing terminology. See
  the patch series cover letter change log for the
  definitions.

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
2.51.0.rc0.205.g4a044479a3-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250811221739.2694336-2-marievic%40google.com.

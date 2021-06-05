Return-Path: <kasan-dev+bncBC6OLHHDVUOBBDHI5OCQMGQEMDKTKPY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103d.google.com (mail-pj1-x103d.google.com [IPv6:2607:f8b0:4864:20::103d])
	by mail.lfdr.de (Postfix) with ESMTPS id 3AC7339C594
	for <lists+kasan-dev@lfdr.de>; Sat,  5 Jun 2021 05:48:30 +0200 (CEST)
Received: by mail-pj1-x103d.google.com with SMTP id fu20-20020a17090ad194b0290163ff5d5867sf8954965pjb.2
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Jun 2021 20:48:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1622864908; cv=pass;
        d=google.com; s=arc-20160816;
        b=MzgfHenslvpLcgWrGvvnjGg3hqV0OSO1j+pYsEnkcDuMQxZros6EvA5NvyXwozS9ui
         qfozmGn9pl6kCIFvz+292y6aEAui3OKB51CGh49uIf6p6g9fEBe6NCLLiV58eDdBWKXd
         0hxazipoxCj0TI7ofOhRPFGIgSvGO3gLGPcr+2fLmw03/e9c6zJu6tPpnot3BmQLysGr
         8a/SwGJJSaSn5gxwBEc0pQpZETAUyguR6MhkhNpMvpRva5RoppM75k2BkbLSQj5YQ90O
         1WE/HXqx2KC3kib17XuTlwsuK12u5iuQ/+J0EgUAELUvMfAcfTOxPSFF4NiJrI4dRPGq
         RKHA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=9DCD3IgNcBAVaqFKFW8NlvngApIeTwLNQl4ZC0qjeTs=;
        b=rgzOBwVqN1ZgaUAWhaUr7KS4ke4hzdSFUc7yA3es9WdC0nZdZnRi/Whsm3PKBFG5AU
         Cyaftrb/5BJhFq5IsjME46P30EDl+TLFrWq2YELGtYwJn/ZLNDZ8NaMFLls7/JSTJMUV
         2RsSYTKi0ZZrGta2SoyoGrGErFPttrJxhUf+vbUge8IC1nY5cxM8Z1zM3XUGxAXWJQlI
         OaucnEIxobhTPzQ0q7+hpzk1z9PVey7oFp3bdbF2ZaYoUQzZuUUzoeUf25zRmly+2wYF
         km4BaoTVCBQZKDWDiOGQ4i73YOFTcxGt9CRNHnAMF8KiHgJfRznbu7lqYlDxNgNuwI55
         TpDA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TvjnijF0;
       spf=pass (google.com: domain of 3c_s6yagkceopmhupsaisaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3C_S6YAgKCeoPMhUPSaiSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=9DCD3IgNcBAVaqFKFW8NlvngApIeTwLNQl4ZC0qjeTs=;
        b=LTJzBFBLs7eq3RELUkV8Frz+uXytxvC2v4lKVjQ6xVGQsTHAqjPAQcORmZsiY3+5Wi
         5rZxTYFx8KkmIahYEQVR9hj2np29PzUpp+LLqlKLqSob+N4V3/TSg2sqgN9cPN/sFqVN
         VXJ/WoKy3NEoy0Jp9eUlQCdRS70W/rH/g2TjQIxXq/hYnHLAIAZBNzsA8IzAhIjDUewN
         in1ErIgxYKT0S5z8Me72bPbZIiObgskWfTWBoBGr7ENIotaZJ0uW5zgO+S0gdyWUfEv6
         qIl2ACV0/mS8ehDm6clXcA32Y0mzrQXeRFIZeOrazkZBhMTUzRLS4PZnNIlk5zzWjsdq
         qzYQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=9DCD3IgNcBAVaqFKFW8NlvngApIeTwLNQl4ZC0qjeTs=;
        b=AFKZmoH+9B/TWFBphpDM5gFvuN6b4grnH1gM+5AmhSYrwZk3jVg1vXkhxa0nphzcO0
         TnbCG6Fv4TlYMwSZDITKDOKSjlJ+sq0bS/9F67J9M3SBx5NUQDlGfjP8N1HZla9YtwX3
         TrIjVUh5p4oTPNztsu4c7iYWuLHzF+8caHaEe96knIAvBzoAMaGTzq8SeAIxmTvKwkxJ
         gveujGN/a9uIddpck9qw4/AxCwh0D1tAj9JQ8aKJswr6fvHXOvkOimFSV5Km13hKMQPD
         CDL1pkrzE5FZ3xaLB6tXgvnamJTd7Z4SD59Jfu55+gsvYIV89eqpfdKqlBaDoFxl2+I3
         ns7g==
X-Gm-Message-State: AOAM533hNgpnYikY1o941f9K1+kx/geFA7LFKS0sd+cPv9wpqdH3SQE0
	bDY1+Xk6ku56D5x1wzTnq90=
X-Google-Smtp-Source: ABdhPJzxUDBWQclvB0NaDspq9UZpSoLFfai1bInR4aYGhT3cewwsMaO9nobaE+PT1u9otudQPgR/LQ==
X-Received: by 2002:a17:902:6b4a:b029:fb:7b8e:56f8 with SMTP id g10-20020a1709026b4ab02900fb7b8e56f8mr7313618plt.46.1622864908707;
        Fri, 04 Jun 2021 20:48:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:4e1b:: with SMTP id c27ls4619907pgb.11.gmail; Fri, 04
 Jun 2021 20:48:28 -0700 (PDT)
X-Received: by 2002:a05:6a00:248e:b029:28e:bca9:5985 with SMTP id c14-20020a056a00248eb029028ebca95985mr7711626pfv.10.1622864908059;
        Fri, 04 Jun 2021 20:48:28 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1622864908; cv=none;
        d=google.com; s=arc-20160816;
        b=Iy8+ZttXFI1BOtlGeTroXo1PIg2nFfTmgLqVt9Df3f4AkknBojhRoK9mavLt1n3WwV
         oQVwTqNO6qzKCGK4hCN8FDBA1X8dwKgmTXdts2mqAFyTRPwBYTM4Cesb9La034dTQ76x
         GbUOmE1aIfYaMrwWb+5C5VV0TpCmC2l+CMGK6XN6P/VVqs59pzZ8JY5PyBDYdpO46UFs
         ajVoM1p7rmNcHSTd00SyBHpVnbW9w55pfTZaGAhSdaeJW7+Sye2kYKcuqxXtg6gSyfK7
         37+Absmmqxfa6DCTvLtmZ2GPbNgseQ80B4i+hGKjHZ2pcHi/EhsC7Tgu36Fsei8mB/Ym
         ydMg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=XPZDtLKS30vXkuj6yT8Gl5haFHJZ9BAHWp7Vy4vosPo=;
        b=Jk8ZNuATBePFI/wtP8jXwWpHCiOcT/euib85TF0Cea/B/+3AzwGZaB8n1n0dbYltmI
         KUkOO1FBlZ9FjvJjodtVlrPyhItwkkRy4FItKkkpg+ap04mSXMdG2slYyOqUncp1Fjfo
         jNqZKikE0VjIeNL4h/RqqtuXVkKcvERw8DzG0fW0obqR6KinabdX/eJyOWbsg3C9/39b
         p/mFFKd/UxFL/2zRHRbWh5XryLY1gFdHrKDiJqeY2n8rHlREWE020g2PMyDFO1hugjyQ
         zWJLx5LxkfBJaaiY5Q99EsmjVQV3QDL5703whOlPq09YwLJh5Aw/1DbGnobmTKuuiR+W
         47OA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TvjnijF0;
       spf=pass (google.com: domain of 3c_s6yagkceopmhupsaisaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3C_S6YAgKCeoPMhUPSaiSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf49.google.com (mail-qv1-xf49.google.com. [2607:f8b0:4864:20::f49])
        by gmr-mx.google.com with ESMTPS id u31si198811pfg.3.2021.06.04.20.48.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 04 Jun 2021 20:48:28 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3c_s6yagkceopmhupsaisaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::f49 as permitted sender) client-ip=2607:f8b0:4864:20::f49;
Received: by mail-qv1-xf49.google.com with SMTP id k6-20020a0cd6860000b029021936c6e8ffso8112859qvi.7
        for <kasan-dev@googlegroups.com>; Fri, 04 Jun 2021 20:48:28 -0700 (PDT)
X-Received: from spirogrip.svl.corp.google.com ([2620:15c:2cb:201:b70c:2182:75b0:bac0])
 (user=davidgow job=sendgmr) by 2002:a0c:dc92:: with SMTP id
 n18mr8063460qvk.8.1622864907203; Fri, 04 Jun 2021 20:48:27 -0700 (PDT)
Date: Fri,  4 Jun 2021 20:48:21 -0700
Message-Id: <20210605034821.2098034-1-davidgow@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.32.0.rc1.229.g3e70b5a671-goog
Subject: [PATCH v2] kasan: test: Improve failure message in KUNIT_EXPECT_KASAN_FAIL()
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Daniel Axtens <dja@axtens.net>, Brendan Higgins <brendanhiggins@google.com>
Cc: David Gow <davidgow@google.com>, kasan-dev@googlegroups.com, 
	kunit-dev@googlegroups.com, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=TvjnijF0;       spf=pass
 (google.com: domain of 3c_s6yagkceopmhupsaisaasxq.oaywmemz-pqhsaasxqsdagbe.oay@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::f49 as permitted sender) smtp.mailfrom=3C_S6YAgKCeoPMhUPSaiSaaSXQ.OaYWMeMZ-PQhSaaSXQSdagbe.OaY@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
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

The KUNIT_EXPECT_KASAN_FAIL() macro currently uses KUNIT_EXPECT_EQ() to
compare fail_data.report_expected and fail_data.report_found. This
always gave a somewhat useless error message on failure, but the
addition of extra compile-time checking with READ_ONCE() has caused it
to get much longer, and be truncated before anything useful is displayed.

Instead, just check fail_data.report_found by hand (we've just set
report_expected to 'true'), and print a better failure message with
KUNIT_FAIL(). Because of this, report_expected is no longer used
anywhere, and can be removed.

Beforehand, a failure in:
KUNIT_EXPECT_KASAN_FAIL(test, ((volatile char *)area)[3100]);
would have looked like:
[22:00:34] [FAILED] vmalloc_oob
[22:00:34]     # vmalloc_oob: EXPECTATION FAILED at lib/test_kasan.c:991
[22:00:34]     Expected ({ do { extern void __compiletime_assert_705(void) __attribute__((__error__("Unsupported access size for {READ,WRITE}_ONCE()."))); if (!((sizeof(fail_data.report_expected) == sizeof(char) || sizeof(fail_data.repp
[22:00:34]     not ok 45 - vmalloc_oob

With this change, it instead looks like:
[22:04:04] [FAILED] vmalloc_oob
[22:04:04]     # vmalloc_oob: EXPECTATION FAILED at lib/test_kasan.c:993
[22:04:04]     KASAN failure expected in "((volatile char *)area)[3100]", but none occurred
[22:04:04]     not ok 45 - vmalloc_oob

Signed-off-by: David Gow <davidgow@google.com>
---
Changes since v1:
https://groups.google.com/g/kasan-dev/c/CbabdwoXGlE
- Remove fail_data.report_expected now that it's unused.
- Use '!' instead of '== false' in the comparison.
- Minor typo fixes in the commit message.

The test failure being used as an example is tracked in:
https://bugzilla.kernel.org/show_bug.cgi?id=213335

Cheers,
-- David

 include/linux/kasan.h |  1 -
 lib/test_kasan.c      | 11 +++++------
 2 files changed, 5 insertions(+), 7 deletions(-)

diff --git a/include/linux/kasan.h b/include/linux/kasan.h
index b1678a61e6a7..18cd5ec2f469 100644
--- a/include/linux/kasan.h
+++ b/include/linux/kasan.h
@@ -17,7 +17,6 @@ struct task_struct;
 
 /* kasan_data struct is used in KUnit tests for KASAN expected failures */
 struct kunit_kasan_expectation {
-	bool report_expected;
 	bool report_found;
 };
 
diff --git a/lib/test_kasan.c b/lib/test_kasan.c
index cacbbbdef768..44e08f4d9c52 100644
--- a/lib/test_kasan.c
+++ b/lib/test_kasan.c
@@ -55,7 +55,6 @@ static int kasan_test_init(struct kunit *test)
 	multishot = kasan_save_enable_multi_shot();
 	kasan_set_tagging_report_once(false);
 	fail_data.report_found = false;
-	fail_data.report_expected = false;
 	kunit_add_named_resource(test, NULL, NULL, &resource,
 					"kasan_data", &fail_data);
 	return 0;
@@ -94,20 +93,20 @@ static void kasan_test_exit(struct kunit *test)
 	    !kasan_async_mode_enabled())				\
 		migrate_disable();					\
 	KUNIT_EXPECT_FALSE(test, READ_ONCE(fail_data.report_found));	\
-	WRITE_ONCE(fail_data.report_expected, true);			\
 	barrier();							\
 	expression;							\
 	barrier();							\
-	KUNIT_EXPECT_EQ(test,						\
-			READ_ONCE(fail_data.report_expected),		\
-			READ_ONCE(fail_data.report_found));		\
+	if (!READ_ONCE(fail_data.report_found)) {			\
+		KUNIT_FAIL(test, KUNIT_SUBTEST_INDENT "KASAN failure "	\
+				"expected in \"" #expression		\
+				 "\", but none occurred");		\
+	}								\
 	if (IS_ENABLED(CONFIG_KASAN_HW_TAGS)) {				\
 		if (READ_ONCE(fail_data.report_found))			\
 			kasan_enable_tagging_sync();			\
 		migrate_enable();					\
 	}								\
 	WRITE_ONCE(fail_data.report_found, false);			\
-	WRITE_ONCE(fail_data.report_expected, false);			\
 } while (0)
 
 #define KASAN_TEST_NEEDS_CONFIG_ON(test, config) do {			\
-- 
2.32.0.rc1.229.g3e70b5a671-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210605034821.2098034-1-davidgow%40google.com.

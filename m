Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQGNZCJQMGQEQXXHHSQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 30EE55197E0
	for <lists+kasan-dev@lfdr.de>; Wed,  4 May 2022 09:09:53 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id v191-20020a1cacc8000000b0038ce818d2efsf336117wme.1
        for <lists+kasan-dev@lfdr.de>; Wed, 04 May 2022 00:09:53 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1651648193; cv=pass;
        d=google.com; s=arc-20160816;
        b=vRmVOlmc2KkUjvcKSGMaH2wLYU8WgA24K/EOnwei47WAJe3t77Em2YhaL049qr2KhH
         piG3Z2gSMFPDKurgBTa4xe04PROdIXq8DeYbndjMkGc2bGG9OXBkpZ0neVzO2ECscpvJ
         xB+9WTr7EBMsUFaMk9hqtezXseJ19jw/Z+znElI3n0bUJiZJcgu+qP/xz0+OBQO7QFz/
         ndDPqSPWo/sClzWXQoCebTBEnFw3MIf5nPfoFWbkQLWQJOVKDwK6mWeXR3sF9Pdm3T3c
         HuH/O6LgDxug8RBVAKyS9OuJ9xwNgwbD7eZeMHub0X+j5b7W8xczfrKpVW+8eX22Obn9
         J8dA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=4RjschYSe6Tf0uOIWySTQjkO16UVCv+lHsWiktEzXQU=;
        b=aLOffGQhtfGOJ/xl3khv78gk3RgtadNmrk5XH1hC3bxbpN7l7CoeF4rqPdrWIZNh9m
         SgBp1iWMjTt+b/KmL+6sXB2Gm1H0D3YwYdaSN9UqFf/YO8nbAEB86JukW6cflJpZ86tN
         EHsI5MoFn43Hv55B7nlAi/grKRvUeBXQwsyPwurKhvnGzC9N1aD8TWqS3MhDwK2U9ES5
         0BQe5jaAvDAKtm29aworgBSCqDhY8dcsCks6FreY0AW5DLGKUcivcxIzGkYRj9/IIS34
         UYeGM/0XH4WSWfqUJxwpSlMjz636wgGnCm4uFe+z0gnttwo5oW8KbGAFIbcrpLSQFurV
         4jNA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=MPZFS7xd;
       spf=pass (google.com: domain of 3vizyygukce0taktgvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3viZyYgUKCe0TakTgVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=4RjschYSe6Tf0uOIWySTQjkO16UVCv+lHsWiktEzXQU=;
        b=dahJN5xllQvXjnGa+PKrISGfJQttv+GfswBz03LS129ySyK7wrfmZekKmWMKTNkD/C
         IHp1iJQC6K+VlEDX8iyFjz+yLTf2DcUFchIIpZXuoyD5dY/JeeV52h1si8zzMAwl77zQ
         XCcLz0mIVzbayQaD45sviw89Q5hDsFv5O7AM6zb7By802O3bS7w0iAyi9K1MTt0nm7SM
         T7/mjBu2pJRx5yfqCkGniT84d+fsw4s95K6u5UCYAIhyrc73jQ0UZ5hpCYTv87Xgh53D
         8qIMuZ1cpq2i3mRSINk/r/J9CqaaGq+BP6nfaBqmjNfwUmAKvTsUe/NE3hy3ayeu0dn3
         nn4g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=4RjschYSe6Tf0uOIWySTQjkO16UVCv+lHsWiktEzXQU=;
        b=iYcpDqWINoGTONuthS2Rcfe4F75wEP4nKVlJcDD5vBoDmAvpsf86J08iVdsggBVxHU
         7CuvdCBSOie3jaD9Fr8fF58JpFHRTWP6RItJdZ86tKlFuZ6Jw/tzqLmJOHZoFKao3RZ9
         xZzOw9GTSV8yseSWfnb87xsaNqZRRWv0QIRV4chDm6oXiNxh5ChRRiiX3M43V4ASzGYo
         R+53VEtA3HUcrOAeTGoqZyYSPiImdtOQ1S13vBG1MkP+8sG7g2RzzQaGDjeppBhmvHVn
         7qMwiurJVbk71KG4fzANdpva4ikk1KqY01WHDiIe3f1KXlV4fyhKhuannEvi+iElUJQS
         9ojw==
X-Gm-Message-State: AOAM530L+9/g5GlchgUgc004c/VWZiiHvBhM9fu1+ARUsPMWY9HIophW
	FyxI23HBVIZsgo7DWxYZOag=
X-Google-Smtp-Source: ABdhPJxXjOySY8IzqsTz6JLETSw6nDJo8m8pVJArh9iX4XXfV4PV7MAguU+6kbhmw0vNOIJvK5QdjA==
X-Received: by 2002:a05:600c:b4e:b0:394:4551:113b with SMTP id k14-20020a05600c0b4e00b003944551113bmr6459886wmr.9.1651648192805;
        Wed, 04 May 2022 00:09:52 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6000:1567:b0:20c:5e04:8d9e with SMTP id
 7-20020a056000156700b0020c5e048d9els1562258wrz.1.gmail; Wed, 04 May 2022
 00:09:51 -0700 (PDT)
X-Received: by 2002:adf:ec51:0:b0:20a:cd42:fe3b with SMTP id w17-20020adfec51000000b0020acd42fe3bmr15262449wrn.719.1651648191320;
        Wed, 04 May 2022 00:09:51 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1651648191; cv=none;
        d=google.com; s=arc-20160816;
        b=SK/S0NBUCmO18G5KDeViHmTDcQMYsVCFu8eBhkg9M90q92lv6wV45yWFdQTkr97kot
         YVhx+B8S8O0qsK6e7CC3wgVYYp7kamnrhZQN610zbvXMT1oZdNe+1Qlk6F4M25r5Xy8E
         OFqWQIa76I9CjOf7gl8hz9XSk17nmOb1UTYvb8q5zZXPEt79230K1ULfBwcTBDPywKOg
         XFRd1cOIXB3oTXv8dnB3pcndhHdmYkVS2bLMw3aRFqCy+zYElCTs0IAJruuU1GbrI6TU
         QHK7RNCbWBIiFB9BVVE0pjeNDhmCcRH17J3N1nJY0vLLo2Zm+n+Wum3M+ZsYbpXS/YAA
         wlgA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=BHgM80QXnuHmX9P5lL3WDnID4JQ8ZgL0PARUx1Pn86E=;
        b=g8RO4Xj0K1RBKwjILnt0PWGC65CsoZln1AnQcCBjOSzg3tK1ENKqOKWdpKxaxr66rt
         b0hdnuAwQ3ftLYk/JSKSW07N0g86tctpKbthuWUOI/1bOYb0tgkKU3xh+kgaApcYiNg7
         IVinZbe76TeJsVn6rolUritZnYJPT3Q5scMqa8P1k8KSlb/akMBZ9fQ6fwnbqU4wiE/v
         AFFRQ82GOSUgW124E8uEWqQBjNdwUpHjv2w2uYi3AWqyvxX0D3d2TztnfEqz3WPqGOJ0
         SRhZflud8JEMg8rtDfzurEBMINNjx6YrFobfUGCxWwv38g9DgWFa5NuxJSMNsQaWU7V1
         iR9w==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=MPZFS7xd;
       spf=pass (google.com: domain of 3vizyygukce0taktgvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3viZyYgUKCe0TakTgVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ed1-x54a.google.com (mail-ed1-x54a.google.com. [2a00:1450:4864:20::54a])
        by gmr-mx.google.com with ESMTPS id m4-20020a5d64a4000000b0020c7b2af134si144886wrp.0.2022.05.04.00.09.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 May 2022 00:09:51 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3vizyygukce0taktgvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--elver.bounces.google.com designates 2a00:1450:4864:20::54a as permitted sender) client-ip=2a00:1450:4864:20::54a;
Received: by mail-ed1-x54a.google.com with SMTP id l24-20020a056402231800b00410f19a3103so331003eda.5
        for <kasan-dev@googlegroups.com>; Wed, 04 May 2022 00:09:51 -0700 (PDT)
X-Received: from elver.muc.corp.google.com ([2a00:79e0:15:13:83ae:6c38:682:3ca2])
 (user=elver job=sendgmr) by 2002:a17:907:3f1d:b0:6f4:ce49:52ea with SMTP id
 hq29-20020a1709073f1d00b006f4ce4952eamr492865ejc.47.1651648190858; Wed, 04
 May 2022 00:09:50 -0700 (PDT)
Date: Wed,  4 May 2022 09:09:41 +0200
Message-Id: <20220504070941.2798233-1-elver@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.36.0.464.gb9c8b46e94-goog
Subject: [PATCH -kselftest/kunit] kcsan: test: use new suite_{init,exit} support
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	Shuah Khan <skhan@linuxfoundation.org>, Daniel Latypov <dlatypov@google.com>, 
	David Gow <davidgow@google.com>, Brendan Higgins <brendanhiggins@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=MPZFS7xd;       spf=pass
 (google.com: domain of 3vizyygukce0taktgvddvat.rdbzphpc-stkvddvatvgdjeh.rdb@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::54a as permitted sender) smtp.mailfrom=3viZyYgUKCe0TakTgVddVaT.RdbZPhPc-STkVddVaTVgdjeh.Rdb@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Use the newly added suite_{init,exit} support for suite-wide init and
cleanup. This avoids the unsupported method by which the test used to do
suite-wide init and cleanup (avoiding issues such as missing TAP
headers, and possible future conflicts).

Signed-off-by: Marco Elver <elver@google.com>
---
This patch should go on the -kselftest/kunit branch, where this new
support currently lives, including a similar change to the KFENCE test.
---
 kernel/kcsan/kcsan_test.c | 31 +++++++++++++------------------
 1 file changed, 13 insertions(+), 18 deletions(-)

diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
index a36fca063a73..59560b5e1d9c 100644
--- a/kernel/kcsan/kcsan_test.c
+++ b/kernel/kcsan/kcsan_test.c
@@ -1565,14 +1565,6 @@ static void test_exit(struct kunit *test)
 	torture_cleanup_end();
 }
 
-static struct kunit_suite kcsan_test_suite = {
-	.name = "kcsan",
-	.test_cases = kcsan_test_cases,
-	.init = test_init,
-	.exit = test_exit,
-};
-static struct kunit_suite *kcsan_test_suites[] = { &kcsan_test_suite, NULL };
-
 __no_kcsan
 static void register_tracepoints(struct tracepoint *tp, void *ignore)
 {
@@ -1588,11 +1580,7 @@ static void unregister_tracepoints(struct tracepoint *tp, void *ignore)
 		tracepoint_probe_unregister(tp, probe_console, NULL);
 }
 
-/*
- * We only want to do tracepoints setup and teardown once, therefore we have to
- * customize the init and exit functions and cannot rely on kunit_test_suite().
- */
-static int __init kcsan_test_init(void)
+static int kcsan_suite_init(struct kunit_suite *suite)
 {
 	/*
 	 * Because we want to be able to build the test as a module, we need to
@@ -1600,18 +1588,25 @@ static int __init kcsan_test_init(void)
 	 * won't work here.
 	 */
 	for_each_kernel_tracepoint(register_tracepoints, NULL);
-	return __kunit_test_suites_init(kcsan_test_suites);
+	return 0;
 }
 
-static void kcsan_test_exit(void)
+static void kcsan_suite_exit(struct kunit_suite *suite)
 {
-	__kunit_test_suites_exit(kcsan_test_suites);
 	for_each_kernel_tracepoint(unregister_tracepoints, NULL);
 	tracepoint_synchronize_unregister();
 }
 
-late_initcall_sync(kcsan_test_init);
-module_exit(kcsan_test_exit);
+static struct kunit_suite kcsan_test_suite = {
+	.name = "kcsan",
+	.test_cases = kcsan_test_cases,
+	.init = test_init,
+	.exit = test_exit,
+	.suite_init = kcsan_suite_init,
+	.suite_exit = kcsan_suite_exit,
+};
+
+kunit_test_suites(&kcsan_test_suite);
 
 MODULE_LICENSE("GPL v2");
 MODULE_AUTHOR("Marco Elver <elver@google.com>");
-- 
2.36.0.464.gb9c8b46e94-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20220504070941.2798233-1-elver%40google.com.

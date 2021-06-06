Return-Path: <kasan-dev+bncBC6OLHHDVUOBBCF26CCQMGQEVTZCRXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1039.google.com (mail-pj1-x1039.google.com [IPv6:2607:f8b0:4864:20::1039])
	by mail.lfdr.de (Postfix) with ESMTPS id 94D2739CBF1
	for <lists+kasan-dev@lfdr.de>; Sun,  6 Jun 2021 02:55:37 +0200 (CEST)
Received: by mail-pj1-x1039.google.com with SMTP id j1-20020a17090a7381b02901605417540bsf8056811pjg.3
        for <lists+kasan-dev@lfdr.de>; Sat, 05 Jun 2021 17:55:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1622940936; cv=pass;
        d=google.com; s=arc-20160816;
        b=Yt1zAMBxqXLQqQfRKDc8Z9id7+kwamvvroN5QvDVr12W9D45+GHb/k5j3RW+S22/d7
         lJ64Ejh6xMTfRiZyXtNiANKR/e1fk/1TRvJAkmwGRVka0t37HpeQspRF/94qeUb3xwEI
         Bo5dS76NQ8bon967UNdNay4TT/WAgALLFRjknaey5By105IBfFOhCr5mgTTV51+1J78f
         SPIl2K2sPAtW4nR4YjbURHRPuKzFltckFg0XIakQaQV3i6V6Gu6RCPX5EAuXiFexw9Kd
         z8sB25GUL3B/VDhvlLdL7NmTuQ/5xgTDJiFjKuy8w66UdaXa2BEbUB8o2uZ+Jl0PU7WU
         tgBw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=0czmkXquWBPSirK3gcYxu3wCbgMgu2gu6Naw2TQoRxI=;
        b=YMJQd4MmyMjls6yUKqSIqsoOMhHG4ZsA5evvSA6VBJZrUs0re7LkXjO6tSWkT898fH
         Prbno4hXYFKBbRspmv+jV+I+VHGeascmX9jgn96tzy84sHTlwtMyQLA5O2lSTIQjFJ1X
         tLsImrAPd6Fpp6MtZkzz81q0lSfYtmwxdMbMZB37bsNSwoQPLYdRP/0T2ZerocnFoMMt
         niqidaie2NwDXvhXWdoZxO/xqZZ6sUl9npIzY9O7iKDxxe4q31dJVxnsn9LqLiitJr98
         yTYScCtiQHN6rCKBInu9nz8L8bur1+LVhUHjWeo52RDHTVCY9I+EiyUyieXmh9kbmW+s
         U9hQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=mB5L3xqa;
       spf=pass (google.com: domain of 3bh28yagkct0czuhcfnvfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3Bh28YAgKCT0cZuhcfnvfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=0czmkXquWBPSirK3gcYxu3wCbgMgu2gu6Naw2TQoRxI=;
        b=dzcRrzlrY3IwEFg0hI8vrbcVBAOqNzXDWV5OW//sGcQeMgZazPh+eIfnRQhOcf9gtf
         PgFEXycPxQf8IXZ4noTxs1QFXpxbH6BgwgBmGs13xntXdEaj2LXaYwSQfkjj/EDnFB70
         fowOUgMIZYZNw3L4FxSwAW2XpWlBHdRxZDrptGi27CtYQxMxywux1bNN38TB073+1X+y
         uMzl1Pf9dPLh7Yl1avcIr6N5ztd6GnxbxE+y5jWVK1tPXEcv6BxgUBxiWoRyLSw7Hc7n
         tcnkbxv0uZojOoCump/Uh3yk3L3oEx1N7gHScZzokpmaVZ8W1G8EQq0Q1QZrPP1snpAb
         XbUQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=0czmkXquWBPSirK3gcYxu3wCbgMgu2gu6Naw2TQoRxI=;
        b=OHxt5kQr+IbLDqK4h3DYbnSyEIDF6ZaMBQpB6OZhHMlvMziPPAUI4e3ahMidh2WWIW
         Y/OvQT8YmyaIILJx3hHFBPFyEAl1bV3lsQs7hp9gVseg8diGdYAT9+nr7tVhbchMCqX8
         jiTl5XjVfUwxoIzAxriFjTA1NYTFPNi4k7D2h6Zs2RWT6lc6e3cyTDv4Tn5JFG5NfNmi
         76Ra/J2VgkXIlFD2PvUZz3mD7LFcQODj55zwnLu6Hz6hW4nYHALFWFyj+bR//58MT+HT
         6BHVwL8uGxzc63Cp5rhqC7VE21MTI7OCwMlmab9rtyxbHF5XGLvyEa/0lNSQu1cfVFo8
         gr2Q==
X-Gm-Message-State: AOAM532/ZQ6W33TXk9ubscCy4j+QoKBdKYg+4Ike9Z50f1486n76BET1
	0PLIRE24fAig/8JrZsdwrL4=
X-Google-Smtp-Source: ABdhPJwt8ouaNBdv6tdapmW6J2MAMAHXpSHoRAHKqZx0Uwf+IG5jGlTOyXfqY3/BmSq4ss+QVHHyPg==
X-Received: by 2002:a17:902:8497:b029:103:b23b:f1c3 with SMTP id c23-20020a1709028497b0290103b23bf1c3mr11184671plo.34.1622940936133;
        Sat, 05 Jun 2021 17:55:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:3601:: with SMTP id d1ls677113pga.9.gmail; Sat, 05 Jun
 2021 17:55:35 -0700 (PDT)
X-Received: by 2002:a63:ee10:: with SMTP id e16mr11762519pgi.135.1622940935550;
        Sat, 05 Jun 2021 17:55:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1622940935; cv=none;
        d=google.com; s=arc-20160816;
        b=v7eMrara5QAbmYFSM9hDQQA4exPtjnYh4nGLCBo2hAOoF/MJh7Iv1L6iGJbOW8xnP1
         cqT6UvhW4xGRG7i9syIMPUPTc9HWAOHSm3WD6dTcYvy1j3xwakFuzYAmXHtGDtuBfUiq
         L6z7qnZ6FnU1zcq1xOuWt1qVo+IfGx878gTTRFG9ziXNoevY4D7mSCO+AAL1UgOtWsKT
         blJ54Nbm3QEBuuL6OwsFCtfR3o2Y8D9JweVJrYO5ZjRllAe6VzkwYJoNsUAD2UuPYdvC
         SoerTW8MnYreNItlZ7XLsm/F9Sjof4ZNzl2rQXmGxPihRXqxSU3QhZ0vXDBZRIiXvzaB
         HnHg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=GHvR3Cn1ebKCJGAQ/YKMJtoF4rLgzfIVburfhTYFub0=;
        b=jwErv7p4Wdt3BGpJbTTabhHgVGCwlTw8PMRl2OtgeLqGdEMZtRUdQb0cvcyLs5ML8g
         uzW6s/r44E9roraZ4hc9t7HeT/ZpDBQtIguBXwSE2WxfkfpChMtBKfpvTZ6NmNItob+x
         Vos6bafKVI1MYPQvfqD7WtfdyC4KASyJEIcK7nyovPwfuXkrnnJ0I+zaDWJY6sDr444H
         fKf+Bj3WEWWJsAMUKWhpBIe7EMaK+5UlGh6XnDDOd0C9pZTFgQ01rMoO296U3TJQ3fUj
         /Fv8jrOHgwW9aNXUetBcZEHnE3WO+v8QCYPWbA3EtZuAU8+sEz11cccRKIXHU3LTo0/u
         Cf8g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=mB5L3xqa;
       spf=pass (google.com: domain of 3bh28yagkct0czuhcfnvfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3Bh28YAgKCT0cZuhcfnvfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id b13si733001pgs.3.2021.06.05.17.55.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 05 Jun 2021 17:55:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3bh28yagkct0czuhcfnvfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id c9-20020a2580c90000b02904f86395a96dso17337862ybm.19
        for <kasan-dev@googlegroups.com>; Sat, 05 Jun 2021 17:55:35 -0700 (PDT)
X-Received: from spirogrip.svl.corp.google.com ([2620:15c:2cb:201:836b:eeb9:54f:d89a])
 (user=davidgow job=sendgmr) by 2002:a25:f20f:: with SMTP id
 i15mr14539079ybe.119.1622940934754; Sat, 05 Jun 2021 17:55:34 -0700 (PDT)
Date: Sat,  5 Jun 2021 17:55:30 -0700
Message-Id: <20210606005531.165954-1-davidgow@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.32.0.rc1.229.g3e70b5a671-goog
Subject: [PATCH v3] kasan: test: Improve failure message in KUNIT_EXPECT_KASAN_FAIL()
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Daniel Axtens <dja@axtens.net>, Brendan Higgins <brendanhiggins@google.com>
Cc: David Gow <davidgow@google.com>, kasan-dev@googlegroups.com, 
	kunit-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	Jonathan Corbet <corbet@lwn.net>, linux-doc@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=mB5L3xqa;       spf=pass
 (google.com: domain of 3bh28yagkct0czuhcfnvfnnfkd.bnljzrzm-cdufnnfkdfqntor.bnl@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3Bh28YAgKCT0cZuhcfnvfnnfkd.bnljZrZm-cdufnnfkdfqntor.bnl@flex--davidgow.bounces.google.com;
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

Also update the example failure in the documentation to reflect this.

Signed-off-by: David Gow <davidgow@google.com>
---

Changes since v2:
https://lkml.org/lkml/2021/6/4/1264
- Update the example error in the documentation

Changes since v1:
https://groups.google.com/g/kasan-dev/c/CbabdwoXGlE
- Remove fail_data.report_expected now that it's unused.
- Use '!' instead of '== false' in the comparison.
- Minor typo fixes in the commit message.

The test failure being used as an example is tracked in:
https://bugzilla.kernel.org/show_bug.cgi?id=213335



 Documentation/dev-tools/kasan.rst |  9 ++++-----
 include/linux/kasan.h             |  1 -
 lib/test_kasan.c                  | 11 +++++------
 3 files changed, 9 insertions(+), 12 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index d3f335ffc751..83ec4a556c19 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -447,11 +447,10 @@ When a test fails due to a failed ``kmalloc``::
 
 When a test fails due to a missing KASAN report::
 
-        # kmalloc_double_kzfree: EXPECTATION FAILED at lib/test_kasan.c:629
-        Expected kasan_data->report_expected == kasan_data->report_found, but
-        kasan_data->report_expected == 1
-        kasan_data->report_found == 0
-        not ok 28 - kmalloc_double_kzfree
+        # kmalloc_double_kzfree: EXPECTATION FAILED at lib/test_kasan.c:974
+        KASAN failure expected in "kfree_sensitive(ptr)", but none occurred
+        not ok 44 - kmalloc_double_kzfree
+
 
 At the end the cumulative status of all KASAN tests is printed. On success::
 
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210606005531.165954-1-davidgow%40google.com.

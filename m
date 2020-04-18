Return-Path: <kasan-dev+bncBC6OLHHDVUOBBIPD5H2AKGQEWZ7BAAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x237.google.com (mail-oi1-x237.google.com [IPv6:2607:f8b0:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 88CDE1AE992
	for <lists+kasan-dev@lfdr.de>; Sat, 18 Apr 2020 05:18:58 +0200 (CEST)
Received: by mail-oi1-x237.google.com with SMTP id b203sf3832175oii.3
        for <lists+kasan-dev@lfdr.de>; Fri, 17 Apr 2020 20:18:58 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1587179937; cv=pass;
        d=google.com; s=arc-20160816;
        b=0d+7SV5v3yvW5NXIoWjO9JKOzUMqAaYlVFMowmuHOodlPt7ME/CSGWCaGhvoeZwhsj
         wyGMheW3TM5qVyUjpfLTFFDMKCIeD+1onhONAKoMzxub+lOHZhcyLh4OAPnP2SoRA++l
         0akBpH2K00wIGUa1gn/UogVyL06IwKkcdtDzTwxojpjLlDyj0gO5Zb1aU6CDsZVhyKMS
         BSmb5caWXOa0xtUuTquAUcJyLsqDtyle6guMpbV+ENDRr3Gh0xeU2Ws8lhhsrKa9zbEa
         OsB5/QdJmq57cE9FneSitOrESMK6gbsugGqYxFbRkeGBW6aad5OCfcaxzsUltZFgU+ud
         gXTA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=5hOLVN+saMnety77WP5hx8U/Y7UyQVlQ16KSmJotU+c=;
        b=SqCL0jsylPFQF12p5oeBgl3SnolpboynxZearFMlcV0bpZ4IjbcWLhGW4I2Pg1Oo5E
         XdXcORJ5vR3SGJkVe7KhCg2tQqhEkLsGmZk9Ms2AcbDn74wpN2C+tmbBNsKRctGGQVe4
         JHXyvZzpQIuMD4YmygSh7FM9aA0/QEoZeXP7JVP2TIq/M47nsip8YXRjKeOwgn/2JTbb
         1yHqD7Zgn1rRouYRxveHjGb6njBj5tp9Y9tPdOEpoGwY/Fitrk2OZnEfTEmdeQzQqfy0
         yXyui4BAuor4T8P7ZnKTPylx1rM6NYiGNwkhKrvY/6Cid7icpKkE0DvcpuW5lzfJMK5s
         I3+w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="JS/kAYv0";
       spf=pass (google.com: domain of 3ohgaxggkcecmjermpxfpxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::549 as permitted sender) smtp.mailfrom=3oHGaXggKCecMJeRMPXfPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5hOLVN+saMnety77WP5hx8U/Y7UyQVlQ16KSmJotU+c=;
        b=hnE1zXn2cEp4zQqVC9MT01DGifFcwnMmrcX09sWXcKvPeC9SDAplWsCpD9HvZ7d5q8
         Fvc5GVHMoNGQTnPSRlKt8PjFpsc+ykRkRl6dJgKey49mEVtJq510tuan5uTs6ufoWVbn
         Cku00c3wmnon04G2YvfUqIVjG1zAnfXNT9lp5RzqIYsButQBwczzkZi8b7ogIotXJI3G
         w1kNbJUAC3daNgO/ugfjXav/WxPwWaLV66LkirjCJ5bkJI9JigvqC0xmWe8iYFQ/eieV
         6dm60wEYejXw/ugNxlIKW7JupkQd5e29YPMtP1VMFllLamnr6pM103sX+WSyhFKEkX/O
         28yw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5hOLVN+saMnety77WP5hx8U/Y7UyQVlQ16KSmJotU+c=;
        b=Lt+ohb54TDI/CbfXNluN+/skw+NlRzbPZiBzM8qqLxhgJtAK+BnAUWR7tv9oV9NRle
         8RTo3vb1e0WCneb9S2pg6ZiG0H/qK0in7Ll/r8atqUJXDJNuKbpFCf6TKLlQAKsuLKre
         YN2M2i+XjfiyARduLuTN5qo3rdMh9wZg89IqZ3jpjPLAe1aNYtSwPWnqiEWtHVQGtjcR
         qSK1XDUYfvBQmj8BIw52i+J7t5qc2V3GieeBbepLzO41fYvn+NcDR0JXfkOlsxPm9QQq
         saaq+E7Sfk9Lt8+kbdfy3aVdXv3yNZOccBde18AlqcHE7Wdz7hq/j3R2O+OKuxPi9xeE
         SenQ==
X-Gm-Message-State: AGi0PuYrXiVXKE+A+INdiNjOkWcNhHm9OHsf5aNVq2cKPUSzaFLHDTab
	6jrUTg4L0VqAHMDgDB2Gf6c=
X-Google-Smtp-Source: APiQypJWkUQ485G2JAkXKHVPYvMqc/vNT5onZKcBGJYK4ti+MgIdyuvpsh/OlWwaH+SU+z6tEK4d8A==
X-Received: by 2002:a05:6808:e:: with SMTP id u14mr4149254oic.50.1587179937487;
        Fri, 17 Apr 2020 20:18:57 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:c648:: with SMTP id w69ls1070824oif.7.gmail; Fri, 17 Apr
 2020 20:18:57 -0700 (PDT)
X-Received: by 2002:aca:5806:: with SMTP id m6mr641671oib.178.1587179937123;
        Fri, 17 Apr 2020 20:18:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1587179937; cv=none;
        d=google.com; s=arc-20160816;
        b=jMUhSGbHKDKNk/Pdmnm8jXE+GK0BJiUrBQ2chEQ4lfLDJgYf011LoNE+HzaNOp+5Ph
         RUFQI1RbuXCsqW/onqNtHgo2L1N+7aZChF2z/IUqbxIJf53Cy4ZUEQmZasPAWaD0Ay5k
         2W5AV40Epm1wh2tt/dykThVsyE0DSaGGF4cGPOxaga/ncYByOTmMyHm/2BJdyLau0NUN
         A/bGRpemJkB0wUVoYBwcFN61ZGADk1JJQM68EuUJIKDc4C9z0zxB3HwWKMWu6/HBaXoU
         O7sEZsv7FcgCyeYj5SKBbYKOtSxwHXtdCGyAXGoigzX7scnELrO3wo47DBukwblNfYkl
         LInw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=fsQ6zkM7uoUMiPnsVxSRYiwCGVhnWM0mTHH2Nkqj5zo=;
        b=jDk8tu0M0d6epPijWOctufN3BC1dGhq19MoKYzOPLikk6Nu6KQMt68luCbWOxXZEQ7
         Vq29qhq34iQZ4nk9tcuEwd8wt529OjElrnZqnFnoJXNl6kY6SnwP+dzi+PsISuWIXT4P
         Sbau8pA6LiPWRtdwJ6IWYo7/xkUG4Ai9WUAnj7p5HhfsD6UhKDQb4cpsC6oV2ljL03OC
         WvCshp1OWXqltzrhaYd9d0srjzCXccGrxrQ+0kcQGvuAUnpzBnMyablWSFnxErDvtoFw
         f6+WRqeo9sm6OdUjbwAYe7FPsIWbnIZQQYB3/rb6+D+oY1dFHVe3T448sOVxMXeGF88s
         UOZg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="JS/kAYv0";
       spf=pass (google.com: domain of 3ohgaxggkcecmjermpxfpxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::549 as permitted sender) smtp.mailfrom=3oHGaXggKCecMJeRMPXfPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x549.google.com (mail-pg1-x549.google.com. [2607:f8b0:4864:20::549])
        by gmr-mx.google.com with ESMTPS id o6si647505otk.5.2020.04.17.20.18.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 17 Apr 2020 20:18:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3ohgaxggkcecmjermpxfpxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::549 as permitted sender) client-ip=2607:f8b0:4864:20::549;
Received: by mail-pg1-x549.google.com with SMTP id 33so3530445pgx.17
        for <kasan-dev@googlegroups.com>; Fri, 17 Apr 2020 20:18:57 -0700 (PDT)
X-Received: by 2002:a17:90a:7486:: with SMTP id p6mr7991333pjk.62.1587179936368;
 Fri, 17 Apr 2020 20:18:56 -0700 (PDT)
Date: Fri, 17 Apr 2020 20:18:32 -0700
In-Reply-To: <20200418031833.234942-1-davidgow@google.com>
Message-Id: <20200418031833.234942-5-davidgow@google.com>
Mime-Version: 1.0
References: <20200418031833.234942-1-davidgow@google.com>
X-Mailer: git-send-email 2.26.1.301.g55bc3eb7cb9-goog
Subject: [PATCH v6 4/5] KASAN: Testing Documentation
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
To: trishalfonso@google.com, brendanhiggins@google.com, 
	aryabinin@virtuozzo.com, dvyukov@google.com, mingo@redhat.com, 
	peterz@infradead.org, juri.lelli@redhat.com, vincent.guittot@linaro.org
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	kunit-dev@googlegroups.com, linux-kselftest@vger.kernel.org, 
	David Gow <davidgow@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="JS/kAYv0";       spf=pass
 (google.com: domain of 3ohgaxggkcecmjermpxfpxxpun.lxvtjbjw-mnepxxpunpaxdyb.lxv@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::549 as permitted sender) smtp.mailfrom=3oHGaXggKCecMJeRMPXfPXXPUN.LXVTJbJW-MNePXXPUNPaXdYb.LXV@flex--davidgow.bounces.google.com;
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

From: Patricia Alfonso <trishalfonso@google.com>

Include documentation on how to test KASAN using CONFIG_TEST_KASAN and
CONFIG_TEST_KASAN_USER.

Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Signed-off-by: David Gow <davidgow@google.com>
---
 Documentation/dev-tools/kasan.rst | 70 +++++++++++++++++++++++++++++++
 1 file changed, 70 insertions(+)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index c652d740735d..74fa6aa0f0df 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -281,3 +281,73 @@ unmapped. This will require changes in arch-specific code.
 
 This allows ``VMAP_STACK`` support on x86, and can simplify support of
 architectures that do not have a fixed module region.
+
+CONFIG_TEST_KASAN_KUNIT & CONFIG_TEST_KASAN_MODULE
+--------------------------------------------------
+
+``CONFIG_TEST_KASAN_KUNIT`` utilizes the KUnit Test Framework for testing.
+This means each test focuses on a small unit of functionality and
+there are a few ways these tests can be run.
+
+Each test will print the KASAN report if an error is detected and then
+print the number of the test and the status of the test:
+
+pass::
+
+        ok 28 - kmalloc_double_kzfree
+or, if kmalloc failed::
+
+        # kmalloc_large_oob_right: ASSERTION FAILED at lib/test_kasan.c:163
+        Expected ptr is not null, but is
+        not ok 4 - kmalloc_large_oob_right
+or, if a KASAN report was expected, but not found::
+
+        # kmalloc_double_kzfree: EXPECTATION FAILED at lib/test_kasan.c:629
+        Expected kasan_data->report_expected == kasan_data->report_found, but
+        kasan_data->report_expected == 1
+        kasan_data->report_found == 0
+        not ok 28 - kmalloc_double_kzfree
+
+All test statuses are tracked as they run and an overall status will
+be printed at the end::
+
+        ok 1 - kasan_kunit_test
+
+or::
+
+        not ok 1 - kasan_kunit_test
+
+(1) Loadable Module
+~~~~~~~~~~~~~~~~~~~~
+
+With ``CONFIG_KUNIT`` enabled, ``CONFIG_TEST_KASAN_KUNIT`` can be built as
+a loadable module and run on any architecture that supports KASAN
+using something like insmod or modprobe.
+
+(2) Built-In
+~~~~~~~~~~~~~
+
+With ``CONFIG_KUNIT`` built-in, ``CONFIG_TEST_KASAN_KUNIT`` can be built-in
+on any architecure that supports KASAN. These and any other KUnit
+tests enabled will run and print the results at boot as a late-init
+call.
+
+(3) Using kunit_tool
+~~~~~~~~~~~~~~~~~~~~~
+
+With ``CONFIG_KUNIT`` and ``CONFIG_TEST_KASAN`` built-in, we can also
+use kunit_tool to see the results of these along with other KUnit
+tests in a more readable way. This will not print the KASAN reports
+of tests that passed. Use `KUnit documentation <https://www.kernel.org/doc/html/latest/dev-tools/kunit/index.html>`_ for more up-to-date
+information on kunit_tool.
+
+.. _KUnit: https://www.kernel.org/doc/html/latest/dev-tools/kunit/index.html
+
+``CONFIG_TEST_KASAN_MODULE`` is a set of KASAN tests that could not be
+converted to KUnit. These tests can be run only as a module with
+``CONFIG_TEST_KASAN_MODULE`` built as a loadable module and
+``CONFIG_KASAN`` built-in. The type of error expected and the
+function being run is printed before the expression expected to give
+an error. Then the error is printed, if found, and that test
+should be interpretted to pass only if the error was the one expected
+by the test.
-- 
2.26.1.301.g55bc3eb7cb9-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200418031833.234942-5-davidgow%40google.com.

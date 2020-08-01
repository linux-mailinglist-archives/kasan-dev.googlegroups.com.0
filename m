Return-Path: <kasan-dev+bncBC6OLHHDVUOBBVFKST4QKGQEWC6K7HY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73f.google.com (mail-qk1-x73f.google.com [IPv6:2607:f8b0:4864:20::73f])
	by mail.lfdr.de (Postfix) with ESMTPS id 3935E2350EE
	for <lists+kasan-dev@lfdr.de>; Sat,  1 Aug 2020 09:10:13 +0200 (CEST)
Received: by mail-qk1-x73f.google.com with SMTP id d131sf22454907qke.3
        for <lists+kasan-dev@lfdr.de>; Sat, 01 Aug 2020 00:10:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596265812; cv=pass;
        d=google.com; s=arc-20160816;
        b=EHkG0hgZrarxQ2sIJXdkBOT5qp1qvE9Bb1kqrbw8Pfic/LwH+yB8ZSAgg64XQIO3nQ
         raXlyDH8gpKbTZad2zJl1UY46zjGsnvkMb+8eT/t88VepkOsKwdVMBHt5Mq7hejSVQlF
         zUtkBTHIl99+lCtEbLSg6fi1EfIKdv2EzUU+jVCCh3HEGGheCzY/FsS3SFKW1zNhNME/
         RntRCWC9Gv4ZIe+4y+133ZiG7zDY2i2GTUfWnOjWAG8KqX9MaSXWc5xcv5yctfMRO9O4
         Hs1JCDsdXzPyfA+WpXtWqvsFjnbjlvBRDJioEYX6v6QRFZXELmaTE7YiGNv+HonjUIfg
         Ssuw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=z8iKxbL+UwOSYPcjc6i5hJB+cQqVKP/pn9Ig+zqB2tw=;
        b=qo5AhNcFFO0UUQWFH0zH4Y2nD66HA9fRqHvSiFF6rbQ1BgvYnm/MpfZoMhuDCNn+qC
         BBYyzDfIYIyX3rfOXBJo0QcMNjFWeUQJtpZ97eOK0gkaBtOn7fuFldon0RBOxuLkFA9H
         8zpbeoU8836K35z7M+V0PulL5LECwyJPqJLM5Gzkxhokpu1uy1E79SqM1Z/tDO2oo3Vm
         2kW+gPke7Pm6o6AuXkCpd5I7J/8zL9udV6a2o4q4pYx1uOUZLYGMO6yBOaTLe0t5Fn9m
         nA3EEgTZCz7dADcrE8XZwV4bUyyLnjMTadOpZZOrZ4YGj/qohRhbsj1lkkAF6cLDsQgQ
         7J+w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="V/FGzNDH";
       spf=pass (google.com: domain of 3uhulxwgkcreurczux5dx55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::44a as permitted sender) smtp.mailfrom=3UhUlXwgKCREurCzux5Dx55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=z8iKxbL+UwOSYPcjc6i5hJB+cQqVKP/pn9Ig+zqB2tw=;
        b=MsSVpmZU6vNBMMZkfJrauwRFDCKi9ZejHy4Z8bj7YTUgap9TB1bfv8JY5KO1ayQxSU
         VneN6jrzxB+wQ4QpZKpaEcVN8dfBKNyxQoLkAw/iao4CukSe6L8+h4iGs8+V5GFkcIU3
         4urAdfsVxtf7ld+c7dYsX5eebBEGCbbyjX6wbdKCht7JV280/JlR4FYg12EZmo1nYVJd
         Dg+Coi0VTUCJVvOg/+mxAWjjmMC9xIFh7guSitxaM3cpp5vhBelVDVjt2u09WQEzRia7
         mIrbouacucIm0tMUYU1uT/piILf1J1HnrFj/F6QYYBzm4wCL7wSQD/8LoP4nK4PmddLb
         VV2w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=z8iKxbL+UwOSYPcjc6i5hJB+cQqVKP/pn9Ig+zqB2tw=;
        b=c7oPFz5MCDW9DtH6N6qfl5zLyizSvX4jJMW0+Lhe5FnC4Trks1OSCS/0V1+7ol3Ntf
         Dj/z4PgKi9tpBW8ZTuEqDlmBQYiT+BONwbRBqLQcSpSw/d7YSqouMjxC+fhAMxpBiARP
         0YKFZ4hM5gYeI7GH4Zr3KXfkpktAFMOKZClGcMEzXZTItzisG7y7kqBwXZh6LbmxC+NW
         RJSC7ZjsvJl9NVGkrW/wR+JAzTTcfRpB/U9SYaxlRwobKrbnO3+CaTRn8bjTwEor2QZA
         zs09cPsnGW/jyILbTTn5Jo0YZtfEiTsAK4PyN/tUC7ba2Gf35a6bCEhAKFVF/RC1zIiJ
         vMCQ==
X-Gm-Message-State: AOAM533gXUc90FvmUJKf8GSStfxZO6jVCqEu/+crG1zOzeSDOX56V71n
	OMUdTN5Z9ZxLcnec+92Y0gw=
X-Google-Smtp-Source: ABdhPJwjAMjszE1P5jqvjGPCEYMxZpentRXQehk0uwDipsk8p4gyhLaXZBUohq1As2mZgmCvDqmRAg==
X-Received: by 2002:ac8:7751:: with SMTP id g17mr7545174qtu.392.1596265812118;
        Sat, 01 Aug 2020 00:10:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:c38d:: with SMTP id o13ls1608085qvi.5.gmail; Sat, 01 Aug
 2020 00:10:11 -0700 (PDT)
X-Received: by 2002:a0c:9b85:: with SMTP id o5mr7640840qve.11.1596265811771;
        Sat, 01 Aug 2020 00:10:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596265811; cv=none;
        d=google.com; s=arc-20160816;
        b=p/C9x7B/lInUY7gGtFJ1i+RuHBmJoZavh4ZubXv0sts3k/vXzFnGn+HPBtzJ9dMBzi
         Q+pJVNkU2Zyh/in4N1C4hmVoiRnQGRHJhhURuDZ+ZfaIemTK9MF3m9Lp7vyZsWdm0TfF
         Ex2daU0tKn0hYn/aHXq4AWOKp8wUY/tXOHz7DMhiCNYO5dYUsFHhPtQl1qkanPqCx4nZ
         UcmR+ey+e5xhx8VbcIMYJZTmls3WHX16RVBiLMpAvMcZu0MzZzL6ewv2jgmN5bVw5vJQ
         MItbCSzcN2HoaETPGWQ/qgLaX/tOUTq5ChXrhNzphQYaMpQQigH5ixCe4XcHtZf4Xoh8
         tAig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=nr8mXyqoppq75z/FRAmv2PARhpMnaUiNjcYddLk+74Y=;
        b=C+XxVJ79ZqE1+XwNGlnTB85sjWx33DK4UVdW1hSLiNa7UrlKvAQpT6yemjZCHZrHgw
         a6sEKM5mWMSeNWYxxPe+DSVPP8yyTOTCaCt7AZWcrg8p/b/xC8BUBRxPJQ6U48QCj9uv
         GgFK8S6rmOZDsUVS+w8rTizO/3g/FFbtIX4+2sToRtoADNdnzJvC0MSVRPafsrsyHxnT
         7RQEFYzE4OPkmBbV5Ql230XnsO6TrTucBloaaJMpYoBHwwuyFxJ03g+pqt+roLA/Bziv
         CP4jwc/bRudM69H9BjQqHbDr+WQn+b8tMmL/RdCEjgsDCZzIXHSaxdWtYGs/SM9myfEL
         1JbA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="V/FGzNDH";
       spf=pass (google.com: domain of 3uhulxwgkcreurczux5dx55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::44a as permitted sender) smtp.mailfrom=3UhUlXwgKCREurCzux5Dx55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pf1-x44a.google.com (mail-pf1-x44a.google.com. [2607:f8b0:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id f38si543646qte.4.2020.08.01.00.10.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 01 Aug 2020 00:10:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3uhulxwgkcreurczux5dx55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::44a as permitted sender) client-ip=2607:f8b0:4864:20::44a;
Received: by mail-pf1-x44a.google.com with SMTP id y20so9027058pfr.1
        for <kasan-dev@googlegroups.com>; Sat, 01 Aug 2020 00:10:11 -0700 (PDT)
X-Received: by 2002:a17:90a:1fcb:: with SMTP id z11mr1131477pjz.1.1596265810438;
 Sat, 01 Aug 2020 00:10:10 -0700 (PDT)
Date: Sat,  1 Aug 2020 00:09:23 -0700
In-Reply-To: <20200801070924.1786166-1-davidgow@google.com>
Message-Id: <20200801070924.1786166-5-davidgow@google.com>
Mime-Version: 1.0
References: <20200801070924.1786166-1-davidgow@google.com>
X-Mailer: git-send-email 2.28.0.163.g6104cc2f0b6-goog
Subject: [PATCH v10 4/5] KASAN: Testing Documentation
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
To: trishalfonso@google.com, brendanhiggins@google.com, 
	aryabinin@virtuozzo.com, dvyukov@google.com, mingo@redhat.com, 
	peterz@infradead.org, juri.lelli@redhat.com, vincent.guittot@linaro.org, 
	andreyknvl@google.com, shuah@kernel.org
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	kunit-dev@googlegroups.com, linux-kselftest@vger.kernel.org, 
	David Gow <davidgow@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b="V/FGzNDH";       spf=pass
 (google.com: domain of 3uhulxwgkcreurczux5dx55x2v.t531r9r4-uvcx55x2vx85b69.t53@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::44a as permitted sender) smtp.mailfrom=3UhUlXwgKCREurCzux5Dx55x2v.t531r9r4-uvCx55x2vx85B69.t53@flex--davidgow.bounces.google.com;
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

Include documentation on how to test KASAN using CONFIG_TEST_KASAN_KUNIT
and CONFIG_TEST_KASAN_MODULE.

Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
Signed-off-by: David Gow <davidgow@google.com>
Reviewed-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Acked-by: Brendan Higgins <brendanhiggins@google.com>
---
 Documentation/dev-tools/kasan.rst | 70 +++++++++++++++++++++++++++++++
 1 file changed, 70 insertions(+)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index 38fd5681fade..42991e40cbe1 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -281,3 +281,73 @@ unmapped. This will require changes in arch-specific code.
 
 This allows ``VMAP_STACK`` support on x86, and can simplify support of
 architectures that do not have a fixed module region.
+
+CONFIG_KASAN_KUNIT_TEST & CONFIG_TEST_KASAN_MODULE
+--------------------------------------------------
+
+``CONFIG_KASAN_KUNIT_TEST`` utilizes the KUnit Test Framework for testing.
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
+With ``CONFIG_KUNIT`` enabled, ``CONFIG_KASAN_KUNIT_TEST`` can be built as
+a loadable module and run on any architecture that supports KASAN
+using something like insmod or modprobe.
+
+(2) Built-In
+~~~~~~~~~~~~~
+
+With ``CONFIG_KUNIT`` built-in, ``CONFIG_KASAN_KUNIT_TEST`` can be built-in
+on any architecure that supports KASAN. These and any other KUnit
+tests enabled will run and print the results at boot as a late-init
+call.
+
+(3) Using kunit_tool
+~~~~~~~~~~~~~~~~~~~~~
+
+With ``CONFIG_KUNIT`` and ``CONFIG_KASAN_KUNIT_TEST`` built-in, we can also
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
2.28.0.163.g6104cc2f0b6-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200801070924.1786166-5-davidgow%40google.com.

Return-Path: <kasan-dev+bncBC6OLHHDVUOBBLMHRL2QKGQEVZGRHHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3f.google.com (mail-oo1-xc3f.google.com [IPv6:2607:f8b0:4864:20::c3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 048561B6DDA
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Apr 2020 08:14:07 +0200 (CEST)
Received: by mail-oo1-xc3f.google.com with SMTP id h9sf6232650oot.19
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Apr 2020 23:14:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1587708846; cv=pass;
        d=google.com; s=arc-20160816;
        b=IynfWz5dYo6lUwXflGcfsbuToAspTwbQAhvTGTbj9QwMEUikiWl5mY77/sP4R5VarA
         BTX9TGoFi1Zx3AMk51JpmuAgWWcDnJDalbdhFxKEWsJAq4xun3i6anTvSvwtqKMjX+Xn
         kg0f4s3f4zitsw0WTMzzsTCzEiSPwtEUIgaDdMe2SL91WXfu6j0LdnkZjGTuy81o4JiQ
         sHo8vTLfFLMNUZkd8fMXje2E5XhoO6KgLEHHCdp5kVH2G7vP3/f8qOuVXpqcIaw/5iq5
         wRMCVCwZd2iYC298x2EYs/zkfRP05Hsgvf/2a6JsuFIQf8AZQLA33ABR035Zq1nIue9H
         3OLA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=r0souQA5PXPD0Usl0j/bMs1XS//pfpkP93hy0tho3Rs=;
        b=fy5GAimXl1hhDBj/hS6hIIzc6VQArBC2zMS1QwEzpeG9IQyVzFlutMIezeLznmsBQN
         xplhlqeN84YBUjOPCe7wM+xHhOFIwllnob+gHhWSNFMYuiV5/Hlaw4KOOoIN2IkrAXTM
         P1C3cLbVW6n1GKyoruOGllXe1GP2ftTOVMxoS9tzeu091kXjNnWIVgQmp8AqnJQl6RXz
         lT1X8UEj0b48thgdaeeZrA0863hIVgqvGQqVhbVAgAMj1wH0fMblSMSWnuTEt4hsFl1u
         tQ8S5+5WxPSDcZUzsFWFDjSj/9V9sahDMk9L1PmaodH9Xyw+VIEGehiAZH4gcgbf2/Et
         Jjyw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ulwvVvdq;
       spf=pass (google.com: domain of 3rioixggkctkyvqdybjrbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3rIOiXggKCTkYVqdYbjrbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=r0souQA5PXPD0Usl0j/bMs1XS//pfpkP93hy0tho3Rs=;
        b=q903d+2GOLqpK2vpcNyd2ttLKQup7H97MZRZ2n7uF9TA6caUdZmrQr43hXx5BLMI8C
         2iDydK0Hz353HCd2WRXtQDq0/prz50VG0Gp6ftLkXL4TTfL4ubUNj9wvTwQdbBadzElr
         dMgt1RynJwMz+GdluULj7TH9OnQKcsCzewbGSlET4Bu31bb4Sb6TtZoRXZ7M72eXhRYQ
         ULx0klonqf0IXTeWOxaq9K9kZrbV9TE2HSySkqawROfYtkyjCVHjBA3pr0XOdKlD92vB
         sHE2ha6N/V2yWO7rLlQjBUEajnroRuuywu+wHCbwqGq41hh7ehGPXz3A/GFcgUr3r5yC
         v3TQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=r0souQA5PXPD0Usl0j/bMs1XS//pfpkP93hy0tho3Rs=;
        b=CxYFXsSP/t83dMD9Q18fshLnVox802YjiQK098wC3HOBqK7kZTovYkwHbdrNoHpz3h
         ZZtiLJ3HWBViTHDvE073VYsM7iBdQ2/oDyM35d+HlZajzXgciYVgu4GmJVs501vpd7LV
         rac/PRKJ4Ez6jAG9G8NbsOaMlTh2+SAkWJO5vI387eT0bq2SJXTXkKz+RjKS7cT/K/EH
         qtoTYVKxbOT6mmb3G1fzqWvP4ZoTPobX0wrnBpemlXBJRisvtOZyMLfODLWfR8NW8weq
         CuHPi+j+ND8DADg94h/LU58LAiDNjny1NnqiRRbLevFKutXGPe9fEAQ+68Fc9u/yt9Mg
         X1YQ==
X-Gm-Message-State: AGi0PubUZiiT5NaHB09N4o8FOlu6uku3VQe95As3e2sLuQdqjmazB9Os
	DgQKRhVt5NM8EtZLbDnIF9A=
X-Google-Smtp-Source: APiQypJdGcd2SPggWlKQ/kPhpYzezF08IvzrQxSqDdIjlJdfjhfy+Gi3v7OiuVm9pzmeg9KXoJ1+BA==
X-Received: by 2002:aca:6508:: with SMTP id m8mr6017763oim.54.1587708845955;
        Thu, 23 Apr 2020 23:14:05 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:363:: with SMTP id 90ls2022269otv.6.gmail; Thu, 23 Apr
 2020 23:14:05 -0700 (PDT)
X-Received: by 2002:a9d:805:: with SMTP id 5mr6651539oty.111.1587708845554;
        Thu, 23 Apr 2020 23:14:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1587708845; cv=none;
        d=google.com; s=arc-20160816;
        b=VcSC9eMAuwVSkinCuyeIR6P58PpW16WdzXjHY667Q/sqxbZN7HHfYkf5xSqwAaxHAN
         5LBOXr3U+FX+XeJxxj3hZkFrxBqeL/8w+qmJ70KpbQXpRJtlRpVQWxG3aZmR/NHie3j9
         0Dn9+Bhrp5bnsHkisb6WXiiqUAPGe2d5+djs5G5PDWRSfEhl+KiqyXN3vbyRoh63gltA
         /8oIudEgG2IPjcjyThJCljTp4DGhyQ+YNQc0hhq/lbCTXjzOXzxkNaJ+Y8aeREATus81
         PATNYW3LTWe52DR0fM9EEiWS+G7fbf/PXsp4XpJyyfJPFI7nhIZbeRslsBgJ2GRV45Cc
         Uaog==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=5epptiP6vyK9ksah1mqKRXgiRHBz5N7tvZFE7or+VcA=;
        b=xskuRVH6lDnX34/54RPji/qEkgJkM2HMEoiI/kXNjK/DQhFY6513wCg3dtjf6UymKN
         B/Pqqmo3o1MU+Ul92E74BIqA+8vq8it712FPyiqwxqJr1LPiUPVGQCka3don7r+icvIO
         V+DKE53/v5X7kOgzaPsjgL7s0k3iVk9bsOATU5R/6xcZ42XQPGquKB0UbU0EqIKpW0Vm
         tofJzxDxbZBltmsRXBXNJdTr/CwtfmdLC4krUTTSbVbsc+1CARmwet+UnNZYp5O9KQNM
         YCZ2b9ZW013na9oywc/sF9yBKL8N+5+LkYX6hqlp5Y6IesrQnxfnfVOhj+xIXIejvWIK
         wl3Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ulwvVvdq;
       spf=pass (google.com: domain of 3rioixggkctkyvqdybjrbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3rIOiXggKCTkYVqdYbjrbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb49.google.com (mail-yb1-xb49.google.com. [2607:f8b0:4864:20::b49])
        by gmr-mx.google.com with ESMTPS id q18si425033otg.4.2020.04.23.23.14.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 23 Apr 2020 23:14:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3rioixggkctkyvqdybjrbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b49 as permitted sender) client-ip=2607:f8b0:4864:20::b49;
Received: by mail-yb1-xb49.google.com with SMTP id v14so8884906ybs.20
        for <kasan-dev@googlegroups.com>; Thu, 23 Apr 2020 23:14:05 -0700 (PDT)
X-Received: by 2002:a25:bd4c:: with SMTP id p12mr13287597ybm.140.1587708844982;
 Thu, 23 Apr 2020 23:14:04 -0700 (PDT)
Date: Thu, 23 Apr 2020 23:13:41 -0700
In-Reply-To: <20200424061342.212535-1-davidgow@google.com>
Message-Id: <20200424061342.212535-5-davidgow@google.com>
Mime-Version: 1.0
References: <20200424061342.212535-1-davidgow@google.com>
X-Mailer: git-send-email 2.26.2.303.gf8c07b1a785-goog
Subject: [PATCH v7 4/5] KASAN: Testing Documentation
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
 header.i=@google.com header.s=20161025 header.b=ulwvVvdq;       spf=pass
 (google.com: domain of 3rioixggkctkyvqdybjrbjjbgz.xjhfvnvi-yzqbjjbgzbmjpkn.xjh@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::b49 as permitted sender) smtp.mailfrom=3rIOiXggKCTkYVqdYbjrbjjbgZ.XjhfVnVi-YZqbjjbgZbmjpkn.Xjh@flex--davidgow.bounces.google.com;
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
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
Signed-off-by: David Gow <davidgow@google.com>
---
 Documentation/dev-tools/kasan.rst | 70 +++++++++++++++++++++++++++++++
 1 file changed, 70 insertions(+)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index c652d740735d..b4b109d88f9e 100644
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
+With ``CONFIG_KUNIT`` and ``CONFIG_TEST_KASAN_KUNIT`` built-in, we can also
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
2.26.2.303.gf8c07b1a785-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200424061342.212535-5-davidgow%40google.com.

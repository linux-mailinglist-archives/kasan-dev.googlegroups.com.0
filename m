Return-Path: <kasan-dev+bncBC6OLHHDVUOBBRXLVD4QKGQEGWGTY6Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id E012E23C497
	for <lists+kasan-dev@lfdr.de>; Wed,  5 Aug 2020 06:29:59 +0200 (CEST)
Received: by mail-pl1-x637.google.com with SMTP id p14sf31595534plq.19
        for <lists+kasan-dev@lfdr.de>; Tue, 04 Aug 2020 21:29:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596601798; cv=pass;
        d=google.com; s=arc-20160816;
        b=NTQsgXo3Dw/YnIWX8eYWAB01tjJUcamlcyLYs4r5FgZDCCWOhy1HLwIw4xe+xy/GIA
         H64prYvlB5o6CQeFbxvWXxRary22zrqsUS1fefn+0c4bxrxbDDgQ15GBiFhkTXzbi4Xl
         8SIUTqRiWMCozk2bvyx5JkK12jzCygKJ2Yx2DG47cRs8CSK92kzaxd33+eZbtMusYNVe
         4J+y8MQoKrL87YbgQZVqrwhBxjv45ZfNgBYMVrNGi6faO7s+SDmfFLfleAXS3qm3J2IU
         rXPngcnpJczg0Ov6cNQiH/pZv0VotsWzNVPXD/QRwCGpvZxBhFhYnO+azvaXPUPhZfok
         z1MA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=AWJH9++vAJU4X0m7LXOSOThZU8ykoEMaLwbFruDneAs=;
        b=C/Wl1njFVESU6ezCoXbSYURFYMsccbb3ulKU4AFLAByplf8Mk/7IqDcQx45tRkXpD7
         2pFar64t5ik/1tJoK4JW/g48LwGbs0Zz0hyMUPYFN3Aum8oKCxVa1B6FjR7QVIkLiFQt
         Y6a7/VEXgvnDBWwgaK3dOsGZ8oSobKpL3djc7nTa5WzacoZwzyCsCoNC2dTy0LV0Y8zJ
         0fCV0KuhBA9q9tqmcF7DLDKOdz0pbrUERIti9lgoFfvVEkUSMMtalOMfhnn4XGzjaGFz
         QGUz8GlM0OI5bsRHHlrdUJrJXeeZMWzkKlv/ndPLaDV6rxtlhVvX655V9RNcOqexcSQM
         1PlA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TBGXVFSW;
       spf=pass (google.com: domain of 3xduqxwgkcdc63ob69hp9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3xDUqXwgKCdc63OB69HP9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AWJH9++vAJU4X0m7LXOSOThZU8ykoEMaLwbFruDneAs=;
        b=oRm4SjBcJWUlKeNNqjePuMWT5u57iBHS93TKRIPzN1G1RF3skZPYaQpe5XtMGr4CXn
         kATDGG4dQedC3zjy4XrhE20UrqHBBeyf2Q5CClE5wnOB2Cfp9zgi20KAJpl+l6rI+n5s
         qoN1tINt2N/ft98iDPvr1WrLkL0bQg0qot1HN2c5FNU6xIWoizNhcTjwoz8deHwxlE1/
         gZZ0NwcAftighKLd9Oo6ZekEulvhs6LSetORCn7S/W9OTEwcln7Pnnd81Zdbtjw6gt4o
         le2Vgn3nbQtLNdecZFSp1UFeGDeA/c5dBaYJRraBEc7mh8EhqcsojEW+Bhnd9v1GTSpf
         TW/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AWJH9++vAJU4X0m7LXOSOThZU8ykoEMaLwbFruDneAs=;
        b=PephV4FVgcn/vohIhuDSSwnae6Z6Frp8wjLOHOZJimLxs2M0xqMxf6GhGwMgVkPaf3
         nDZU3SmyQaDzm9qWmv1akahuPPy0u7oH3CfNAdFxwIikeIJSEqvX1ZFEIkchnvxBxIej
         7wGKPtOnhsjlQu1Q7TJIvhLVk9FlmhnB77YagqWr8SLUUkFl1K4J8ns3TNzlqL0IGo0z
         6VyWD3Q3o3AEwpShlHWKoCHul3v/RfjbvAbgwx06iBJLFjJ+8vl8FzfYLisLHFdsS2Xp
         SFkHvtfaIro1MdV/b1z0fcMLbIJKQlTN+ivRo4Si8JLBgkhACuWBe6BtCvSP81PFpPoG
         C8Fg==
X-Gm-Message-State: AOAM530H3KD3aU+vToVdof6oDZEHuQZDjCmPyr4Oa8NP7irUIGr1aU92
	uMegs1WtKARsqFtisgCyG1Y=
X-Google-Smtp-Source: ABdhPJy0odQi7auX73PQWAsJk5VxzFIxTg7RnYYTKQillyJxi8/V1slv/K/2TatGjg33cO3k+nIdaA==
X-Received: by 2002:aa7:854f:: with SMTP id y15mr1554802pfn.298.1596601798286;
        Tue, 04 Aug 2020 21:29:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:9a4c:: with SMTP id x12ls504513plv.7.gmail; Tue, 04
 Aug 2020 21:29:57 -0700 (PDT)
X-Received: by 2002:a17:902:eb14:: with SMTP id l20mr1436254plb.6.1596601797819;
        Tue, 04 Aug 2020 21:29:57 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596601797; cv=none;
        d=google.com; s=arc-20160816;
        b=TsxoqyUp8Dd2epvjsQ/PQEJ86equEGiIBWEc7KpOzsVpnZ9+zZaRMYZU/u6+JPXTXf
         V1mNYS6Mb8WkZP4F/DYBv6cB4ijXQZQc3x5jWl/KmYtDCRPx8U8infE1v7JB7J5p1gh6
         Z1WIpNjqtJ7vFtid/QtwgoW8uEcGNdJfkmUM8Sy4f5eX613Fzp5Ti1fJjP40HXGzJlrI
         IAKkFXLHZaKPjRx2DA2hxWKHzk9RUj/VaH681XHj7iBgZRNxqUJQoqeVc9blNTmUePOv
         Seao2vtTbweZt0zJ5st8K+4+OKrwJUBFFCEIPaJ4l1lZW4UO2DSzm6Gy8Mrv8zGpFWB0
         Wy2w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=nr8mXyqoppq75z/FRAmv2PARhpMnaUiNjcYddLk+74Y=;
        b=aoKOa+0ccbbgL7eAZm8lRQe2s9nysevVvbP0bZIgnnuPE2scOUZiJjkvAtJLmMNwY5
         DOJf2hyoDdfyAxmxT2rLOIEahHhyfQ71LtRD0WiU3TANjW1qKm3aapFWmEYJ4Bi+/NbC
         B92MTSgMG0DP+lMCQ0Ad4gKlPfgVjurC2HSxVYgl6oIPtNBMie0o2+p+m9Hm4s2y/pxU
         VxdHfa5RGhlujL5JOpyNRUtnxrlMsUrjQ3yp6ruswqCHZu4L+TZnA0FKvWvqeUZPQu+2
         oUJj33gYtPCO5furdTfR850W7B3iwvHJ7AhuX/4Hd0RkCVAm5y8W4fOqClAhsmGp8ILE
         Fzgg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=TBGXVFSW;
       spf=pass (google.com: domain of 3xduqxwgkcdc63ob69hp9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3xDUqXwgKCdc63OB69HP9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x84a.google.com (mail-qt1-x84a.google.com. [2607:f8b0:4864:20::84a])
        by gmr-mx.google.com with ESMTPS id i3si308076pjx.2.2020.08.04.21.29.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 04 Aug 2020 21:29:57 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3xduqxwgkcdc63ob69hp9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::84a as permitted sender) client-ip=2607:f8b0:4864:20::84a;
Received: by mail-qt1-x84a.google.com with SMTP id z5so14574976qtc.2
        for <kasan-dev@googlegroups.com>; Tue, 04 Aug 2020 21:29:57 -0700 (PDT)
X-Received: by 2002:ad4:4152:: with SMTP id z18mr1839378qvp.42.1596601796941;
 Tue, 04 Aug 2020 21:29:56 -0700 (PDT)
Date: Tue,  4 Aug 2020 21:29:37 -0700
In-Reply-To: <20200805042938.2961494-1-davidgow@google.com>
Message-Id: <20200805042938.2961494-6-davidgow@google.com>
Mime-Version: 1.0
References: <20200805042938.2961494-1-davidgow@google.com>
X-Mailer: git-send-email 2.28.0.163.g6104cc2f0b6-goog
Subject: [PATCH v11 5/6] KASAN: Testing Documentation
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
To: trishalfonso@google.com, brendanhiggins@google.com, 
	aryabinin@virtuozzo.com, dvyukov@google.com, mingo@redhat.com, 
	peterz@infradead.org, juri.lelli@redhat.com, vincent.guittot@linaro.org, 
	andreyknvl@google.com, shuah@kernel.org, akpm@linux-foundation.org
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	kunit-dev@googlegroups.com, linux-kselftest@vger.kernel.org, 
	linux-mm@kvack.org, David Gow <davidgow@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=TBGXVFSW;       spf=pass
 (google.com: domain of 3xduqxwgkcdc63ob69hp9hh9e7.5hfd3l3g-67o9hh9e79khnil.5hf@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::84a as permitted sender) smtp.mailfrom=3xDUqXwgKCdc63OB69HP9HH9E7.5HFD3L3G-67O9HH9E79KHNIL.5HF@flex--davidgow.bounces.google.com;
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200805042938.2961494-6-davidgow%40google.com.

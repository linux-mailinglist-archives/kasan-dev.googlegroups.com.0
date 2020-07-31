Return-Path: <kasan-dev+bncBC6OLHHDVUOBBXOCR34QKGQEBIIHPPI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63f.google.com (mail-pl1-x63f.google.com [IPv6:2607:f8b0:4864:20::63f])
	by mail.lfdr.de (Postfix) with ESMTPS id A4B52233E68
	for <lists+kasan-dev@lfdr.de>; Fri, 31 Jul 2020 06:43:10 +0200 (CEST)
Received: by mail-pl1-x63f.google.com with SMTP id p14sf20574227plq.19
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Jul 2020 21:43:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596170589; cv=pass;
        d=google.com; s=arc-20160816;
        b=a79vEn5dqBLNamwLkHOzImxu+oU0KFh2A3YEuvSSUsGW9qYrqPvwYiDlUiwdU94paK
         0/lVCqHPYOPn0RxO3udRyq0Lacx6Z5wb7btTlspPG+NztsoJItiqM4/AEn0k7ZUghRfV
         lMqj1hXf0l03L7vFZ3ivi/96hyLnBawfSobkOJxoQMFrO5BQQIkLmsr2uSH0un3OYECG
         IMS0fX70fSR7B3boDfu5ka+OFXod1YmmxXXRmsPwI4WK0iLwBxKvrnRLosip+vRgLmpS
         xL7tXJZF7lKfjhTNmYWF7OnLf1XrtqO6cAKiK3D1cec4lpmTveZCQalB1DdX/uGVQzSg
         Lw6Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=YPmAbPbyC7Sd1wIlqX4hSgL2B316aq/V6B2p+BR8tdg=;
        b=RWDrQyOe9ixUBHJZDbGSAOiT+XkHfA+3e3ykBN34Yj0vpcP+el56tu/S8dQQxCL/dg
         MHZyCUDVReMoe9rtzLuW7wtWrOrxlTxCv4+wG+6jp5muXq7OPBfOcQ3optvPT2TmLiec
         L6qyYU/dMaOcqwzoZZ8jLF2PWcj8XVeWJReYJPS/3/snAh9K4m48HV8JXYRghMry//TG
         IgDBvAleh229egGYz5iMFVXBN+/7a/h8q6aSaPXNxwitEK9dR6UVK2JZTxHI7C2Evb+Y
         rYBttZX76t+0BA2crMWjnYszXgcUPlNvBGsEBiVyQ38HzOfsvVU5vf9GIKNNbpNoGP7Q
         h8hQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PzMkVTq1;
       spf=pass (google.com: domain of 3w6ejxwgkcswlidqloweowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3W6EjXwgKCSwLIdQLOWeOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YPmAbPbyC7Sd1wIlqX4hSgL2B316aq/V6B2p+BR8tdg=;
        b=W5QE6TVPuqkihFBETqEze5Rh2iZ3z8YvN2yTJueU+wk/J6cme1KJM50+EArNftzcLa
         r8fCmyzscDSO9dNcQNlxqGe1Rb6mjlviwUD1fdM9k06uNBxbNMJ2JngLj7y/M2KnlIUk
         YQ18ccqG2Y/+DtJOZMrePj3xpd10g+EanpvVRw/VA44nEd+E55JUxoz+ViwPr+eGSMfx
         cmdsmFZKEe4aEP34e2a3xAOHLT7kcOmfsb6E59HU3i4nmy4tXgyzgw3vO2fmA3LR97ZW
         dsZr6wlYlVfOlrbmI9Ytwhw3Pg08c2maWevcVb+rlqcDUlXOBIZc9fT68nfBEjsG+mH9
         wWew==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=YPmAbPbyC7Sd1wIlqX4hSgL2B316aq/V6B2p+BR8tdg=;
        b=WJpzDqNrS8SnLnb/RvE1d10LeJnpG77VGutdOwGZJQJTrur9sHCS7kdpkr95HIdiOW
         slrexdsT1MDPWh9w2JxZhTDZH4i2Nuavd8yYYMg6VNcNzycKuTtfPQdm8HZLXwa6rAuG
         t6SrZi0CRSys0SLyUzAgCcxErcUkiOd7q8TlzUzap1G4SkqW5v5L9maf9y9Z2fC758uq
         c9nE9GRalfspqJzyG1ufV9fQYs7shnD8+6q1sFQ0cqrQdzfIb7texediNem5RzjeWzNQ
         71QEMuGr3uHv43pSb3hxlwoEpDfsKd2nFrZBjBi5JbkP4wGlycZsn4bd4p8J4Du2OaIF
         kgnQ==
X-Gm-Message-State: AOAM532YUi54CDRUoybcQOVXmfchZ1XcFC1/0OVWoVrYeBujth95BJr4
	GaLcjiA4HXpbrNHJvwPBYq8=
X-Google-Smtp-Source: ABdhPJy/Is+RTD5Vy1x+0Ppg7nVjQCMNL0TS7TumEJQNPD8poZFjFbqmZti9NeArqssM0Bqm2KWCng==
X-Received: by 2002:a63:d10a:: with SMTP id k10mr2047558pgg.382.1596170589086;
        Thu, 30 Jul 2020 21:43:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a62:8306:: with SMTP id h6ls2627409pfe.1.gmail; Thu, 30 Jul
 2020 21:43:08 -0700 (PDT)
X-Received: by 2002:a63:a843:: with SMTP id i3mr2092914pgp.190.1596170588629;
        Thu, 30 Jul 2020 21:43:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596170588; cv=none;
        d=google.com; s=arc-20160816;
        b=kL9o8KLApwEAD0Wv6tiUYZhtRw1CxKMWFmYe/Ir0/YRFare/icVVffnTvneAY0XGVv
         V92KYVbHr9EAtBooVKoJvcFtoMdYf1Ei6b4Aau6i974ou8hV/3ywWsc41+/URmza+rv6
         MYuxpU+J7VHQG1BL7mQ3nMr1i4TdhAr9jcnZiG10vtOJkjv2FTZpYHGpnm0W6e+Z02xO
         HLUVon+VXGYfhpHOm/6HFZwhx+E5KrPiBA7lFpyaXH32fhTPCBLAUqFvU6UFH4MDqR+/
         GxVsp927pV6I97uzU7QetY7TuFFZTDD+JrvuIlnzTNF5xP2OY+K+Ry3oxJNWiM0y65DB
         L3Ng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=BW8tJXunVDhJUT5XRrBOJfZjcR8xNS1VRsDjHnpq2UQ=;
        b=Vn9nCeG7jLFQ5IMNzNcpxnacEHpQJSx/nLM1xREd6kpU6mAkDkNsvsSoT/KXWSziuw
         3O4gSr6SvPrRrbXcXpgIjqL6NbJ3z5s57xDgqZA74oSPsiTnBHGDoUsJAGGH6EH5/Oqn
         b6RkYAcMsAnw6YbWCFxPflAyjluLeM5X+aJX9XHowudK1r5Gig6LTxJPfUE7inyqxmFG
         pjhtRQmupiwg4gk6u2853RXjBfpUB9zpyf1yijICQ5SFFt4U2TxHRykkmq0mI5/Jb7gl
         HJ2azb4vodi1CBIbFBlUrBYjMDxEpYEJ/7QLmmKm1YTqJlLSdWN3roHBEzmm3KsHC/tu
         NvDA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=PzMkVTq1;
       spf=pass (google.com: domain of 3w6ejxwgkcswlidqloweowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3W6EjXwgKCSwLIdQLOWeOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id n68si393408pgn.1.2020.07.30.21.43.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 30 Jul 2020 21:43:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3w6ejxwgkcswlidqloweowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id i62so36485327ybc.15
        for <kasan-dev@googlegroups.com>; Thu, 30 Jul 2020 21:43:08 -0700 (PDT)
X-Received: by 2002:a25:aaf3:: with SMTP id t106mr3273322ybi.56.1596170587795;
 Thu, 30 Jul 2020 21:43:07 -0700 (PDT)
Date: Thu, 30 Jul 2020 21:42:41 -0700
In-Reply-To: <20200731044242.1323143-1-davidgow@google.com>
Message-Id: <20200731044242.1323143-5-davidgow@google.com>
Mime-Version: 1.0
References: <20200731044242.1323143-1-davidgow@google.com>
X-Mailer: git-send-email 2.28.0.163.g6104cc2f0b6-goog
Subject: [PATCH v9 4/5] KASAN: Testing Documentation
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
 header.i=@google.com header.s=20161025 header.b=PzMkVTq1;       spf=pass
 (google.com: domain of 3w6ejxwgkcswlidqloweowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3W6EjXwgKCSwLIdQLOWeOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--davidgow.bounces.google.com;
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
index c652d740735d..1f9a75df0fc8 100644
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200731044242.1323143-5-davidgow%40google.com.

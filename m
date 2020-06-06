Return-Path: <kasan-dev+bncBC6OLHHDVUOBBM5L5T3AKGQEA735CLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x139.google.com (mail-il1-x139.google.com [IPv6:2607:f8b0:4864:20::139])
	by mail.lfdr.de (Postfix) with ESMTPS id 43A8E1F0492
	for <lists+kasan-dev@lfdr.de>; Sat,  6 Jun 2020 06:04:04 +0200 (CEST)
Received: by mail-il1-x139.google.com with SMTP id c29sf7806707ilf.20
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Jun 2020 21:04:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1591416243; cv=pass;
        d=google.com; s=arc-20160816;
        b=o6XeMEJ5RdG0sTVyOwkJaj5uYBpFPT25Au8jqDk1FUT4r/qiphP05V0VqWtgCgCQnr
         PCplqy9jO0AZLlmcf93VeTA/MnK4oyi9nGf4tE+i+h4NtQViLA+7xmenGRWmUxXZKY8l
         5KAFpSMwRGeTErXoUNDtWsPOf1OXKkHPQ9Zuko2pyaVR535j5+zAY08OGRlRQeGlkAEh
         OwfMR6yA1rTCuGSVF96qWp2Myy2hF60c1M224obZP/K1rIU+L6D8RYsJuYvVkn99j4r6
         hKermot3ZwHYHHC35dohGckQpAfdz4UnBsGKJsWZkKNdn6V2//J6KC60PScWkawKRWSr
         4cew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=/YClFHUCRYoBDcgimtFa8TipDuPODhOG2nCej9fLpWk=;
        b=UTtTDGsqVu1geluqCfPjl8RwyMNoejgJuBehmbJ/UZRHym9UWN7/ILkHUhEHJTUeur
         xUmkV4JqLgB6SeMflXZxCeyIer7VnWmls3z5Pye2eF8VDlRz7tHlSndUA7wm8yNabNu9
         OaV27r3IVlU5PIDBqpHxLExuUmBbT4cOtPb/OkhP1ScFIYeXfHmdtIIXJ9lYgy8FkIhH
         3e9guqpeQSk5i63WB12ypZP+uFBEgHJV36nqbmD6j0ifAqju3OiVSj7C0hYWCVGsU+W5
         +wCK/oZBr5gXFw4/jtObtJro8S0rOTbvnGxyQSrX3sRcOIlKlHlfueCZcHgHzavwbPkr
         EKNQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SeSUTQIo;
       spf=pass (google.com: domain of 3shxbxggkcucmj4rmpx5pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3shXbXggKCUcmj4rmpx5pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/YClFHUCRYoBDcgimtFa8TipDuPODhOG2nCej9fLpWk=;
        b=VcK2kGk5kErdFfQvv48Cv2wKOoepa3zZkanmOmNfHr8Rh91Xz3PYvOBoniddMwz25M
         tnwasqUfAaSSiE4c3hhPM/H8WiWnXQdRRqZzKMU6hH/sjt/wUDmUZjuBtmGPD7isk/Ty
         sh1gvU1TwYW3TNF/AEAXyislhjBzKDu2I4yN4Whbqadvmhun1RdnN4MvZaARcpld1EGL
         5OfLF04WX+vvFFPmfNQgPVHJaUh5vWnPh9/lm9I57XtV4GewdYxT67itaN+BPzzRBOEi
         hsN0O6UYXkyejN75f74VQiiYBXvpLUSGKG5BFmNJlieqCJLvCZ3Z2CQ8463caehNV2Ib
         jC/A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/YClFHUCRYoBDcgimtFa8TipDuPODhOG2nCej9fLpWk=;
        b=TdABrDTc54WramJz25Mx7P+4vcxC5I5cNe4A8HXDPVwd8GynBBhpQGr+zyQ204giso
         0pMUfut0zN+gmrX9liVG3BuS2G6JGRYCMhAFb3r6poxPtMx0CzM1yIR2nkQCUGuqBID1
         B46UX6cFaHSNQ4gZWALhfSHcpZqiqMBrPDcatv7K80IRyLhIBVKgthDGo9Hp0YoQD84J
         o0GxJ8yYjnvruzj6u3WowemLJsH3W0bvvaWnFRRkVmkASYeboCWQtrv7DZOr4GrVcO8n
         Oe15aGT0eIOrPi/5j4Flskg8kGOwG9rSb7NGxljBFJj2wB1kDlGs6X49vJQnYjclPg7B
         WLtw==
X-Gm-Message-State: AOAM533bbpBvymQ+PwQdmDSAchKUZKLuzhG1J7Z2H4dzAIiPlqW33RO0
	KjWgshtK4lBRNg0AwN3fUvE=
X-Google-Smtp-Source: ABdhPJx5gqLJZfitaQxZvtEektesizs3h2gw+LGxN3zC8XLgBTnf+ny3JWLJF82wF7QA/STRjoiLqA==
X-Received: by 2002:a02:a46:: with SMTP id 67mr11459931jaw.144.1591416243132;
        Fri, 05 Jun 2020 21:04:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:9108:: with SMTP id t8ls3014825ild.3.gmail; Fri, 05 Jun
 2020 21:04:02 -0700 (PDT)
X-Received: by 2002:a92:c812:: with SMTP id v18mr11802454iln.178.1591416242817;
        Fri, 05 Jun 2020 21:04:02 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1591416242; cv=none;
        d=google.com; s=arc-20160816;
        b=GREfc4lCmWV265KFheqLMvCScMeJhe7vo2uKLWtdXBUtHEgVKQZaPoBEXi4EEb1IEM
         fVgaPxTcTEwzsr7fUUQ1Sflctug5VwKGBYztHSa0M+nhpO4VpdkXcBkbS/jGBX/KIXQv
         ZiZPvRcrC0DfYp2184lVx2NpAmejzPRQ+lTC0HtrlJehkW6JRNXmqer+qW54l/q6dhrC
         xpBlgUn6A91SP81S8Om51dRZZDJFQJcB3GRj3MFIjnsVkZlLPgXKWKaRc01Ns/jfrHvL
         JMwhzIJXhSSo4cmrq71INZ9PLhp+cxz8DkyCM9VW58sZ/jcAUaGOLmeyg27k4Aj1OjzK
         5oTg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=LRVbJ2IzntUJ3rFAogfVmsjnLs4DtIrCaWey4mp2L10=;
        b=SjmbCBNzFDNc1T5vOOzzXcKl9qqMG0NqQ4+rQyp70S/IxY1n4idt5iQFpOsovUsmSp
         YxtB3++WewtksScVP0l7Ter37GsJTE7Aj50f0U2Rlqixad603t5jia4Nh4R32wTGShH3
         HdLGXL+CzW4OsXVH6x/e7IBXxvSXYC1ZL0KKbXNlWbZiKLPwSNqZA8D0U6GJgor3qpcR
         LKW7X6ax7uaYJcOPySIVw1myx7QjWPrEx/wo83yE2QfazekjmxRPr3RDfxjnI/e3DYZa
         t+rWgSiOxqUYSI2KG0+PF6QAKq5S4nySMi9ufIvbUxU875wHGU+xXvUQ6MLD8qEsydNF
         RoPA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SeSUTQIo;
       spf=pass (google.com: domain of 3shxbxggkcucmj4rmpx5pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3shXbXggKCUcmj4rmpx5pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id v16si502498ilj.1.2020.06.05.21.04.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Jun 2020 21:04:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3shxbxggkcucmj4rmpx5pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id y189so14543764ybc.14
        for <kasan-dev@googlegroups.com>; Fri, 05 Jun 2020 21:04:02 -0700 (PDT)
X-Received: by 2002:a25:b5c2:: with SMTP id d2mr22710530ybg.9.1591416242137;
 Fri, 05 Jun 2020 21:04:02 -0700 (PDT)
Date: Fri,  5 Jun 2020 21:03:48 -0700
In-Reply-To: <20200606040349.246780-1-davidgow@google.com>
Message-Id: <20200606040349.246780-5-davidgow@google.com>
Mime-Version: 1.0
References: <20200606040349.246780-1-davidgow@google.com>
X-Mailer: git-send-email 2.27.0.278.ge193c7cf3a9-goog
Subject: [PATCH v8 4/5] KASAN: Testing Documentation
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
 header.i=@google.com header.s=20161025 header.b=SeSUTQIo;       spf=pass
 (google.com: domain of 3shxbxggkcucmj4rmpx5pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3shXbXggKCUcmj4rmpx5pxxpun.lxvtj1jw-mn4pxxpunp0x3y1.lxv@flex--davidgow.bounces.google.com;
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
Reviewed-by: Andrey Konovalov <andreyknvl@google.com>

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
2.27.0.278.ge193c7cf3a9-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200606040349.246780-5-davidgow%40google.com.

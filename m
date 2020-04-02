Return-Path: <kasan-dev+bncBDK3TPOVRULBBOE6TH2AKGQEGNJREEY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 5701B19CBD9
	for <lists+kasan-dev@lfdr.de>; Thu,  2 Apr 2020 22:46:50 +0200 (CEST)
Received: by mail-pf1-x43d.google.com with SMTP id t19sf4005363pfq.21
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Apr 2020 13:46:50 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1585860409; cv=pass;
        d=google.com; s=arc-20160816;
        b=sZw9nAeH/PYA+C9QiKLtbTAH2Zad17yo65TiOZAoIqyV1sv1AQ3JKL3wWoQVhQ02+u
         UhEWwF1nDD7cE2tc7oqykGwZ0Sz/cyd2K71DWUhg0mR5PT5DtDgnHMRs/MRU0TKoKMQT
         wBOAjZyBuoKv3LQB5lETvqnDRy1Q9dDDsKwe0GXluuWtPLUGXKM9q6pBtWIL8PpM283L
         iEya7+CmTwD2zeKULeFjfbjtNqSrjSyvZfb0In04HIybnlaNYG+fE76YZQYZh/A/yM1g
         yF2akuXZZn+ZXc8ZIDLeSbLmoObLpNIGnw6tmHcqo5LpbP+uOjloYFYExUpyf2ETeVPd
         iJxg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=/fPYp6rPaNRrudva2nG3DbgdsJU3sGtNreHmz5O+hgA=;
        b=nR5pjcSFiZ/Lqu7+a1cMIZrWnH6y7zw/yl9wyhxRz03S2ioqteR9+gNDlS0FBPjAvY
         US9UexuQ8xL7dXdipy1hdrdiL65SDzMS4Pimpd7PPoAQ3gYESQ83vjPfYTGDdB05Gx1V
         OevMhPabvhiT2w/jz1jdnfWbVpHcMkmki/bQ1UhMRGPO2fi/ExgJ5K808GhBfLmb+iWL
         m2dmg3eUM9aKBoZVxl+pKUFoB9RCOv+jUa655ZXIOptwuYpwcZSzU/Ipf4sNrnMLCvnh
         3z8QvurjyKlinQjIQgjdygnoTXDRc3ZAkQI5TcDjeFyHS5BJvZeVbdh+26KaJey8upgl
         0y/g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uQMfb0xx;
       spf=pass (google.com: domain of 3oe-gxgwkcekectdslwqzydzrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--trishalfonso.bounces.google.com designates 2607:f8b0:4864:20::64a as permitted sender) smtp.mailfrom=3OE-GXgwKCekecTdSLWQZYdZRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--trishalfonso.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/fPYp6rPaNRrudva2nG3DbgdsJU3sGtNreHmz5O+hgA=;
        b=TpiU4gg6Jt7Wj6aRbUpogDzCAiHZX6tMnl1Fz9Mnwn5lQOYRi1e177arJ7IQmKaaUV
         xS6sCQvW+TLcsrQLSW/y3MqICCYpFGnSWLLSoQO+TEAvGAJcF1SJ7Axg1+3DO8Dva0GC
         5l0btpgCGbocGiQOkC+R4CpWvKCCWIUmDQrNJVQEeMFiiPQqtknbwdqPhAxDcFa299dL
         ybeGdyqjQbrg5wRujqcR9z2vqM0uRojojPnpLlkkBhdXEUYHLDmrqrku2QNzEjVQ9EXT
         4or2ktP4E0oc3WD+szuWS/LGIsQFCDbITz6sL1NIvS5sY4xpeKtPN+zkUvhH5Vd5Z6e6
         MBTw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/fPYp6rPaNRrudva2nG3DbgdsJU3sGtNreHmz5O+hgA=;
        b=MIX7DJe/VkQzBnVUdQrTMTZCwmf3B97GBS2E0/H6CcbVggG6w2Dm0tnMe5foAK2c7p
         yaAOnqZkWh4MaQQg0qKNGI2UGb3/OseGekHLW+EKvBICehODMHX787XytT8MPb6oCEL9
         +zyjJBo0KAlLFHHmJar+MAqYax7/3WD3td8qQ5zXc13EUzB+v66gXjYvZmyjyNk1r4kU
         5d/f0KhlO//6v9/vp2dtEtpRN+QiwIWmokA/ksSB61e+AOTdUFPy2DxdLUJzMGQqIt0J
         TaqnLfLY2Kx8nxzfJARzk64JtujTRof9NPLCpcPeigyioidRvUPSwM4dKsp9dpsO9ddk
         /DCA==
X-Gm-Message-State: AGi0PuYO75CqTfXlxx+A7JxQFv6WGKtVohnvxaFWnOgoMUaoDt6DvCOw
	bi69N8n1sz4lV7U+KSwuBlQ=
X-Google-Smtp-Source: APiQypKjUnkVlVKO43H9j23bYB936tyKGhA5cNm9xFUzpVrHgvNchONf9NH3WlRyUJbuFXwwPal+Tw==
X-Received: by 2002:a63:aa02:: with SMTP id e2mr4057600pgf.263.1585860408915;
        Thu, 02 Apr 2020 13:46:48 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:9688:: with SMTP id n8ls3618589plp.3.gmail; Thu, 02
 Apr 2020 13:46:48 -0700 (PDT)
X-Received: by 2002:a17:90a:346f:: with SMTP id o102mr5824941pjb.162.1585860408403;
        Thu, 02 Apr 2020 13:46:48 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1585860408; cv=none;
        d=google.com; s=arc-20160816;
        b=mYEOoHDORXjNYbdiJBpN/++xNHKBoostTDr44CoX8VUTwvTdOfNsJ3ebsZgZXzD8zF
         p1CpXaA+0o5nqvkatFkDCdwHu+iq/74g3mQ+80g5dRVT07hl5L8nu9NiCozJQLC3AO2p
         DwcL9eYNvK5WBXMLlOgSJyaO7Kit4IhAm/G7OaOYvR56f9cRqnQz/RoziqZq7JGobVVo
         /aQyY2mkI2Ao95JpDjEYT7JMoggDlLXEHzWj/5Lv2TfsYoeWrC6zAuB1hIIbdXNI9AP0
         13cPd8v4F/rDqN6IFAd517mpYm9ItTYeYNMKrTkrhsc0/Nd8WlPJSfyENpcQ53NYqG6d
         4WPw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=u9tYGbzZUoeKacfHKj+okUgzHoM8x17MGKsRKBVzF6I=;
        b=nQKfVhCsUOGx3e6zZ4rZGldgV/NdT6jppSIckgvJZW2OUmKRPN/ZGyXBa9/SYLwTSj
         GEdrQoJK3G70Pdyrcs6HxRwwN4NKUPuKwKHsTp4RJ/MlKFMtJWx2OIQKV8KKYC1HEOvG
         1kwrIDM8Oo86YuYxD3kx+Pip+HQk5hyEPUey+ezfywIABie2u87ZQvCvrn5WwSv0BhVQ
         2lJyqoE9ksOsTJERzqvbOr9SFKh4tYxoZbftxtVXNYnvnfVq5OuxIMR7czE9eO1tQLlm
         kZb9OXIiiWjfXBTxM6lHhVEUOPyeDWpdUrC+nCvmWDlXKtI5k25EvKzv89C2cgM01U2O
         b2cA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=uQMfb0xx;
       spf=pass (google.com: domain of 3oe-gxgwkcekectdslwqzydzrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--trishalfonso.bounces.google.com designates 2607:f8b0:4864:20::64a as permitted sender) smtp.mailfrom=3OE-GXgwKCekecTdSLWQZYdZRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--trishalfonso.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x64a.google.com (mail-pl1-x64a.google.com. [2607:f8b0:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id 19si439646pgb.2.2020.04.02.13.46.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 02 Apr 2020 13:46:48 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3oe-gxgwkcekectdslwqzydzrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--trishalfonso.bounces.google.com designates 2607:f8b0:4864:20::64a as permitted sender) client-ip=2607:f8b0:4864:20::64a;
Received: by mail-pl1-x64a.google.com with SMTP id x6so3600567plo.13
        for <kasan-dev@googlegroups.com>; Thu, 02 Apr 2020 13:46:48 -0700 (PDT)
X-Received: by 2002:a17:90a:2663:: with SMTP id l90mr5314572pje.188.1585860408019;
 Thu, 02 Apr 2020 13:46:48 -0700 (PDT)
Date: Thu,  2 Apr 2020 13:46:37 -0700
In-Reply-To: <20200402204639.161637-1-trishalfonso@google.com>
Message-Id: <20200402204639.161637-3-trishalfonso@google.com>
Mime-Version: 1.0
References: <20200402204639.161637-1-trishalfonso@google.com>
X-Mailer: git-send-email 2.26.0.292.g33ef6b2f38-goog
Subject: [PATCH v4 4/4] KASAN: Testing Documentation
From: "'Patricia Alfonso' via kasan-dev" <kasan-dev@googlegroups.com>
To: davidgow@google.com, brendanhiggins@google.com, aryabinin@virtuozzo.com, 
	dvyukov@google.com, mingo@redhat.com, peterz@infradead.org, 
	juri.lelli@redhat.com, vincent.guittot@linaro.org
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	kunit-dev@googlegroups.com, linux-kselftest@vger.kernel.org, 
	Patricia Alfonso <trishalfonso@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: trishalfonso@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=uQMfb0xx;       spf=pass
 (google.com: domain of 3oe-gxgwkcekectdslwqzydzrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--trishalfonso.bounces.google.com
 designates 2607:f8b0:4864:20::64a as permitted sender) smtp.mailfrom=3OE-GXgwKCekecTdSLWQZYdZRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--trishalfonso.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Patricia Alfonso <trishalfonso@google.com>
Reply-To: Patricia Alfonso <trishalfonso@google.com>
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

Include documentation on how to test KASAN using CONFIG_TEST_KASAN and
CONFIG_TEST_KASAN_USER.

Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
---
 Documentation/dev-tools/kasan.rst | 70 +++++++++++++++++++++++++++++++
 1 file changed, 70 insertions(+)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index c652d740735d..287ba063d9f6 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -281,3 +281,73 @@ unmapped. This will require changes in arch-specific code.
 
 This allows ``VMAP_STACK`` support on x86, and can simplify support of
 architectures that do not have a fixed module region.
+
+CONFIG_TEST_KASAN & CONFIG_TEST_KASAN_USER
+-------------------------------------------
+
+``CONFIG_TEST_KASAN`` utilizes the KUnit Test Framework for testing.
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
+With ``CONFIG_KUNIT`` built-in, ``CONFIG_TEST_KASAN`` can be built as
+a loadable module and run on any architecture that supports KASAN
+using something like insmod or modprobe.
+
+(2) Built-In
+~~~~~~~~~~~~~
+
+With ``CONFIG_KUNIT`` built-in, ``CONFIG_TEST_KASAN`` can be built-in
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
+``CONFIG_TEST_KASAN_USER`` is a set of KASAN tests that could not be
+converted to KUnit. These tests can be run only as a module with
+``CONFIG_TEST_KASAN_USER`` built as a loadable module and
+``CONFIG_KASAN`` built-in. The type of error expected and the
+function being run is printed before the expression expected to give
+an error. Then the error is printed, if found, and that test
+should be interpretted to pass only if the error was the one expected
+by the test.
-- 
2.26.0.292.g33ef6b2f38-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200402204639.161637-3-trishalfonso%40google.com.

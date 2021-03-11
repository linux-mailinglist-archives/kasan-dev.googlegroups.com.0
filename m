Return-Path: <kasan-dev+bncBDX4HWEMTEBRBME3VKBAMGQEO3IHBAA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x539.google.com (mail-ed1-x539.google.com [IPv6:2a00:1450:4864:20::539])
	by mail.lfdr.de (Postfix) with ESMTPS id 8546B337FBA
	for <lists+kasan-dev@lfdr.de>; Thu, 11 Mar 2021 22:37:52 +0100 (CET)
Received: by mail-ed1-x539.google.com with SMTP id n20sf10601761edr.8
        for <lists+kasan-dev@lfdr.de>; Thu, 11 Mar 2021 13:37:52 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615498672; cv=pass;
        d=google.com; s=arc-20160816;
        b=lp/THb0t5bIFF3Icib536cmjFyKL72bY68eZB1xzOobzS7HadgQCgQTWcrGsh+3FGO
         1z971OZD0aM4Hr/zFSXdT9ktmQ5h1MWu9Vuu+8ENXzRF6fk1AT1bSI+B/tAY7NmNyLNU
         i/wvrkH3V7B5djGEORK2XteNUxjz5U+IOHI304sJBe3BqtfdwEPpILz386GH8kFYQfGs
         SO3ss80oU90FgGhOhWeTMX49skISyv7PlxHKPZ+PvCCVgUPVXi5V4SkivFn/TfDKN6l6
         p+wf06mbIAhGY7SEe+a/ns5oONNmZk/MY/Xtd5zpsFD4RInmgeGWo7Lqa7Jw9VwxpLeA
         kT3A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=rnFSvqw8htf1Dar0+APZ72E067/t9HD2RtzstLg0ETA=;
        b=FxPMci4pS+Fs4GdlEvytG02lRu/Hvo/m9TdW0eDAWLHSlf0npprku+5/zESYPXeh0d
         1oJyqsGla9+ik0PzubkIB/GtPggpLPGPeneL+QIYCRSfXc3fPU3iZs24XoUj1N68BCgL
         79gnxbI788LZdhG4sULuemG9odOTWRVJV+DddmDYhFlnC9wF3ZazfgCD8Lmxp3Rl3s6X
         3COXxF50Q57/Ydb2i/jinrtULiytmwelR0VgSBjQRr2v41iVaN2Y4P/2oij/uAjF31IK
         AP8k05mexdjkfoDKDplAHTw+hN9WTgMJ6Y6IqviHxYqvL+XT8sOqbyXuyfNWZZg3nCtL
         t2HA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vUKUWADT;
       spf=pass (google.com: domain of 3r41kyaokcfwerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3r41KYAoKCfwerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rnFSvqw8htf1Dar0+APZ72E067/t9HD2RtzstLg0ETA=;
        b=j1OTKFUbGnoPrz26t85mZKXlrzlGwXPkzKvbrkyj7y6P0eUOpQuyn6KlXCqjYlHyOY
         I0rBsQEQyTMsk9ynBxdy7Y6yPxodOsmanA/t2ntSA7ME8RDkLvP6cEfBe/9npsltsAAM
         2ZrSWJwYrkviNbnOYj3aaLYoWl2Tg+zlXoo20TWjU/l0PfC7fI2eBn9YGt33oF8DFmHS
         sljSZXAN3qQyyR0sDbH3DRj214XUwRrH4kEg43wSQ11HXP1nMUQ2ILHfphLJEJAoVB0G
         xa3ZFww8ZkG/u/DBuNAyMy/6FdgR+fRmqm4dTQchYmZu9eQx9QSSuvKntnjsgRwcmw/7
         8gHA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=rnFSvqw8htf1Dar0+APZ72E067/t9HD2RtzstLg0ETA=;
        b=Vo6HaOPNia0elWxou2Z6KQeLCoIWRbXTtHu3UOnjYGM0KDpOr/LC1NettMIJC/awMH
         EsCII4NX+3H77QsCbwzp5uqQ/8bD+SNeiNPVr9CoIzAQ28bQY7AjpJIXdtKv/YQjc8C1
         gd6k0Wf6vMBECLAoRPmumZOEAp2PQOrvZWU99HNksgKr7ITgU9v+Bi0XQYKr6+4KhWLx
         y43ENhUcavbseaM9QH9iOz7knaPga8yGL04fgplHL8u4acHSqZtb9kyalenmcbTK1q4k
         eZeTuBY//cwWhclWSUpiod2loXKsSOE0nHjMDdAF4mthAvn6f9R3HtT1g3fWOs9AA/J4
         Zm7Q==
X-Gm-Message-State: AOAM532sYhwrqoE/KZbSXr5X6PTDyB8JK4iUITXx6crCFr5D0qv/vmXm
	hgXGKYsvUecb8yLlRVPI6zA=
X-Google-Smtp-Source: ABdhPJwAh5XbGr1B4BN/vN8Dt4NDFXZ55pI7d2vnck9G8D6xfG9t0xZaYI9rVwnM1lKGcAkFHiIc8A==
X-Received: by 2002:a17:906:d71:: with SMTP id s17mr5303984ejh.126.1615498672271;
        Thu, 11 Mar 2021 13:37:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:907:d06:: with SMTP id gn6ls959469ejc.0.gmail; Thu, 11
 Mar 2021 13:37:51 -0800 (PST)
X-Received: by 2002:a17:906:58d6:: with SMTP id e22mr5047048ejs.112.1615498671462;
        Thu, 11 Mar 2021 13:37:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615498671; cv=none;
        d=google.com; s=arc-20160816;
        b=n8CtYZ/8OcudiD4zF4JhzTTF0MmD2pqnCu4Ei9CSD6yaa/geARpFsIk7QflEQWvXEk
         aa8ePuQk8AZIMT1RUlTHejQQShTc0CpJUk4eUCjKrSUjOvYgF1awqNJDH3bQ/oEND6/K
         V8pMhDJ0pfHigxXIKwKXT0QpLFKVpJ9zULZ8e72dj19CUqU43YUbQoScihunKr+H+Ulq
         dR8oRRnAGrvLy5VdPUBVtR99FqLniPJi37X7xq9LVGLmPmMvOwtt7dfsDXyM13VAUO7+
         dSUvTCSCcYBps06uU+uqAIj9Gp5mFo5XAgLMLeyW1wFf5q/seH5xDbWEE8r32Clq7q/D
         QbDQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=KqyiEXFZVlJ5WAkVIpzRsNvJDBTABYowTYxavN0wmPI=;
        b=ZZ5Ld/Am0cpi/i+ovVRaaLksargxATRllUBBDtR0OBXP5eHITogh6CvruFFiSuhPtg
         yzbdbf/66k5i7mCgZdti2uCLEqbMQ+6S+Ez6uDl2o2dj+uZOW10ylsbluwNO4apsE3PV
         WrtcS3l8b5rGMLAPkhYMKgZB5IwKdnHPMaaQWOxQxAEq96hXsh5K41h/EBQ46T7YPjgg
         8sDXtOgq1QU/qjTpci44aT6+ASOPcYuibirmqrkRbgDKldIdW9ksGACbTA/DSA1T5cpz
         2TyUQgOBcypRo5/QSZQ5aZzg3gY/lNOokCFCo2MImyir6ZplzyaBa7NHkPB2bgdIakkK
         3Kvg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=vUKUWADT;
       spf=pass (google.com: domain of 3r41kyaokcfwerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3r41KYAoKCfwerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x44a.google.com (mail-wr1-x44a.google.com. [2a00:1450:4864:20::44a])
        by gmr-mx.google.com with ESMTPS id m18si78485edd.5.2021.03.11.13.37.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 11 Mar 2021 13:37:51 -0800 (PST)
Received-SPF: pass (google.com: domain of 3r41kyaokcfwerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::44a as permitted sender) client-ip=2a00:1450:4864:20::44a;
Received: by mail-wr1-x44a.google.com with SMTP id s10so10129414wre.0
        for <kasan-dev@googlegroups.com>; Thu, 11 Mar 2021 13:37:51 -0800 (PST)
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:95a:d8a8:4925:42be])
 (user=andreyknvl job=sendgmr) by 2002:a7b:cc84:: with SMTP id
 p4mr10172254wma.10.1615498671258; Thu, 11 Mar 2021 13:37:51 -0800 (PST)
Date: Thu, 11 Mar 2021 22:37:23 +0100
In-Reply-To: <f6efb2f36fc1f40eb22df027e6bc956cac71745e.1615498565.git.andreyknvl@google.com>
Message-Id: <f9e2d81b65dac1c51a8109f039a5adbc5798d169.1615498565.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <f6efb2f36fc1f40eb22df027e6bc956cac71745e.1615498565.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.31.0.rc2.261.g7f71774620-goog
Subject: [PATCH 11/11] kasan: docs: update tests section
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=vUKUWADT;       spf=pass
 (google.com: domain of 3r41kyaokcfwerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::44a as permitted sender) smtp.mailfrom=3r41KYAoKCfwerhvi2orzpksskpi.gsqoewer-hizksskpikvsytw.gsq@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

Update the "Tests" section in KASAN documentation:

- Add an introductory sentence.
- Add proper indentation for the list of ways to run KUnit tests.
- Punctuation, readability, and other minor clean-ups.

Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
---
 Documentation/dev-tools/kasan.rst | 33 +++++++++++++++----------------
 1 file changed, 16 insertions(+), 17 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index 6628b133c9ad..c4a3c8a9fe71 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -398,19 +398,20 @@ To disable KASAN reports in a certain part of the kernel code:
 Tests
 ~~~~~
 
-KASAN tests consist of two parts:
+There are KASAN tests that allow verifying that KASAN works and can detect
+certain types of memory corruptions. The tests consist of two parts:
 
 1. Tests that are integrated with the KUnit Test Framework. Enabled with
 ``CONFIG_KASAN_KUNIT_TEST``. These tests can be run and partially verified
-automatically in a few different ways, see the instructions below.
+automatically in a few different ways; see the instructions below.
 
 2. Tests that are currently incompatible with KUnit. Enabled with
 ``CONFIG_KASAN_MODULE_TEST`` and can only be run as a module. These tests can
-only be verified manually, by loading the kernel module and inspecting the
+only be verified manually by loading the kernel module and inspecting the
 kernel log for KASAN reports.
 
-Each KUnit-compatible KASAN test prints a KASAN report if an error is detected.
-Then the test prints its number and status.
+Each KUnit-compatible KASAN test prints one of multiple KASAN reports if an
+error is detected. Then the test prints its number and status.
 
 When a test passes::
 
@@ -438,27 +439,25 @@ Or, if one of the tests failed::
 
         not ok 1 - kasan
 
-
 There are a few ways to run KUnit-compatible KASAN tests.
 
 1. Loadable module
 
-With ``CONFIG_KUNIT`` enabled, ``CONFIG_KASAN_KUNIT_TEST`` can be built as
-a loadable module and run on any architecture that supports KASAN by loading
-the module with insmod or modprobe. The module is called ``test_kasan``.
+   With ``CONFIG_KUNIT`` enabled, KASAN-KUnit tests can be built as a loadable
+   module and run by loading the `test_kasan.ko`` with ``insmod`` or
+   ``modprobe``.
 
 2. Built-In
 
-With ``CONFIG_KUNIT`` built-in, ``CONFIG_KASAN_KUNIT_TEST`` can be built-in
-on any architecure that supports KASAN. These and any other KUnit tests enabled
-will run and print the results at boot as a late-init call.
+   With ``CONFIG_KUNIT`` built-in, KASAN-KUnit tests can be built-in as well.
+   In this case, the tests will run at boot as a late-init call.
 
 3. Using kunit_tool
 
-With ``CONFIG_KUNIT`` and ``CONFIG_KASAN_KUNIT_TEST`` built-in, it's also
-possible use ``kunit_tool`` to see the results of these and other KUnit tests
-in a more readable way. This will not print the KASAN reports of the tests that
-passed. Use `KUnit documentation <https://www.kernel.org/doc/html/latest/dev-tools/kunit/index.html>`_
-for more up-to-date information on ``kunit_tool``.
+   With ``CONFIG_KUNIT`` and ``CONFIG_KASAN_KUNIT_TEST`` built-in, it is also
+   possible to use ``kunit_tool`` to see the results of KUnit tests in a more
+   readable way. This will not print the KASAN reports of the tests that passed.
+   See `KUnit documentation <https://www.kernel.org/doc/html/latest/dev-tools/kunit/index.html>`_
+   for more up-to-date information on ``kunit_tool``.
 
 .. _KUnit: https://www.kernel.org/doc/html/latest/dev-tools/kunit/index.html
-- 
2.31.0.rc2.261.g7f71774620-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/f9e2d81b65dac1c51a8109f039a5adbc5798d169.1615498565.git.andreyknvl%40google.com.

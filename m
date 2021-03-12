Return-Path: <kasan-dev+bncBDX4HWEMTEBRBP7TVWBAMGQEHFGGUNQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 2438E338FEB
	for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 15:25:04 +0100 (CET)
Received: by mail-lj1-x23f.google.com with SMTP id q13sf9865082ljp.23
        for <lists+kasan-dev@lfdr.de>; Fri, 12 Mar 2021 06:25:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1615559103; cv=pass;
        d=google.com; s=arc-20160816;
        b=fz6/FHZmoPE0zhAP9+mR+FNbWJEjhr2/H1UypxxQwzkSzw/oHjblRv6aKHAXzud16W
         OaTvqkZqfx3gzslkT/lC4XRPfDLMmD7j2TjgcXjg2ZuvMPCKEEDIk4b0+goDibVH4Rdg
         1Yyy1gAYWEMtOldesq7FVxcIt2CO4uMHmhbCfLodvTxS9GtYATJdAx06hOKMuVZ2OgS6
         1PTj6TgGH2LnF9BrvBLk5FzEnDRVb/jT1VIUqoA8Pd6XzsJHzT3ZcoKF/QNhPiG2Z/iN
         RQK2STyAmXfwXsI1C7swaHc8/dajNlEW8DK80xcnksHToqFSLCwVR3Zi4svqp5Yrp3De
         i4AA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=1qYLRh1TDlIQzX4pL4VWB9vj+msP/qQ8VY3KhLDjckU=;
        b=yDRXRcnLiNZriUFMRRKHofWmuJ6JIt75i5XC5EDJXsE6axSsbWTKKw3avkWrDiN+8L
         RLf2wBsVuzAnoymnbOkci+qlVnlKJZoMRwjn1wa4xEUpTkRI9gGaG0xVZGReF7dyybxI
         xFuEztLHrxdJgm9AR2OdRJWz7fJEWSft7J6Inok6nNoRpP/ExYfUNOn9o7conkt97iAf
         ltqQvc6GFoaygP9gfPW902uCIO6P2EvKLVgBLB8yGARFblxqPbgzkkz7VxbiH8uprOYW
         vUAVJmFNWKL/1sqhvYVG3VdwplTfKd1+N3teY8lYXvXhQmXIZlg9Ofk4UBz8uBxCVxR2
         Hfxw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Xnhtd3gv;
       spf=pass (google.com: domain of 3vxllyaokceyivlzmgsvdtowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3vXlLYAoKCeYIVLZMgSVdTOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1qYLRh1TDlIQzX4pL4VWB9vj+msP/qQ8VY3KhLDjckU=;
        b=dasDECHoWP8vEZXeJWesdP3ddIBauRGrI8obq6CapMI634Yv6uNrQZqnZKbarNl2Ph
         yO8FEuUwU0aI4o9+AOBNXd0U3mSoPRJwBXZhbw4rqbkLqwZhz31fJ2++p8eFtpWvlTp/
         zgDPNg/kdQ6bC+fUeSqjFuUkXEi2hiQY/exgtymb73W9jWW6f6S+iLSJx6slybn8frnU
         elBK1PSsX7NDUIzfWDOKmc9lpkPCEZ1bGEm+7hqCPU3PZhgqQTb6Smi7qDfowPJDaF8w
         SwvXc5eZw9vsbapoeL7EY0Adct3CRRyFgU24sAUqOnw3267Fh0vzlQeWkOTTosz7RejA
         05Kg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=1qYLRh1TDlIQzX4pL4VWB9vj+msP/qQ8VY3KhLDjckU=;
        b=AxvRvWSLTbUwt446lpY8ntniUMgmFzmBCxL6cVqTiJ+3OUpnDbOQXV4FC06gRwr/8e
         B6D5SwkyIEh0AosktwmKmrIZuTtNE+5trPiTN4N6qNmPaiAYqaYUUUBx/ps+9M9mvpmE
         2F5oNiB/+YShM0fqCdD8PG8/yiA1GOsOFXPu4aSGv4CASqZ0Nk/52Ie4MRTdlnJ7DYXG
         6Q4pc0+XEYYntS6tJwOlxlrtUW+/1SxLlYDAa6eRIJH2waVAmshY4y9e7OkPc5FyENoE
         FT/ctZx5KdPm027yrzYpa8LSZx6gfSt08hJkqq42usWXaI5PB/tC/rdfHyGZk/sCJQ9j
         FuOw==
X-Gm-Message-State: AOAM531f9FUV8yszWTg6968F7JCI4XyZzM0+1umhMrk7/UtMx+9pCxOI
	sNzm2FHGhh+vbFwFjfpdyyc=
X-Google-Smtp-Source: ABdhPJxPV0TYJjYmGEyEyNW5lKmF37vAWc5S1oVlS9KSOqqxiVq1l7GEyVkfs/Hj8+DfKyIi586UUQ==
X-Received: by 2002:a2e:b814:: with SMTP id u20mr2486056ljo.370.1615559103737;
        Fri, 12 Mar 2021 06:25:03 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3993:: with SMTP id j19ls3504945lfu.3.gmail; Fri,
 12 Mar 2021 06:25:02 -0800 (PST)
X-Received: by 2002:ac2:4896:: with SMTP id x22mr5564261lfc.565.1615559102827;
        Fri, 12 Mar 2021 06:25:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1615559102; cv=none;
        d=google.com; s=arc-20160816;
        b=VLsBb/9Uk6pB+34syKRjWylcSasDwDtl7oT03EQJVtxf1f1b9iJlX9U58KPPwhxV+Q
         AI1NaCv1GcAMzpGeBl43+Mvi40gqmp9RCrU/J9SQQR1mum+cUHeiUbvRzFOAjeqFxoi0
         UG7dFFIkXjyedRyscUA7oOOF+DbimXHDLeElO9Q5ZYq6Jev/3L/J/ydQqc+wYYHqQBuo
         bqQLyRf4rmL6D/glWTCzge+BwF3XX/LhdZttW2i6zw3WnyQZrgcOSYb1yl3WZCcWCxUJ
         2XHZK+ot8fq7IASBFyt5+7fz6hw65EwIgo8v6H0iPB0ZMuKOD2DLg6ruvzZz5osKQlBo
         J7NA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=Bw5uCei/catF+EzOEmfCcRCFyREJER0Q0h8plWDwOtQ=;
        b=O1HuMc4B9anFGfOstnPCbnKvtQ/RMqtWA3n6u9F8EQ7/aChcSpGhzQcAy7TYaPDo20
         BdTBi79tjB4Xlg1Z5QXvQ13CSNtHwyldDqJBS+jo/MLzi2L61fwkeYm+iscgMVt0UqKC
         S9anK0WfvXIpFxsB+UKG/pxqND22n60M7bOq2vlLRfRMJyq96aBDgGtCaPBMeeGLEpFv
         hcIjh6VpTn55iLG6B+XJsmKNDKnX7+F2lZgdQkZo1SbDLskLRzamjZNgcdf5lL4Rr4qd
         V4atWNwlMsTsCxgeW6U3M+oBbAEjBhghYL1z7adL1attJa+JGSXsNZBmKZ4UQIF75JXX
         vgrA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Xnhtd3gv;
       spf=pass (google.com: domain of 3vxllyaokceyivlzmgsvdtowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3vXlLYAoKCeYIVLZMgSVdTOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--andreyknvl.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id a66si206326lfd.7.2021.03.12.06.25.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 12 Mar 2021 06:25:02 -0800 (PST)
Received-SPF: pass (google.com: domain of 3vxllyaokceyivlzmgsvdtowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--andreyknvl.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id p15so11113874wre.13
        for <kasan-dev@googlegroups.com>; Fri, 12 Mar 2021 06:25:02 -0800 (PST)
X-Received: from andreyknvl3.muc.corp.google.com ([2a00:79e0:15:13:95a:d8a8:4925:42be])
 (user=andreyknvl job=sendgmr) by 2002:a7b:c18e:: with SMTP id
 y14mr2248712wmi.1.1615559101927; Fri, 12 Mar 2021 06:25:01 -0800 (PST)
Date: Fri, 12 Mar 2021 15:24:34 +0100
In-Reply-To: <c2bbb56eaea80ad484f0ee85bb71959a3a63f1d7.1615559068.git.andreyknvl@google.com>
Message-Id: <fb08845e25c8847ffda271fa19cda2621c04a65b.1615559068.git.andreyknvl@google.com>
Mime-Version: 1.0
References: <c2bbb56eaea80ad484f0ee85bb71959a3a63f1d7.1615559068.git.andreyknvl@google.com>
X-Mailer: git-send-email 2.31.0.rc2.261.g7f71774620-goog
Subject: [PATCH v2 11/11] kasan: docs: update tests section
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
To: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	Marco Elver <elver@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Dmitry Vyukov <dvyukov@google.com>, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Xnhtd3gv;       spf=pass
 (google.com: domain of 3vxllyaokceyivlzmgsvdtowwotm.kwusiaiv-lmdowwotmozwcxa.kwu@flex--andreyknvl.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=3vXlLYAoKCeYIVLZMgSVdTOWWOTM.KWUSIaIV-LMdOWWOTMOZWcXa.KWU@flex--andreyknvl.bounces.google.com;
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

Changes v1->v2:
- Fix missing snippet delimeter around "test_kasan.ko".
- Drop "the" before "test_kasan.ko".
---
 Documentation/dev-tools/kasan.rst | 32 +++++++++++++++----------------
 1 file changed, 15 insertions(+), 17 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index 5749c14b38d0..a8c3e0cff88d 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -411,19 +411,20 @@ saving and restoring the per-page KASAN tag via
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
 
@@ -451,27 +452,24 @@ Or, if one of the tests failed::
 
         not ok 1 - kasan
 
-
 There are a few ways to run KUnit-compatible KASAN tests.
 
 1. Loadable module
 
-With ``CONFIG_KUNIT`` enabled, ``CONFIG_KASAN_KUNIT_TEST`` can be built as
-a loadable module and run on any architecture that supports KASAN by loading
-the module with insmod or modprobe. The module is called ``test_kasan``.
+   With ``CONFIG_KUNIT`` enabled, KASAN-KUnit tests can be built as a loadable
+   module and run by loading ``test_kasan.ko`` with ``insmod`` or ``modprobe``.
 
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
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/fb08845e25c8847ffda271fa19cda2621c04a65b.1615559068.git.andreyknvl%40google.com.

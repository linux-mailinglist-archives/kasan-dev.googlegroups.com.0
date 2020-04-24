Return-Path: <kasan-dev+bncBC6OLHHDVUOBBHUHRL2QKGQEUEN33UY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33c.google.com (mail-ot1-x33c.google.com [IPv6:2607:f8b0:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 431AC1B6DD3
	for <lists+kasan-dev@lfdr.de>; Fri, 24 Apr 2020 08:13:56 +0200 (CEST)
Received: by mail-ot1-x33c.google.com with SMTP id x3sf5641596otp.10
        for <lists+kasan-dev@lfdr.de>; Thu, 23 Apr 2020 23:13:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1587708830; cv=pass;
        d=google.com; s=arc-20160816;
        b=qNTixtAsh8wDxRx5gA2OcSxKmgQrcx749HPCEoGAAmjBIvCCpiGY9o2woD4aFwUhCL
         C5UBtGRZgEav3v5VpbpdmaxrTimLjTaWYkj43MkqTKZtNEIDHR2//I09FJ0zDtcySdlj
         uGR53HrwtDhlUF5V9Pf/j2L+Kr/eydQf5WL6SVVNiwgiNxPpwhf7VlrKoY5yYkdlD5Ya
         YWVUgDf9Cue4KcLgj4H7+FvUDwGR+WgLllUBHZhzx07qTxaGweaqobByvxLAmWqF9g+o
         nfqQhln/yXfKrTeAss7V51DZZI3DESO60hE2kNCiYm8Z67RM2va+MYgI506Yrd4cfVze
         sQdw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=DJ94abJBZQ/6QsLYpaghQ77gdWc2FjT5YJka1qIJX6k=;
        b=JF1+T91KgmXDUQ3uZ+j9e4mNXZX9EuOc0JunJz7ewjP2eS9A5/03lrDOIYPP/xgsZw
         idmOCg+fuQ5bYGYAzxXm2e+YIm9GDrlA6C+RHl51SH0/R0v0d4YDvuHkiWpCW70cakWe
         g3rAbOFnLysKVsKeS2CtDDyw6IAUTY/GUcAyhE8GDjbFVFo4+A/tKLx6qKlFPMnnp/Sn
         OKqYzC/2G7X7zdBMVuYijQZt3xrLSrNul9T64I4iceBS1OXlbwd0e6IucTPzNPuRIR2/
         A/Xi12p6NigiI9sbI7QejNZhioC/Ka8aOzTqWPbC6sXQyZOdxA6NlG9Zg1Dnh255f4Fg
         rCyA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Rf7iTk78;
       spf=pass (google.com: domain of 3nioixggkcskifaniltblttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::64a as permitted sender) smtp.mailfrom=3nIOiXggKCSkIFaNILTbLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=DJ94abJBZQ/6QsLYpaghQ77gdWc2FjT5YJka1qIJX6k=;
        b=MiFzaKYp/HF4EZe7XMDnecvK1Y4QaL3rhyFubY8tvPoMLaJhRRvTLeO7tvCGwUAzdB
         K0kgH2hBufnnlFgQVED2QrMd/Ov97N79IYwaXb+Eh2YOGC4kJF6UDQuK3ldlN51RFCPr
         dgPZZqy7OShGGdpRwiXr75arVLlx07NSXsk7J8kqbKZEG+ANDi5NxR4vOIpleRxJcu9s
         //aM3GeOGbcODIdgI2C1FeRzKyFpPNmJGF/bMiX76bCnSAmjzBaT+STSomAX4oJGfj75
         Q3FqNCZaqdgb+XOp6s7AOLDvYNveGZaG5sRRBmXc9Ixhe4YJne9ErsIOZH+mzGI9HhH8
         bYQA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=DJ94abJBZQ/6QsLYpaghQ77gdWc2FjT5YJka1qIJX6k=;
        b=fb7XDE8ewmfAJx6u+EOA83N1RjL1NIlHvpgxvZWFvXyZsUlG010nZSvlDd0kj/GQwI
         N/uhsXaxUDOskIEOnek8sIh3SjtKLooKLmZPrCycr6Qxd+Z35okz3aCRdIVtiRxzu6iD
         wMIcTwEesCqHcm38+IoNS1tM2TgYODjC+CM8BWxO+HPJ0MK/NolPxJnSoX7l0YeU35n2
         UsNTa9NMKlxzflgN5AUFQxhC1pTSfbrOD2bP1Mc1528vLkWjyiP3AZv8Ppcidp4gLqyX
         gjyS4ABpN4gh1OPWIDNnkaLtSKhPuKOophsQ7iNkVXcJG8Ra3ADnqHWh2rC7cOkuso31
         g7WA==
X-Gm-Message-State: AGi0PuYj9DmOyXh2+85Ue+zo4BmYZ3TaQPamYtNFzjkbjBCLB94dnUyN
	EVQWbRTpeJgBZ6L0jLTlwug=
X-Google-Smtp-Source: APiQypIKYbR58YM0cVXEQwpe61vKEMEaM7ZpLUZBrsND4jQa2GdMs6TJkC7z0NRV4XbCRSi6xHZeBw==
X-Received: by 2002:aca:2b0a:: with SMTP id i10mr5992248oik.22.1587708830111;
        Thu, 23 Apr 2020 23:13:50 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:363:: with SMTP id 90ls2022175otv.6.gmail; Thu, 23 Apr
 2020 23:13:49 -0700 (PDT)
X-Received: by 2002:a05:6830:1303:: with SMTP id p3mr6830204otq.186.1587708829792;
        Thu, 23 Apr 2020 23:13:49 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1587708829; cv=none;
        d=google.com; s=arc-20160816;
        b=p+WzA4gb8A6q0RRhvoyRBrB4PdNewXoP0C6wM1R1wNjXb6CJOGrYBIzCueccES+XXo
         YLXhEexvXeDMBssbJuts6JQIQ9dIIZBf52+OwLh1XWFK4/oOz0WJNvmUTm0l9MLSngRw
         nIrYLlGdVG90BElU8xae9Ge0WGd9ssSGv5ly4BsrLr+me1EE77QoeW4LQb82m4shzgq+
         teWYskUrPExwcZ2vJQJonxipAPd8up5wLjwl9uVbkIsLPuAon8uyG9YOsptP9D+G655a
         gl3qyYJg2aZuf0nwGy2Krk1ws4BmyGRIxk4tm71L5WZH0ag6vyvTSbK0DLsD8nRClooM
         emUA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=hEcvs1wHnncZBwVXSE4QsPgDAjpnjLGcoblNPYaX51o=;
        b=pVSzLIHhAmThNXZT4yI0TH5bGRkPhxg34awZRgDI81pcQ8uD/+Hf0WV55JU57r+bS2
         slWOMk0eiTV8I+7tuumc3X4ffWqxLhhjA685ml6m9cA1Hvirb98eesLY6ruKKiE7Tg7y
         BxLhlzFanWzcr+axyMKyt+h66tJiMNu7qsO9aUli9q7va1xGXMizec/IR4VVOzgFU95i
         G1/ScSUvK/4xEQYj8ezcKUq9Rq2uNFmHqdeDf3dgOIzXCvJNqSv5esbnsDKPQc0TFsbo
         9wKYpPnX0tFDN/D+KLprHnxkti0nrpKqMQ3/qSrv+ODbCYBseQ0WDVh6LBJ5QVKzhJ+Q
         KPLA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Rf7iTk78;
       spf=pass (google.com: domain of 3nioixggkcskifaniltblttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::64a as permitted sender) smtp.mailfrom=3nIOiXggKCSkIFaNILTbLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x64a.google.com (mail-pl1-x64a.google.com. [2607:f8b0:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id o6si653712otk.5.2020.04.23.23.13.49
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 23 Apr 2020 23:13:49 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3nioixggkcskifaniltblttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::64a as permitted sender) client-ip=2607:f8b0:4864:20::64a;
Received: by mail-pl1-x64a.google.com with SMTP id x2so6781806pll.2
        for <kasan-dev@googlegroups.com>; Thu, 23 Apr 2020 23:13:49 -0700 (PDT)
X-Received: by 2002:a17:90b:110d:: with SMTP id gi13mr4547288pjb.131.1587708828845;
 Thu, 23 Apr 2020 23:13:48 -0700 (PDT)
Date: Thu, 23 Apr 2020 23:13:37 -0700
Message-Id: <20200424061342.212535-1-davidgow@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.26.2.303.gf8c07b1a785-goog
Subject: [PATCH v7 0/5] KUnit-KASAN Integration
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
To: trishalfonso@google.com, brendanhiggins@google.com, 
	aryabinin@virtuozzo.com, dvyukov@google.com, mingo@redhat.com, 
	peterz@infradead.org, juri.lelli@redhat.com, vincent.guittot@linaro.org
Cc: David Gow <davidgow@google.com>, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, kunit-dev@googlegroups.com, 
	linux-kselftest@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Rf7iTk78;       spf=pass
 (google.com: domain of 3nioixggkcskifaniltblttlqj.htrpfxfs-ijalttlqjlwtzux.htr@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::64a as permitted sender) smtp.mailfrom=3nIOiXggKCSkIFaNILTbLTTLQJ.HTRPFXFS-IJaLTTLQJLWTZUX.HTR@flex--davidgow.bounces.google.com;
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

This patchset contains everything needed to integrate KASAN and KUnit.

KUnit will be able to:
(1) Fail tests when an unexpected KASAN error occurs
(2) Pass tests when an expected KASAN error occurs

Convert KASAN tests to KUnit with the exception of copy_user_test
because KUnit is unable to test those.

Add documentation on how to run the KASAN tests with KUnit and what to
expect when running these tests.

This patchset depends on:
- "[PATCH v3 kunit-next 0/2] kunit: extend kunit resources API" [1]
- "[PATCH v3 0/3] Fix some incompatibilites between KASAN and
  FORTIFY_SOURCE" [2]

Changes from v6:
 - Rebased on top of kselftest/kunit
 - Rebased on top of Daniel Axtens' fix for FORTIFY_SOURCE
   incompatibilites [2]
 - Removed a redundant report_enabled() check.
 - Fixed some places with out of date Kconfig names in the
   documentation.

Changes from v5:
 - Split out the panic_on_warn changes to a separate patch.
 - Fix documentation to fewer to the new Kconfig names.
 - Fix some changes which were in the wrong patch.
 - Rebase on top of kselftest/kunit (currently identical to 5.7-rc1)

Changes from v4:
 - KASAN no longer will panic on errors if both panic_on_warn and
   kasan_multishot are enabled.
 - As a result, the KASAN tests will no-longer disable panic_on_warn.
 - This also means panic_on_warn no-longer needs to be exported.
 - The use of temporary "kasan_data" variables has been cleaned up
   somewhat.
 - A potential refcount/resource leak should multiple KASAN errors
   appear during an assertion was fixed.
 - Some wording changes to the KASAN test Kconfig entries.

Changes from v3:
 - KUNIT_SET_KASAN_DATA and KUNIT_DO_EXPECT_KASAN_FAIL have been
 combined and included in KUNIT_DO_EXPECT_KASAN_FAIL() instead.
 - Reordered logic in kasan_update_kunit_status() in report.c to be
 easier to read.
 - Added comment to not use the name "kasan_data" for any kunit tests
 outside of KUNIT_EXPECT_KASAN_FAIL().

Changes since v2:
 - Due to Alan's changes in [1], KUnit can be built as a module.
 - The name of the tests that could not be run with KUnit has been
 changed to be more generic: test_kasan_module.
 - Documentation on how to run the new KASAN tests and what to expect
 when running them has been added.
 - Some variables and functions are now static.
 - Now save/restore panic_on_warn in a similar way to kasan_multi_shot
 and renamed the init/exit functions to be more generic to accommodate.
 - Due to [3] in kasan_strings, kasan_memchr, and
 kasan_memcmp will fail if CONFIG_AMD_MEM_ENCRYPT is enabled so return
 early and print message explaining this circumstance.
 - Changed preprocessor checks to C checks where applicable.

Changes since v1:
 - Make use of Alan Maguire's suggestion to use his patch that allows
   static resources for integration instead of adding a new attribute to
   the kunit struct
 - All KUNIT_EXPECT_KASAN_FAIL statements are local to each test
 - The definition of KUNIT_EXPECT_KASAN_FAIL is local to the
   test_kasan.c file since it seems this is the only place this will
   be used.
 - Integration relies on KUnit being builtin
 - copy_user_test has been separated into its own file since KUnit
   is unable to test these. This can be run as a module just as before,
   using CONFIG_TEST_KASAN_USER
 - The addition to the current task has been separated into its own
   patch as this is a significant enough change to be on its own.


[1] https://lore.kernel.org/linux-kselftest/1585313122-26441-1-git-send-email-alan.maguire@oracle.com/T/#t
[2] https://lkml.org/lkml/2020/4/23/708
[3] https://bugzilla.kernel.org/show_bug.cgi?id=206337



David Gow (1):
  mm: kasan: Do not panic if both panic_on_warn and kasan_multishot set

Patricia Alfonso (4):
  Add KUnit Struct to Current Task
  KUnit: KASAN Integration
  KASAN: Port KASAN Tests to KUnit
  KASAN: Testing Documentation

 Documentation/dev-tools/kasan.rst |  70 +++
 include/kunit/test.h              |   5 +
 include/linux/kasan.h             |   6 +
 include/linux/sched.h             |   4 +
 lib/Kconfig.kasan                 |  18 +-
 lib/Makefile                      |   3 +-
 lib/kunit/test.c                  |  13 +-
 lib/test_kasan.c                  | 688 +++++++++++++-----------------
 lib/test_kasan_module.c           |  76 ++++
 mm/kasan/report.c                 |  34 +-
 10 files changed, 514 insertions(+), 403 deletions(-)
 create mode 100644 lib/test_kasan_module.c

-- 
2.26.2.303.gf8c07b1a785-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200424061342.212535-1-davidgow%40google.com.

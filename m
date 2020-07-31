Return-Path: <kasan-dev+bncBC6OLHHDVUOBBVGCR34QKGQEPF55JAI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13f.google.com (mail-il1-x13f.google.com [IPv6:2607:f8b0:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id B4CD5233E5F
	for <lists+kasan-dev@lfdr.de>; Fri, 31 Jul 2020 06:43:01 +0200 (CEST)
Received: by mail-il1-x13f.google.com with SMTP id u3sf2368175ilj.19
        for <lists+kasan-dev@lfdr.de>; Thu, 30 Jul 2020 21:43:01 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596170580; cv=pass;
        d=google.com; s=arc-20160816;
        b=H+cU6Vc0oBQmgbg0LwVjsWhxeMUpmccCJSPblfmlaheRBFeGaRJeWQhwmt6GX2+71F
         aqvZtx+bhoBXdJqo8270qy0IOKRVe+nl0Alp9l006+xqzVy+Y5pm5GbgfpEjV8qPSjjL
         aAANEEIqa3Y5XvKC6HmOI6CLO5NeXsNoOdBC84M/Vz1YsbEs/PJNufMSHhStzp2RgDQI
         j+TVM9BV00iY4CaEsNNLK9QaXqKGcuk7qAmYLfv4GHML2AmPfQeJ3SFt0jWwo4eWieTd
         lfGZDzuO32TX78USO1g7MTE4gjL7cdQdPJyw2u00YKlA8ey3udrnnJ10KjpAsku2GvLb
         D3Sw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=cDlOjM9RUeAWW1fFd8YuOv32W9LJzmUm9NZwlHJMy4o=;
        b=cHTaDcw6ymqQhGMv2y8Ft/RjolMzvUMdlEouKlwugC6LL3PfKjQU261Lw57Ra2v9jh
         qmORDRYQEwHG+lWOEJXro059/z7uH95d9sECNdrMVpWV9sqiUAJ/VwMHPSlD1SzzGYYG
         ywAk2pJpzvUpBLm4tKcX3QDs0A6tzi/OLh4ZtL6LtpHARFxsCzT5XR/B6zeUBa0WX2Jr
         IVTXXTAtanxTXekdBQHlws6Vm/bFx7Q5P1v0ybBtZ8aunkYpVBok8IEDdr1L1Ue48N4J
         GLgvs0tzEOw426BZpyrikt0zYnK4Dv8pP7rbdFHf9I4G1+2ElUmGTLSar2VdhYb5Q+mm
         oMrQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SfL5KD6k;
       spf=pass (google.com: domain of 3u6ejxwgkcsqdavidgowgoogle.comkasan-devgooglegroups.com@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3U6EjXwgKCSQDAVIDGOWGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=cDlOjM9RUeAWW1fFd8YuOv32W9LJzmUm9NZwlHJMy4o=;
        b=CCUgz8Se1lpS41MQnSRqfOPKeT/ObLBcMqPRCHtfUKJjwqdQcIEUYSk5ch3lCtjvSO
         Hd8hEEPCfoML6tQd+HDmjjRlhC3cYhCDT+XjW7puv02XkptemK48b2fHENYYdu2f7WIc
         n1EYZ9xBFQ7RgDAWIvQkdg5R8K0ugWcnCWkulv9Hm8dYDZOHkXO2I+IfQW+iGEIhZ2nU
         jNicO0oyNvd8xMK63gQzrEajbYlxqvM5uD1EvHTZdtMJCrwAs1333VbxNHERRpAGoV1d
         4I3UUHIPhojoiaL1YbEhpNo1Udu+wEa8FSz651b35SosOWi28zNyV/YdGZln+3JnE6N8
         sz2w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=cDlOjM9RUeAWW1fFd8YuOv32W9LJzmUm9NZwlHJMy4o=;
        b=ik+wBZiC/JpVkNT5/ccp9SaIheEJ+kt18XoF9Zv+29lNYV7WtlfPOAQ6rlMKxx/JiS
         FWH9hWC0ol9ykHgqLf5COKTOVGb5PzVUiJn4ge8aPZFcSf4cGUQG+iSbZ+dW0xu5PsV8
         92DhDWkcWLrfRWNZgzzLMqW0YCM/WZsOAWVUGU7fkodFN6CvxbdU8Wz5cT/VejhkFbNw
         I31pRz11C+mUEjmHzrqeEjCb+hiSOlrBPVX/IK+x7yiAPwNm9f1KMhBe0opKYqweDg0f
         4ObtHU3iTqUnEea2bl29FKEy30ZlJrIwUtGAFcxqH05vERDMDsgTQsaKh06YPDqaI1dj
         m89A==
X-Gm-Message-State: AOAM533SgOnpPm0swcwztOMbF1Peg+6dptkW8JvHm1Jwyk95XrsPNowP
	RoW6+xXbUSVpOh8BMJtBFBk=
X-Google-Smtp-Source: ABdhPJzfQ1596qGbso2TmFAvIgXxL76mCNcKqNG5BqX4vFLkZT4DbUS1jEQRmp8Cc1zgYloWm4dgfg==
X-Received: by 2002:a02:aa87:: with SMTP id u7mr2956819jai.13.1596170580428;
        Thu, 30 Jul 2020 21:43:00 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6638:134a:: with SMTP id u10ls1250838jad.9.gmail; Thu,
 30 Jul 2020 21:43:00 -0700 (PDT)
X-Received: by 2002:a05:6638:1489:: with SMTP id j9mr959518jak.22.1596170579993;
        Thu, 30 Jul 2020 21:42:59 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596170579; cv=none;
        d=google.com; s=arc-20160816;
        b=TbhMaXzu+EE7610t0sIJuP7DYt8h0mEL9DV02K53xGka01Se9XYmAaIb+Buy/6CPRD
         JFTOt5sZCL+q/rnRQC1LAmfE9iB2pIhYZ+uCNLf/VjtzB2aELJgn+S8e14/NKpIHANiJ
         qpX+U51eVotgWryC1YNklT5AmZYEI9lcuVeKJayFFZpjFEBuWob4sGcpFW1e+AmgszwW
         IsDClXEV+HjD9Eq9O/g0gbW8DUXRfVDg57fMcpIhzDE2TII/S9Wqx9iU+TvboNXifHaq
         rmRV7COmeQ6AsgmnmaX9BMcNL7qTKXZMXoXqOvcEzfpdbp4XCGBZQBhzWfwJ468s/eba
         j5/Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=K3PusR14df0uIi/zL2N7bolWKbqSLb4cLy+G3Ea6VDU=;
        b=mCoyYeHNbBA/yBOXvn0t9YbU3V9NBNEiKm258/Uv1SO9xocfSqo9y3z0cPDL9Rv01Z
         WtBvsNuEprOaVt185D77b67D8rcaLu/KuHHproLd1LRo6pPNT0LOC+xR8SP+yJWbpRZq
         Axg4fHKTt5VZKRwEtN6lfleAQK/5jQiRFlauWMp7yPQ0t+NoaiEJ1txVg8YFJ5C1FkJb
         BDi/X09upVbodwhLMSRx30mA6IfBU//g9FAXPRrMgu8h1b7TJI1NolQLmG8U7hD3cqXw
         tDw9fN2WepIX4k9j/+0Z0lcq/bnS42+d9I0ev9GopESkVBzFgVgqUVrfYsvaPtBPDQjI
         LsqQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SfL5KD6k;
       spf=pass (google.com: domain of 3u6ejxwgkcsqdavidgowgoogle.comkasan-devgooglegroups.com@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3U6EjXwgKCSQDAVIDGOWGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id t6si371529ioi.1.2020.07.30.21.42.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 30 Jul 2020 21:42:59 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3u6ejxwgkcsqdavidgowgoogle.comkasan-devgooglegroups.com@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id q145so23528872ybg.8
        for <kasan-dev@googlegroups.com>; Thu, 30 Jul 2020 21:42:59 -0700 (PDT)
X-Received: by 2002:a5b:d12:: with SMTP id y18mr3333265ybp.400.1596170579443;
 Thu, 30 Jul 2020 21:42:59 -0700 (PDT)
Date: Thu, 30 Jul 2020 21:42:37 -0700
Message-Id: <20200731044242.1323143-1-davidgow@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.28.0.163.g6104cc2f0b6-goog
Subject: [PATCH v9 0/5] KASAN-KUnit Integration
From: "'David Gow' via kasan-dev" <kasan-dev@googlegroups.com>
To: trishalfonso@google.com, brendanhiggins@google.com, 
	aryabinin@virtuozzo.com, dvyukov@google.com, mingo@redhat.com, 
	peterz@infradead.org, juri.lelli@redhat.com, vincent.guittot@linaro.org, 
	andreyknvl@google.com, shuah@kernel.org
Cc: David Gow <davidgow@google.com>, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com, kunit-dev@googlegroups.com, 
	linux-kselftest@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: davidgow@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=SfL5KD6k;       spf=pass
 (google.com: domain of 3u6ejxwgkcsqdavidgowgoogle.comkasan-devgooglegroups.com@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3U6EjXwgKCSQDAVIDGOWGOOGLE.COMKASAN-DEVGOOGLEGROUPS.COM@flex--davidgow.bounces.google.com;
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
- "kunit: extend kunit resources API" [1]
 - This is already present in the kselftest/kunit branch

I'd _really_ like to get this into 5.9 if possible: we also have some
other changes which depend on some things here.

Changes from v8:
 - Rebased on top of kselftest/kunit
 - (Which, with this patchset, should rebase cleanly on 5.8-rc7)
 - Renamed the KUnit test suite, config name to patch the proposed
   naming guidelines for KUnit tests[6]

Changes from v7:
 - Rebased on top of kselftest/kunit
 - Rebased on top of v4 of the kunit resources API[1]
 - Rebased on top of v4 of the FORTIFY_SOURCE fix[2,3,4]
 - Updated the Kconfig entry to support KUNIT_ALL_TESTS

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
 - Due to [4] in kasan_strings, kasan_memchr, and
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


[1] https://lore.kernel.org/linux-kselftest/CAFd5g46Uu_5TG89uOm0Dj5CMq+11cwjBnsd-k_CVy6bQUeU4Jw@mail.gmail.com/T/#t
[2] https://lore.kernel.org/linux-mm/20200424145521.8203-1-dja@axtens.net/
[3] https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=adb72ae1915db28f934e9e02c18bfcea2f3ed3b7
[4] https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=47227d27e2fcb01a9e8f5958d8997cf47a820afc
[5] https://bugzilla.kernel.org/show_bug.cgi?id=206337
[6] https://lore.kernel.org/linux-kselftest/20200620054944.167330-1-davidgow@google.com/


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
 lib/Kconfig.kasan                 |  22 +-
 lib/Makefile                      |   7 +-
 lib/kunit/test.c                  |  13 +-
 lib/test_kasan.c                  | 858 ------------------------------
 mm/kasan/report.c                 |  34 +-
 9 files changed, 147 insertions(+), 872 deletions(-)
 delete mode 100644 lib/test_kasan.c

-- 
2.28.0.163.g6104cc2f0b6-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200731044242.1323143-1-davidgow%40google.com.

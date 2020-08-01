Return-Path: <kasan-dev+bncBC6OLHHDVUOBBLNKST4QKGQEOSVNBJI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 894172350E5
	for <lists+kasan-dev@lfdr.de>; Sat,  1 Aug 2020 09:09:35 +0200 (CEST)
Received: by mail-pf1-x439.google.com with SMTP id u11sf14264512pfm.23
        for <lists+kasan-dev@lfdr.de>; Sat, 01 Aug 2020 00:09:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1596265774; cv=pass;
        d=google.com; s=arc-20160816;
        b=APD0BkJ5OtHr6jJNWoeVEsBaD0AfJ+RzaRtWmN+L/WiE35vx/AwAmf96u1sb5mGi3O
         jKzCJELtu6z/BuioO3GDvbHviY6dSXBE+Xvy1KKTNUvuOLZVDiZMboYFn39q1QDS41Jb
         XKkoen2f0o6hPNk1fKAE4AtOMF0B3raSY853UhPc8ZrN4N5/ErRFkcayhf/2cKnSCnF4
         UP9MYEyVEULLIuQv+Q2O27offwt/xmVV0yB75ogEbpL10KdTbaPclpgiQ9ejgj5Bp0Io
         HJba0k1c3iWuO3BdX4fB4TsTcbn77nCHFNVtTIVD7BvpJvwh6lvpwZS+nV5z87e6xyBY
         ZiDg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :mime-version:message-id:date:dkim-signature;
        bh=A0qtXfpsDx/8ntbnbIwUUUyGYX0cCBgJIpBFP5b9i4w=;
        b=l83B7DgA226i+t6xraUIabrdllsvkW+5n3nkqF79fH3hyM6CqiawzdXbyfy2jjTi1f
         8jhOlNWli3AoQPWHuQz3qyUvs8xak3ndb+/f+j0Do685Mq9lpp/Lt8Qewhugzpde8fPF
         REpWdbXwU0/VVje90zAH5oOEd5EDU9fAGhZrhbsmGovzduRgrofQV1tg4pY5Tg/7+R/K
         h8AVF7CFPsSzPVk7GAkMTpETIcB1jG+Rwvk3zvDqUlEPTQSgV7SDDOTx/fxngQz123cl
         /uk2by1A0hUZWM9eZH+LNcMkE9FrdngL6n3qb2rqaOKdHq86D2ag5o7ZqRDA6ksH2K1V
         Qpkg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="IHYl/2b8";
       spf=pass (google.com: domain of 3lbulxwgkcekolgtorzhrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3LBUlXwgKCekOLgTORZhRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:message-id:mime-version:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=A0qtXfpsDx/8ntbnbIwUUUyGYX0cCBgJIpBFP5b9i4w=;
        b=n0Urs9a3bf7vKG7LGP0TaiSz6LQ+Q76vIp3la6gkY55QBFX4qABGD3CNSDvuPCnU4Q
         uJrX3LBk3PnZy0i2E7p4Q7dpRBNM+F56m838eRuUFAUNTR0ST5c9djGsAO8StyXez2On
         th7H5dIzTQeZ1D4VoL9kCjeNSqoFGMJkqO9HzvIo4WgalDVaELhJZaN16n3jy9QFG4yc
         N4wVDu2r+/QkkUBcL1UeGuhtge4VLJvd1zkuHP843gPCPdh5hdMxrHmmKrs/kW8eH96Y
         d5qqab+r/gL5PIl/yIMJB6Bs3EOMYaAfi/kVXoNo2e80XgxjLwotaP+gw+PZEtbVvEUs
         Zy0A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:message-id:mime-version:subject:from:to:cc
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=A0qtXfpsDx/8ntbnbIwUUUyGYX0cCBgJIpBFP5b9i4w=;
        b=Kjzka5O11B1O+E/N6LnRXU7i+SU3+xi/6+oiOVvfZ7Er26ofvV9RMn/fnQtUcF6PyU
         3dNbZ/kLhe7YPuKt1seGllipkPR9K+Scvrnr0MgnV1cyacm07E4F4gY0qFLqvCKCCjNC
         jEYH5IHETgJUPcB6nucRztUtAs/7bTkkMbMHDblYgvtVP+UPS/rH/5jseCUfh79SVeak
         SlIXsqLO7X1uXOmn1htf5+Pbe8jj1dzZOstZbH9msuXPM3LVHLKABwqRkZmXaIa+TFKz
         LdS2/OwPeHhwwW0oE4KF4fElzz6mloDOBaOlRwCOZsnPEgW3xqvL9yxX1RU+a0WG74ry
         qFKw==
X-Gm-Message-State: AOAM531jAFNCw1I/netwvnj26G5Oa0472l+cqJaCBW/Wdnv6l8fgHVmY
	7rbXFBeVZ4SzW4qN6Tr3RNc=
X-Google-Smtp-Source: ABdhPJzKHPs1ge+vjM6zkI6q1pafvvJyoJbJKqEm+7NFQ8dMhCZ4S2cxuaL/V0lXIGIVXTpLNNPBKQ==
X-Received: by 2002:a17:90b:f11:: with SMTP id br17mr7675980pjb.68.1596265774051;
        Sat, 01 Aug 2020 00:09:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a63:4282:: with SMTP id p124ls3652812pga.7.gmail; Sat, 01
 Aug 2020 00:09:33 -0700 (PDT)
X-Received: by 2002:a62:1ad0:: with SMTP id a199mr1623482pfa.56.1596265773533;
        Sat, 01 Aug 2020 00:09:33 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1596265773; cv=none;
        d=google.com; s=arc-20160816;
        b=nGpSkn37KTv92TmTCNDvqnMcm8eMMSIRsdniJuzlJulYdV8IaYrYqraj5IBBCTN8z+
         FgcmCmHprdh/c4mYqNIIGIuzS0CpKcReiS1hmI1/giSrb/qz1vP2LICl1fHjVZgR9kiD
         /AfGg5R+G16lrpFrGYq8zhYE86nPeDf8O+YzLG+gnWAifWdwRe7s6Up3QQCppMB3JPfi
         JTU0WEYfABP+ljsvOKgkE8rF2f6qcNWOWqquxsD63qUqzsOtIYvOhnrcGLHoaP1xxC8F
         AcaVETVSMnnRPTuidh2VzVTi/KwOoAWFbd1SuGeAlLYgWMqxAxoy0UwouNscQIpfwsMf
         19Zg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:mime-version:message-id:date:dkim-signature;
        bh=J6mfWqFl9ILoOse64w8NCh3ZibSveR4Njn3UWGLPdfQ=;
        b=tR0XXYDZm4aLZ0P9GPF7w6eIomeYg4SK2n2dceIQztNcPAZuCv6ePmNS9iypkTNazx
         9SvcmIbJPaxcegGLzWOwPAZbBA90Oxizxc3LH1CQXlfd4qmTXjSq8OLNSGijnPiICJY6
         2QbTafoBrFTXc3qU93A+xjVz4klPh3fkq4iLRjk13wEYreVpZJaQMhNauhfCfxUPPl0q
         5flMqAiUowu51u5QajWVyLf1qH8TOg/JsPGUaZrMDfgOfFu/+chSJuNzMMx52Y+9TzGn
         zuw9Drgigx/ySbCQeXyQfeFDKjp8tzvDLi0/H917LUf0xRd6zfoGVDdpE6s3s1+zIWmx
         zlxw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b="IHYl/2b8";
       spf=pass (google.com: domain of 3lbulxwgkcekolgtorzhrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3LBUlXwgKCekOLgTORZhRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--davidgow.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb4a.google.com (mail-yb1-xb4a.google.com. [2607:f8b0:4864:20::b4a])
        by gmr-mx.google.com with ESMTPS id n68si547863pgn.1.2020.08.01.00.09.33
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 01 Aug 2020 00:09:33 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3lbulxwgkcekolgtorzhrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--davidgow.bounces.google.com designates 2607:f8b0:4864:20::b4a as permitted sender) client-ip=2607:f8b0:4864:20::b4a;
Received: by mail-yb1-xb4a.google.com with SMTP id 7so38750943ybl.5
        for <kasan-dev@googlegroups.com>; Sat, 01 Aug 2020 00:09:33 -0700 (PDT)
X-Received: by 2002:a25:c145:: with SMTP id r66mr7371613ybf.244.1596265772670;
 Sat, 01 Aug 2020 00:09:32 -0700 (PDT)
Date: Sat,  1 Aug 2020 00:09:19 -0700
Message-Id: <20200801070924.1786166-1-davidgow@google.com>
Mime-Version: 1.0
X-Mailer: git-send-email 2.28.0.163.g6104cc2f0b6-goog
Subject: [PATCH v10 0/5] KASAN-KUnit Integration
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
 header.i=@google.com header.s=20161025 header.b="IHYl/2b8";       spf=pass
 (google.com: domain of 3lbulxwgkcekolgtorzhrzzrwp.nzxvldly-opgrzzrwprczfad.nzx@flex--davidgow.bounces.google.com
 designates 2607:f8b0:4864:20::b4a as permitted sender) smtp.mailfrom=3LBUlXwgKCekOLgTORZhRZZRWP.NZXVLdLY-OPgRZZRWPRcZfad.NZX@flex--davidgow.bounces.google.com;
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

Changes from v9:
 - Rebased on top of linux-next (20200731) + kselftest/kunit and [7]
 - Note that the kasan_rcu_uaf test has not been ported to KUnit, and
   remains in test_kasan_module. This is because:
   (a) KUnit's expect failure will not check if the RCU stacktraces
       show.
   (b) KUnit is unable to link the failure to the test, as it occurs in
       an RCU callback.

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
[7] https://lkml.org/lkml/2020/7/31/571


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
 lib/kasan_kunit.c                 | 770 +++++++++++++++++++++++++
 lib/kunit/test.c                  |  13 +-
 lib/test_kasan.c                  | 903 ------------------------------
 lib/test_kasan_module.c           | 111 ++++
 mm/kasan/report.c                 |  34 +-
 11 files changed, 1028 insertions(+), 917 deletions(-)
 create mode 100644 lib/kasan_kunit.c
 delete mode 100644 lib/test_kasan.c
 create mode 100644 lib/test_kasan_module.c

-- 
2.28.0.163.g6104cc2f0b6-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200801070924.1786166-1-davidgow%40google.com.
